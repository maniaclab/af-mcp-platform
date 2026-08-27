"""The AF Broker Identity Token (issue #162): the internal credential format for AF-native backends.

Two classes of backends exist (see docs/auth.md's "AF Broker Identity
Token" section). External identity systems (Rucio, ATLAS IAM) are
federation problems -- account linking plus a federated credential, the
existing OIDCProvider/OAuth21Provider/X509Provider set. AF-native services
(condor-token-service, future jupyter-mcp, ...) are the opposite: AF is the
source of truth, no federation occurs, and the broker is authoritative --
so the credential is one the broker itself signs. There is no trust
boundary crossed by involving Keycloak in this path: round-tripping through
it per call to re-encode facts the broker already resolved from the
directory (subject, POSIX identity) would be an availability and latency
cost with no trust gain.

The token is an identity assertion, nothing more: ``iss``/``sub``/``aud``/
``exp``/``iat``/``jti``, plus ``uid``/``gid``/``unixname`` only for targets
whose config declares they need POSIX identity. Deliberately absent:
permissions, groups, or any authorization claim -- authorization is an
attribute of the principal, decided per-call by the broker's entitlement
check, and must never migrate into tokens. Consumers verify against the
broker's own JWKS (``GET /.well-known/jwks.json``, api/wellknown.py) with a
standard library and MUST reject tokens whose ``aud`` is not exactly
themselves.
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar

import jwt
import structlog
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import HTTPException, status
from jwt.algorithms import RSAAlgorithm

from af_mcp_broker import metrics
from af_mcp_broker.credentials.base import (
    CredentialKind,
    CredentialProvider,
    ExecutionModel,
    IssuedCredential,
)

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from pydantic import SecretBytes

    from af_mcp_broker.config import Settings
    from af_mcp_broker.credentials.cache import CredentialCache
    from af_mcp_broker.identity import Principal

log = structlog.get_logger(__name__)


@dataclass(frozen=True)
class BrokerIssuedTokenOptions:
    """The per-target token properties the broker-issued provider needs to mint one AF-native backend's identity token: the ``aud`` to stamp, and whether to carry POSIX identity.

    Sourced from the target's ``ServiceSpec`` (``effective_audience``,
    ``requires_posix``) at wiring time in ``app.py`` (issue #257) -- so every
    token property of a service lives on the service entry, while the provider
    stays decoupled from the service registry and receives only the resolved
    values it needs. ``audience`` is always the resolved effective audience
    (never empty); a target with no options at all falls back to its own name.
    """

    audience: str
    requires_posix: bool = False


def _rfc7638_thumbprint(public_key: rsa.RSAPublicKey) -> str:
    """RFC 7638 JWK thumbprint of *public_key*, used as the ``kid``.

    Derived from the key material itself (SHA-256 over the canonical
    ``{"e","kty","n"}`` JSON), so the same key always publishes the same
    ``kid`` regardless of which process loaded it -- no coordination needed
    between replicas or across restarts.
    """
    jwk = json.loads(RSAAlgorithm.to_jwk(public_key))
    canonical = json.dumps(
        {"e": jwk["e"], "kty": jwk["kty"], "n": jwk["n"]},
        sort_keys=True,
        separators=(",", ":"),
    )
    digest = hashlib.sha256(canonical.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def _public_jwk(public_key: rsa.RSAPublicKey) -> dict[str, Any]:
    """Public-material-only JWK for *public_key*, with kid/use/alg set.

    ``RSAAlgorithm.to_jwk`` on a *public* key can never emit private
    parameters, which is what keeps ``BrokerTokenIssuer.jwks()`` publishable
    by construction.
    """
    jwk = json.loads(RSAAlgorithm.to_jwk(public_key))
    jwk.update({"kid": _rfc7638_thumbprint(public_key), "use": "sig", "alg": "RS256"})
    return jwk


class BrokerTokenIssuer:
    """Holds the broker's RS256 signing key, mints identity-assertion JWTs, and serves the JWKS document.

    ``additional_public_key_pems`` supports rotation: extra PUBLIC keys
    published in the JWKS alongside the active key, so a successor key can
    be published before its first use and the retiring key kept verifiable
    through an overlap window -- see docs/auth.md's rotation procedure.
    Only the active key ever signs.
    """

    def __init__(
        self,
        private_key_pem: bytes,
        issuer: str,
        ttl_seconds: int = 600,
        additional_public_key_pems: Sequence[bytes] = (),
    ) -> None:
        private_key = serialization.load_pem_private_key(private_key_pem, password=None)
        if not isinstance(private_key, rsa.RSAPrivateKey):
            raise TypeError(
                "Broker signing key must be an RSA private key (RS256); got "
                f"{type(private_key).__name__}"
            )
        self._private_key = private_key
        self._issuer = issuer
        self._ttl_seconds = ttl_seconds
        self.kid = _rfc7638_thumbprint(private_key.public_key())

        # JWKS is static for the process lifetime -- build it once.
        keys = [_public_jwk(private_key.public_key())]
        for pem in additional_public_key_pems:
            public_key = serialization.load_pem_public_key(pem)
            if not isinstance(public_key, rsa.RSAPublicKey):
                raise TypeError(
                    "Additional broker JWKS keys must be RSA public keys; "
                    f"got {type(public_key).__name__}"
                )
            keys.append(_public_jwk(public_key))
        self._jwks: dict[str, Any] = {"keys": keys}
        # Public halves for verify(): the active key plus rotation overlap
        # keys, so a token signed just before a rotation stays verifiable.
        self._verification_keys = [private_key.public_key()] + [
            key
            for pem in additional_public_key_pems
            if isinstance(
                key := serialization.load_pem_public_key(pem), rsa.RSAPublicKey
            )
        ]

    def mint(
        self,
        subject: str,
        audience: str,
        *,
        uid: int | None = None,
        gid: int | None = None,
        unixname: str | None = None,
    ) -> tuple[str, int]:
        """Sign an identity-assertion JWT for *(subject, audience)*.

        Returns ``(token, expires_at_epoch)``. The claim set is EXACTLY
        ``iss``/``sub``/``aud``/``exp``/``iat``/``jti``, plus
        ``uid``/``gid``/``unixname`` when passed (the caller gates those on
        per-target config) -- never a permission, group, or any other
        authorization claim (issue #162).
        """
        now = int(time.time())
        expires_at = now + self._ttl_seconds
        claims: dict[str, Any] = {
            "iss": self._issuer,
            "sub": subject,
            "aud": audience,
            "exp": expires_at,
            "iat": now,
            "jti": uuid.uuid4().hex,
        }
        if uid is not None:
            claims["uid"] = uid
        if gid is not None:
            claims["gid"] = gid
        if unixname is not None:
            claims["unixname"] = unixname
        token = jwt.encode(
            claims, self._private_key, algorithm="RS256", headers={"kid": self.kid}
        )
        return token, expires_at

    def verify(self, token: str) -> dict[str, Any] | None:
        """Verify a token this broker issued; return its claims or None.

        Checks signature (active key, then rotation overlap keys), ``iss``,
        and ``exp``. Deliberately does NOT check ``aud`` — audience policy
        belongs to the consuming endpoint (e.g. the x509 redeem endpoint
        requires ``aud`` to be a configured x509 target); verify() only
        proves the token is authentically ours and current.
        """
        for public_key in self._verification_keys:
            try:
                claims: dict[str, Any] = jwt.decode(
                    token,
                    public_key,
                    algorithms=["RS256"],
                    issuer=self._issuer,
                    options={"verify_aud": False},
                )
            except jwt.InvalidSignatureError:
                continue  # try the next rotation key
            except jwt.InvalidTokenError:
                return None  # authentic-looking but invalid (expired, iss, ...)
            return claims
        return None

    def jwks(self) -> dict[str, Any]:
        """Return the RFC 7517 JWKS document: the active key's public half plus any additional rotation keys."""
        return self._jwks


def load_broker_token_issuer(settings: Settings) -> BrokerTokenIssuer | None:
    """Build the issuer from *settings*, or return None when the feature is unconfigured (no ``broker_signing_key_file``).

    Every misconfiguration short of "not configured at all" raises
    RuntimeError with an actionable message so ``app.py``'s lifespan fails
    the boot loudly (a broker that advertised broker-issued credentials but
    couldn't sign them would otherwise fail at first request instead).
    """
    if not settings.broker_signing_key_file:
        return None

    issuer_url = settings.broker_token_effective_issuer
    if not issuer_url:
        raise RuntimeError(
            "BROKER_SIGNING_KEY_FILE is set but neither BROKER_TOKEN_ISSUER "
            "nor BROKER_PUBLIC_ORIGIN is -- the AF Broker Identity Token "
            "needs an `iss` URL its consumers can pin."
        )

    key_path = Path(settings.broker_signing_key_file)
    try:
        private_key_pem = key_path.read_bytes()
    except OSError as exc:
        raise RuntimeError(
            f"BROKER_SIGNING_KEY_FILE ({key_path}) could not be read: {exc}"
        ) from exc

    additional_pems: list[bytes] = []
    if settings.broker_additional_public_keys_dir:
        # Only *.pem files: a mounted Secret's directory also contains
        # Kubernetes' hidden ..data plumbing, which must not be parsed.
        for pem_path in sorted(
            Path(settings.broker_additional_public_keys_dir).glob("*.pem")
        ):
            try:
                additional_pems.append(pem_path.read_bytes())
            except OSError as exc:
                raise RuntimeError(
                    f"Additional broker JWKS key {pem_path} could not be read: {exc}"
                ) from exc

    try:
        issuer = BrokerTokenIssuer(
            private_key_pem=private_key_pem,
            issuer=issuer_url,
            ttl_seconds=settings.broker_token_ttl_seconds,
            additional_public_key_pems=additional_pems,
        )
    except (ValueError, TypeError) as exc:
        raise RuntimeError(
            f"BROKER_SIGNING_KEY_FILE ({key_path}) or an additional JWKS "
            f"key is not a usable RSA PEM: {exc}"
        ) from exc

    log.info(
        "broker_token_issuer.loaded",
        issuer=issuer_url,
        kid=issuer.kid,
        ttl_seconds=settings.broker_token_ttl_seconds,
        additional_keys=len(additional_pems),
    )
    return issuer


class BrokerIssuedProvider(CredentialProvider):
    """Issues AF Broker Identity Tokens for AF-native backend targets.

    A *native* provider (issue #162), unlike the federated
    OIDCProvider/OAuth21Provider/X509Provider set: the broker is
    authoritative for these identities, so there is no linking step
    (``is_linked`` is unconditionally True -- AF-native backends are
    available from day one) and no external service in the mint path at
    all. Tokens are cached in the shared ``CredentialCache`` keyed
    ``(subject, target)`` with expiry = token ``exp``.

    A target whose service sets ``requires_posix`` (via ``token_options``,
    issue #257) requires the principal to actually carry a POSIX identity; a
    principal without one gets an ``HTTPException(404)`` naming the target -- the same
    point-of-use requirement as x509's ``PosixIdentityRequiredError``,
    raised as HTTPException because this provider is delivered over the
    aggregator's ``bearer`` branch, which already surfaces HTTPException
    detail cleanly (the OIDCProvider precedent) with no aggregator changes.
    """

    cred_class: ClassVar[str] = "broker_issued"
    execution_model: ClassVar[ExecutionModel] = ExecutionModel.DELEGATED

    def __init__(
        self,
        issuer: BrokerTokenIssuer,
        cache: CredentialCache,
        alias: str,
        targets: frozenset[str],
        token_options: Mapping[str, BrokerIssuedTokenOptions],
    ) -> None:
        self._issuer = issuer
        self._cache = cache
        self._alias = alias
        self._targets = targets
        self._token_options = token_options
        self._log = structlog.get_logger(__name__).bind(
            provider="BrokerIssuedProvider", alias=alias
        )

    async def is_linked(self, principal: Principal) -> bool:  # noqa: ARG002 (interface)
        """Return True unconditionally — the broker itself is the credential source for AF-native backends, so there is no linkage to check."""
        return True

    async def issue(
        self,
        principal: Principal,
        target: str,
        min_remaining_seconds: int = 300,
        passphrase: SecretBytes | None = None,  # noqa: ARG002 (interface)
    ) -> IssuedCredential:
        """Return a bearer credential carrying a freshly-minted (or still-valid cached) AF Broker Identity Token for *(principal, target)*.

        Raises:
            HTTPException(404): when this target's service declares
                ``requires_posix`` but the principal has no POSIX identity —
                see the class docstring.

        """
        audience, requires_posix = self._resolve_token_options(target)

        posix: dict[str, Any] = {}
        if requires_posix:
            if (
                principal.uid is None
                or principal.gid is None
                or principal.unixname is None
            ):
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=(
                        f"Service {target!r} requires POSIX identity claims "
                        "(uid/gid/unixname) in its AF Broker Identity Token, "
                        "which your account does not have. Contact your "
                        "Analysis Facility operator to request a POSIX "
                        "identity."
                    ),
                )
            posix = {
                "uid": principal.uid,
                "gid": principal.gid,
                "unixname": principal.unixname,
            }

        cached = await self._cache.get(
            principal.subject, target, min_remaining=min_remaining_seconds
        )
        if cached is not None:
            self._log.debug(
                "broker_issued.issue.cache_hit",
                subject=principal.subject,
                target=target,
            )
            return cached

        async def _do_mint() -> IssuedCredential:
            token, expires_at = self._issuer.mint(principal.subject, audience, **posix)
            audit_id = uuid.uuid4().hex
            cred = IssuedCredential(
                cred_class=self.cred_class,
                target=target,
                kind=CredentialKind.BEARER,
                expires_at=expires_at,
                payload={
                    "access_token": token,
                    "token_type": "Bearer",
                },
                audit_id=audit_id,
                source="broker_token_issuer",
                execution_model=self.execution_model,
            )
            await self._cache.put(
                principal.subject, target, cred, expires_at=expires_at
            )
            metrics.broker_identity_tokens_issued_total.labels(target=target).inc()
            # Never log token material -- subject/target/audience only.
            self._log.info(
                "broker_issued.issue.success",
                subject=principal.subject,
                target=target,
                audience=audience,
                requires_posix=requires_posix,
                audit_id=audit_id,
                expires_at=expires_at,
            )
            return cred

        # Single-flighted like every other provider: concurrent misses for
        # this (subject, target) await one mint (issue #94's pattern) --
        # cheap here (an in-process signature, no network), but it keeps
        # jti/audit cardinality one-per-credential rather than one-per-racer.
        return await self._cache.get_or_mint(
            principal.subject, target, min_remaining_seconds, _do_mint
        )

    async def revoke(self, principal: Principal, target: str) -> None:
        """Drop the cached token; the short TTL is the actual revocation bound."""
        await self._cache.revoke(principal.subject, target)

    def _resolve_token_options(self, target: str) -> tuple[str, bool]:
        """Return *(audience, requires_posix)* for *target*: the service-declared token options, or the defaults (audience = target name, no POSIX claims) when the target has no service entry. ``audience`` from options is already the resolved ``effective_audience`` (never empty)."""
        opts = self._token_options.get(target)
        if opts is None:
            return target, False
        return opts.audience, opts.requires_posix
