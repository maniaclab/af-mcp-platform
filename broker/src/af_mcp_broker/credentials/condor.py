"""HTCondor IDTOKENs via condor-token-service (issue #169).

HTCondor IDTOKENS are signed with the pool password — a symmetric key that
can mint tokens for any identity in the pool, so it never leaves Condor
infrastructure and never enters the broker. Issuance is delegated to
condor-token-service, a small external service pinned to a Condor node with
the key mounted read-only, exposing one ``POST /v1/token`` endpoint
authenticated by the AF Broker Identity Token (issue #162) with
``aud=condor-token-service`` and a ``unixname`` claim.

``CondorTokenProvider`` is the second native provider (broker-authoritative,
no linking — see ``broker_issued.py``'s module docstring for the two-class
doctrine) and composes the same ``BrokerTokenIssuer``: mint an identity
assertion for the principal, exchange it at the service for an IDTOKEN,
cache the IDTOKEN keyed ``(subject, target)`` with TTL = the service's
``expires_at``. If HTCondor is later configured to trust the broker's JWKS
directly (SCITOKENS), only this class's implementation changes — the
``CredentialProvider`` contract, condor-mcp, and the registry wiring are
untouched.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING, ClassVar

import httpx
import structlog
from fastapi import HTTPException, status

from af_mcp_broker import metrics
from af_mcp_broker.credentials.base import (
    CredentialKind,
    CredentialProvider,
    ExecutionModel,
    IssuedCredential,
)
from af_mcp_broker.http import get_http_client

if TYPE_CHECKING:
    from pydantic import SecretBytes

    from af_mcp_broker.credentials.broker_issued import BrokerTokenIssuer
    from af_mcp_broker.credentials.cache import CredentialCache
    from af_mcp_broker.identity import Principal

log = structlog.get_logger(__name__)


class CondorTokenProvider(CredentialProvider):
    """Issues per-user HTCondor IDTOKENs by exchanging a broker-minted identity token at condor-token-service.

    A *native* provider like ``BrokerIssuedProvider``: the broker is
    authoritative, so ``is_linked`` is unconditionally True and there is no
    portal linking step. Unlike broker-issued targets, POSIX identity is not
    per-target config here — the service mints
    ``condor_token_create -identity <unixname>@...``, so a principal without
    a POSIX identity can never receive an IDTOKEN; that requirement is
    enforced at ``issue()`` time as an ``HTTPException(404)`` naming the
    target, the same point-of-use shape (and the same aggregator ``bearer``
    delivery branch) as ``BrokerIssuedProvider``'s ``include_posix`` check.

    Service failures map to generic client-visible errors: 429 passes
    through with its ``Retry-After`` (the service rate-limits per subject);
    every other non-200 — including 401/403, which mean the broker's own
    token or claim set was rejected, a broker<->service contract failure the
    caller cannot act on — becomes a 502 whose detail never carries the
    service's response body.
    """

    cred_class: ClassVar[str] = "condor_token"
    execution_model: ClassVar[ExecutionModel] = ExecutionModel.DELEGATED

    def __init__(
        self,
        issuer: BrokerTokenIssuer,
        cache: CredentialCache,
        alias: str,
        targets: frozenset[str],
        service_url: str,
        audience: str = "condor-token-service",
    ) -> None:
        self._issuer = issuer
        self._cache = cache
        self._alias = alias
        self._targets = targets
        # AnyHttpUrl normalizes a bare origin to a trailing-slash form;
        # strip it so the endpoint join below never produces "//v1/token".
        self._token_endpoint = f"{service_url.rstrip('/')}/v1/token"
        self._audience = audience
        self._log = structlog.get_logger(__name__).bind(
            provider="CondorTokenProvider", alias=alias
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
        """Return a bearer credential carrying a fresh (or still-valid cached) HTCondor IDTOKEN for *(principal, target)*.

        Raises:
            HTTPException(404): when the principal has no POSIX identity —
                see the class docstring.
            HTTPException(429): when condor-token-service rate-limits the
                exchange (``Retry-After`` passed through).
            HTTPException(502): when the exchange fails for any other
                reason (service unreachable, broker token rejected, minting
                failed) — generic detail only.

        """
        if principal.uid is None or principal.gid is None or principal.unixname is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=(
                    f"Service {target!r} requires a POSIX identity "
                    "(uid/gid/unixname) — HTCondor IDTOKENs are minted for "
                    "your unix account, which your account does not have. "
                    "Contact your Analysis Facility operator to request a "
                    "POSIX identity."
                ),
            )

        cached = await self._cache.get(
            principal.subject, target, min_remaining=min_remaining_seconds
        )
        if cached is not None:
            self._log.debug(
                "condor_token.issue.cache_hit",
                subject=principal.subject,
                target=target,
            )
            return cached

        async def _do_mint() -> IssuedCredential:
            idtoken, expires_at = await self._exchange(principal, target)
            audit_id = uuid.uuid4().hex
            cred = IssuedCredential(
                cred_class=self.cred_class,
                target=target,
                kind=CredentialKind.BEARER,
                expires_at=expires_at,
                payload={
                    "access_token": idtoken,
                    "token_type": "Bearer",
                },
                audit_id=audit_id,
                source="condor_token_service",
                execution_model=self.execution_model,
            )
            await self._cache.put(
                principal.subject, target, cred, expires_at=expires_at
            )
            metrics.condor_tokens_issued_total.labels(target=target).inc()
            # Never log token material -- subject/target/audit only.
            self._log.info(
                "condor_token.issue.success",
                subject=principal.subject,
                target=target,
                audit_id=audit_id,
                expires_at=expires_at,
            )
            return cred

        # Single-flighted like every other provider (issue #94's pattern):
        # concurrent misses for this (subject, target) await one exchange
        # instead of each independently hitting the service.
        return await self._cache.get_or_mint(
            principal.subject, target, min_remaining_seconds, _do_mint
        )

    async def revoke(self, principal: Principal, target: str) -> None:
        """Drop the cached IDTOKEN; IDTOKENS are not server-side revocable, so the short lifetime is the actual revocation bound."""
        await self._cache.revoke(principal.subject, target)

    async def _exchange(self, principal: Principal, target: str) -> tuple[str, float]:
        """Mint a broker identity token for *principal* and exchange it at condor-token-service.

        Returns ``(idtoken, expires_at_epoch)``. Failure mapping per the
        class docstring; the service's response body is logged nowhere and
        never reaches the caller.
        """
        broker_token, _ = self._issuer.mint(
            principal.subject,
            self._audience,
            uid=principal.uid,
            gid=principal.gid,
            unixname=principal.unixname,
        )
        try:
            resp = await get_http_client().post(
                self._token_endpoint,
                headers={"Authorization": f"Bearer {broker_token}"},
                timeout=10.0,
            )
        except httpx.HTTPError as exc:
            self._log.warning(
                "condor_token.exchange.unreachable",
                subject=principal.subject,
                target=target,
                error=str(exc),
            )
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="The HTCondor credential service could not be reached.",
            ) from exc

        if resp.status_code == status.HTTP_429_TOO_MANY_REQUESTS:
            headers = (
                {"Retry-After": resp.headers["Retry-After"]}
                if "Retry-After" in resp.headers
                else None
            )
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=(
                    "The HTCondor credential service rate-limited this "
                    "request. Retry later."
                ),
                headers=headers,
            )
        if resp.status_code != status.HTTP_200_OK:
            # Status code only -- the response body may carry service
            # internals and must reach neither the log nor the caller.
            self._log.warning(
                "condor_token.exchange.failed",
                subject=principal.subject,
                target=target,
                upstream_status=resp.status_code,
            )
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="HTCondor credential issuance failed.",
            )

        data = resp.json()
        # The contract pins expires_at to ISO8601 UTC; interpret a naive
        # timestamp as UTC rather than broker-local time.
        expires_dt = datetime.fromisoformat(data["expires_at"])
        if expires_dt.tzinfo is None:
            expires_dt = expires_dt.replace(tzinfo=UTC)
        return data["token"], expires_dt.timestamp()
