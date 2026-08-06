"""Tests for the AF Broker Identity Token (issue #162).

Covers the issuer core (``BrokerTokenIssuer``: claim-set exactness, kid
thumbprint stability, JWKS publication + rotation overlap), the
``load_broker_token_issuer`` settings loader, and ``BrokerIssuedProvider``
(the ``CredentialProvider`` for AF-native backends: always linked, POSIX
claims gated on per-target config, credential caching with expiry = token
exp). App-level wiring (startup fail-closed, /.well-known/jwks.json, the
aggregator path) lives in test_broker_issued_app.py.
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
from typing import TYPE_CHECKING, Any

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
from fastapi import HTTPException
from jwt.algorithms import RSAAlgorithm

from af_mcp_broker.config import BrokerIssuedTargetOptions, Settings
from af_mcp_broker.credentials import CredentialKind, ExecutionModel
from af_mcp_broker.credentials.broker_issued import (
    BrokerIssuedProvider,
    BrokerTokenIssuer,
    load_broker_token_issuer,
)
from af_mcp_broker.credentials.cache import CredentialCache

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

ISSUER_URL = "https://mcp.example.com"

# The documented claim set (issue #162) -- identity assertion, nothing more.
# Tests assert EXACT equality against these: any extra claim (a capability,
# a group, anything) is a design failure, not an additive change.
_BASE_CLAIMS = frozenset({"iss", "sub", "aud", "exp", "iat", "jti"})
_POSIX_CLAIMS = _BASE_CLAIMS | {"uid", "gid", "unixname"}


def _make_rsa_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _private_pem(key: rsa.RSAPrivateKey) -> bytes:
    return key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())


def _public_pem(key: rsa.RSAPrivateKey) -> bytes:
    return key.public_key().public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
    )


def _rfc7638_thumbprint(key: rsa.RSAPrivateKey) -> str:
    """Independently compute the RFC 7638 JWK thumbprint an issuer's kid must equal."""
    jwk = json.loads(RSAAlgorithm.to_jwk(key.public_key()))
    canonical = json.dumps(
        {"e": jwk["e"], "kty": jwk["kty"], "n": jwk["n"]},
        sort_keys=True,
        separators=(",", ":"),
    )
    digest = hashlib.sha256(canonical.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def verify_against_jwks(
    token: str, jwks: dict[str, Any], *, audience: str, issuer: str = ISSUER_URL
) -> dict[str, Any]:
    """Validate *token* exactly the way an AF-native consumer would.

    Select the JWK by the token header's ``kid``, then verify signature,
    ``aud``, ``iss``, and ``exp`` with a standard library -- no
    broker-internal shortcuts.
    """
    kid = jwt.get_unverified_header(token)["kid"]
    matches = [k for k in jwks["keys"] if k["kid"] == kid]
    assert matches, f"no JWKS key matches kid={kid!r}"
    public_key = RSAAlgorithm.from_jwk(json.dumps(matches[0]))
    return jwt.decode(
        token,
        public_key,  # type: ignore[arg-type]  # JWKS only has public keys
        algorithms=["RS256"],
        audience=audience,
        issuer=issuer,
        options={"verify_exp": True},
    )


@pytest.fixture
def rsa_key() -> rsa.RSAPrivateKey:
    return _make_rsa_key()


@pytest.fixture
def issuer(rsa_key: rsa.RSAPrivateKey) -> BrokerTokenIssuer:
    return BrokerTokenIssuer(
        private_key_pem=_private_pem(rsa_key),
        issuer=ISSUER_URL,
        ttl_seconds=600,
    )


# ---------------------------------------------------------------------------
# BrokerTokenIssuer: claims
# ---------------------------------------------------------------------------


def test_mint_claim_set_is_exactly_the_documented_set(
    issuer: BrokerTokenIssuer,
) -> None:
    token, _ = issuer.mint("user-123", "condor-token-service")
    claims = jwt.decode(token, options={"verify_signature": False})

    assert set(claims) == _BASE_CLAIMS


def test_mint_never_carries_authorization_claims(issuer: BrokerTokenIssuer) -> None:
    """Deliberately absent: capabilities, groups, or any authorization claim
    (issue #162 -- if a backend is ever written to test token.capabilities,
    this design has failed). Redundant with the exact-set assertion above,
    but named so a future 'just add the groups claim' change trips a test
    that says why not."""
    token, _ = issuer.mint(
        "user-123", "condor-token-service", uid=1000, gid=1000, unixname="auser"
    )
    claims = jwt.decode(token, options={"verify_signature": False})

    assert "capabilities" not in claims
    assert "groups" not in claims
    assert "scope" not in claims


def test_mint_posix_claim_set_is_exactly_the_documented_set(
    issuer: BrokerTokenIssuer,
) -> None:
    token, _ = issuer.mint(
        "user-123", "condor-token-service", uid=50123, gid=5000, unixname="auser"
    )
    claims = jwt.decode(token, options={"verify_signature": False})

    assert set(claims) == _POSIX_CLAIMS
    assert claims["uid"] == 50123
    assert claims["gid"] == 5000
    assert claims["unixname"] == "auser"


def test_mint_core_claim_values(issuer: BrokerTokenIssuer) -> None:
    before = int(time.time())
    token, expires_at = issuer.mint("user-123", "condor-token-service")
    after = int(time.time())
    claims = jwt.decode(token, options={"verify_signature": False})

    assert claims["iss"] == ISSUER_URL
    assert claims["sub"] == "user-123"
    assert claims["aud"] == "condor-token-service"
    assert before <= claims["iat"] <= after
    assert claims["exp"] == claims["iat"] + 600
    assert expires_at == claims["exp"]


def test_mint_jti_is_unique_per_token(issuer: BrokerTokenIssuer) -> None:
    jtis = {
        jwt.decode(
            issuer.mint("user-123", "condor-token-service")[0],
            options={"verify_signature": False},
        )["jti"]
        for _ in range(10)
    }

    assert len(jtis) == 10


def test_mint_respects_configured_ttl(rsa_key: rsa.RSAPrivateKey) -> None:
    issuer = BrokerTokenIssuer(
        private_key_pem=_private_pem(rsa_key), issuer=ISSUER_URL, ttl_seconds=42
    )
    token, expires_at = issuer.mint("user-123", "jupyter-mcp")
    claims = jwt.decode(token, options={"verify_signature": False})

    assert claims["exp"] - claims["iat"] == 42
    assert expires_at == claims["exp"]


# ---------------------------------------------------------------------------
# BrokerTokenIssuer: kid / JWKS
# ---------------------------------------------------------------------------


def test_kid_is_the_rfc7638_thumbprint(rsa_key: rsa.RSAPrivateKey) -> None:
    issuer = BrokerTokenIssuer(private_key_pem=_private_pem(rsa_key), issuer=ISSUER_URL)

    assert issuer.kid == _rfc7638_thumbprint(rsa_key)


def test_kid_is_stable_across_loads_of_the_same_key(
    rsa_key: rsa.RSAPrivateKey,
) -> None:
    pem = _private_pem(rsa_key)
    first = BrokerTokenIssuer(private_key_pem=pem, issuer=ISSUER_URL)
    second = BrokerTokenIssuer(private_key_pem=pem, issuer=ISSUER_URL)

    assert first.kid == second.kid


def test_token_header_carries_the_kid(issuer: BrokerTokenIssuer) -> None:
    token, _ = issuer.mint("user-123", "condor-token-service")

    assert jwt.get_unverified_header(token)["kid"] == issuer.kid


def test_jwks_publishes_public_material_only(issuer: BrokerTokenIssuer) -> None:
    jwks = issuer.jwks()

    assert len(jwks["keys"]) == 1
    (key,) = jwks["keys"]
    assert key["kty"] == "RSA"
    assert key["use"] == "sig"
    assert key["alg"] == "RS256"
    assert key["kid"] == issuer.kid
    # No private-key parameters, ever (RFC 7517 s6.3.2 private members).
    assert not ({"d", "p", "q", "dp", "dq", "qi"} & set(key))


def test_jwks_includes_additional_rotation_keys(
    rsa_key: rsa.RSAPrivateKey,
) -> None:
    old_key = _make_rsa_key()
    issuer = BrokerTokenIssuer(
        private_key_pem=_private_pem(rsa_key),
        issuer=ISSUER_URL,
        additional_public_key_pems=[_public_pem(old_key)],
    )
    jwks = issuer.jwks()

    kids = {k["kid"] for k in jwks["keys"]}
    assert kids == {_rfc7638_thumbprint(rsa_key), _rfc7638_thumbprint(old_key)}
    for key in jwks["keys"]:
        assert not ({"d", "p", "q", "dp", "dq", "qi"} & set(key))


def test_rotation_overlap_old_token_verifies_against_new_jwks(
    rsa_key: rsa.RSAPrivateKey,
) -> None:
    """The documented rotation procedure: a token signed by the retiring key
    must keep verifying against a JWKS whose active key is the new one, as
    long as the old public key is still published alongside it."""
    old_key = _make_rsa_key()
    old_issuer = BrokerTokenIssuer(
        private_key_pem=_private_pem(old_key), issuer=ISSUER_URL
    )
    token, _ = old_issuer.mint("user-123", "condor-token-service")

    new_issuer = BrokerTokenIssuer(
        private_key_pem=_private_pem(rsa_key),
        issuer=ISSUER_URL,
        additional_public_key_pems=[_public_pem(old_key)],
    )

    claims = verify_against_jwks(
        token, new_issuer.jwks(), audience="condor-token-service"
    )
    assert claims["sub"] == "user-123"


def test_minted_token_verifies_like_a_consumer_would(
    issuer: BrokerTokenIssuer,
) -> None:
    token, _ = issuer.mint("user-123", "condor-token-service")

    claims = verify_against_jwks(token, issuer.jwks(), audience="condor-token-service")
    assert claims["sub"] == "user-123"


def test_consumer_rejects_wrong_audience(issuer: BrokerTokenIssuer) -> None:
    """Per-backend aud enforced strictly: a token minted for one backend must
    fail verification at any other (issue #162 -- backends MUST reject
    tokens whose aud is not exactly themselves)."""
    token, _ = issuer.mint("user-123", "condor-token-service")

    with pytest.raises(jwt.InvalidAudienceError):
        verify_against_jwks(token, issuer.jwks(), audience="jupyter-mcp")


# ---------------------------------------------------------------------------
# load_broker_token_issuer (settings -> issuer)
# ---------------------------------------------------------------------------


def _write_key_files(tmp_path: Path) -> tuple[rsa.RSAPrivateKey, Path]:
    key = _make_rsa_key()
    key_file = tmp_path / "signing-key.pem"
    key_file.write_bytes(_private_pem(key))
    return key, key_file


def test_load_returns_none_when_unconfigured() -> None:
    settings = Settings(broker_public_origin="https://mcp.example.com")

    assert load_broker_token_issuer(settings) is None


def test_load_builds_issuer_from_key_file(tmp_path: Path) -> None:
    key, key_file = _write_key_files(tmp_path)
    settings = Settings(
        broker_signing_key_file=str(key_file),
        broker_public_origin="https://mcp.example.com",
    )

    issuer = load_broker_token_issuer(settings)

    assert issuer is not None
    assert issuer.kid == _rfc7638_thumbprint(key)
    token, _ = issuer.mint("user-123", "condor-token-service")
    claims = jwt.decode(token, options={"verify_signature": False})
    assert claims["iss"] == "https://mcp.example.com"


def test_load_reads_additional_public_keys_dir(tmp_path: Path) -> None:
    _, key_file = _write_key_files(tmp_path)
    old_key = _make_rsa_key()
    extra_dir = tmp_path / "additional"
    extra_dir.mkdir()
    (extra_dir / "old-key.pem").write_bytes(_public_pem(old_key))
    # Non-*.pem files (e.g. a mounted Secret's hidden ..data plumbing) are
    # ignored rather than parsed.
    (extra_dir / "README").write_text("not a key")
    settings = Settings(
        broker_signing_key_file=str(key_file),
        broker_additional_public_keys_dir=str(extra_dir),
        broker_public_origin="https://mcp.example.com",
    )

    issuer = load_broker_token_issuer(settings)

    assert issuer is not None
    kids = {k["kid"] for k in issuer.jwks()["keys"]}
    assert _rfc7638_thumbprint(old_key) in kids
    assert len(kids) == 2


def test_load_raises_when_key_file_missing(tmp_path: Path) -> None:
    settings = Settings(
        broker_signing_key_file=str(tmp_path / "nope.pem"),
        broker_public_origin="https://mcp.example.com",
    )

    with pytest.raises(RuntimeError, match="BROKER_SIGNING_KEY_FILE"):
        load_broker_token_issuer(settings)


def test_load_raises_when_key_file_is_not_a_key(tmp_path: Path) -> None:
    bad = tmp_path / "bad.pem"
    bad.write_text("this is not a PEM")
    settings = Settings(
        broker_signing_key_file=str(bad),
        broker_public_origin="https://mcp.example.com",
    )

    with pytest.raises(RuntimeError, match="BROKER_SIGNING_KEY_FILE"):
        load_broker_token_issuer(settings)


def test_load_raises_when_no_issuer_url_available(tmp_path: Path) -> None:
    _, key_file = _write_key_files(tmp_path)
    settings = Settings(broker_signing_key_file=str(key_file))

    with pytest.raises(RuntimeError, match="BROKER_TOKEN_ISSUER"):
        load_broker_token_issuer(settings)


# ---------------------------------------------------------------------------
# BrokerIssuedProvider
# ---------------------------------------------------------------------------


@pytest.fixture
def provider_factory(
    issuer: BrokerTokenIssuer,
) -> Callable[..., tuple[BrokerIssuedProvider, CredentialCache]]:
    def _make(
        target_options: dict[str, BrokerIssuedTargetOptions] | None = None,
    ) -> tuple[BrokerIssuedProvider, CredentialCache]:
        cache = CredentialCache()
        provider = BrokerIssuedProvider(
            issuer=issuer,
            cache=cache,
            alias="af-native",
            targets=frozenset({"condor-token-service", "jupyter-mcp"}),
            target_options=target_options or {},
        )
        return provider, cache

    return _make


async def test_provider_is_always_linked(provider_factory, make_principal) -> None:
    provider, _ = provider_factory()

    assert await provider.is_linked(make_principal()) is True


async def test_provider_issues_bearer_credential(
    provider_factory, make_principal, issuer: BrokerTokenIssuer
) -> None:
    provider, _ = provider_factory()
    principal = make_principal(subject="sub-abc")

    cred = await provider.issue(principal, "condor-token-service")

    assert cred.cred_class == "broker_issued"
    assert cred.kind == CredentialKind.BEARER
    assert cred.execution_model == ExecutionModel.DELEGATED
    assert cred.target == "condor-token-service"
    assert cred.payload["token_type"] == "Bearer"
    claims = verify_against_jwks(
        cred.payload["access_token"], issuer.jwks(), audience="condor-token-service"
    )
    assert claims["sub"] == "sub-abc"
    assert cred.expires_at == claims["exp"]


async def test_provider_audience_defaults_to_target_name(
    provider_factory, make_principal
) -> None:
    provider, _ = provider_factory()

    cred = await provider.issue(make_principal(), "jupyter-mcp")

    claims = jwt.decode(
        cred.payload["access_token"], options={"verify_signature": False}
    )
    assert claims["aud"] == "jupyter-mcp"


async def test_provider_audience_override_from_target_options(
    provider_factory, make_principal
) -> None:
    provider, _ = provider_factory(
        {"jupyter-mcp": BrokerIssuedTargetOptions(audience="jupyter")}
    )

    cred = await provider.issue(make_principal(), "jupyter-mcp")

    claims = jwt.decode(
        cred.payload["access_token"], options={"verify_signature": False}
    )
    assert claims["aud"] == "jupyter"


async def test_provider_omits_posix_claims_by_default(
    provider_factory, make_principal
) -> None:
    """Even for a principal that HAS a POSIX identity: without include_posix
    the token is exactly the base identity assertion."""
    provider, _ = provider_factory()
    principal = make_principal(uid=50123, gid=5000, unixname="auser")

    cred = await provider.issue(principal, "condor-token-service")

    claims = jwt.decode(
        cred.payload["access_token"], options={"verify_signature": False}
    )
    assert set(claims) == _BASE_CLAIMS


async def test_provider_includes_posix_claims_when_configured(
    provider_factory, make_principal
) -> None:
    provider, _ = provider_factory(
        {"condor-token-service": BrokerIssuedTargetOptions(include_posix=True)}
    )
    principal = make_principal(uid=50123, gid=5000, unixname="auser")

    cred = await provider.issue(principal, "condor-token-service")

    claims = jwt.decode(
        cred.payload["access_token"], options={"verify_signature": False}
    )
    assert set(claims) == _POSIX_CLAIMS
    assert claims["uid"] == 50123
    assert claims["gid"] == 5000
    assert claims["unixname"] == "auser"


async def test_provider_include_posix_without_posix_identity_raises_404(
    provider_factory, make_principal
) -> None:
    """Same point-of-use shape as x509's PosixIdentityRequiredError, raised
    as HTTPException(404) because BrokerIssuedProvider is delivered over the
    aggregator's bearer branch, which surfaces HTTPException detail cleanly
    (the OIDCProvider precedent) -- see the provider docstring."""
    provider, _ = provider_factory(
        {"condor-token-service": BrokerIssuedTargetOptions(include_posix=True)}
    )
    principal = make_principal(uid=None, gid=None, unixname=None)

    with pytest.raises(HTTPException) as excinfo:
        await provider.issue(principal, "condor-token-service")

    assert excinfo.value.status_code == 404
    assert "condor-token-service" in str(excinfo.value.detail)
    assert "POSIX" in str(excinfo.value.detail)


async def test_provider_caches_token_until_min_remaining(
    provider_factory, make_principal
) -> None:
    provider, _ = provider_factory()
    principal = make_principal(subject="sub-abc")

    first = await provider.issue(principal, "condor-token-service")
    second = await provider.issue(principal, "condor-token-service")

    # Same token (same jti) -- served from CredentialCache, no re-mint.
    assert second.payload["access_token"] == first.payload["access_token"]


async def test_provider_remints_near_expiry(
    provider_factory, make_principal, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A cached token with fewer than min_remaining seconds left is a cache
    miss (CredentialCache semantics) and must be re-minted -- this is why
    the TTL default (600) sits above the 300s floor."""
    provider, _ = provider_factory()
    principal = make_principal(subject="sub-abc")

    first = await provider.issue(principal, "condor-token-service")

    real_time = time.time
    # 400s later: 200s remain on a 600s token -- below the 300s floor.
    monkeypatch.setattr(time, "time", lambda: real_time() + 400)
    second = await provider.issue(principal, "condor-token-service")

    assert second.payload["access_token"] != first.payload["access_token"]


async def test_provider_revoke_drops_cached_credential(
    provider_factory, make_principal
) -> None:
    provider, cache = provider_factory()
    principal = make_principal(subject="sub-abc")

    first = await provider.issue(principal, "condor-token-service")
    await provider.revoke(principal, "condor-token-service")
    second = await provider.issue(principal, "condor-token-service")

    assert second.payload["access_token"] != first.payload["access_token"]
    assert cache.get_proxy_meta("sub-abc", "condor-token-service") is None


async def test_provider_mint_increments_issued_counter(
    provider_factory, make_principal
) -> None:
    from af_mcp_broker import metrics

    provider, _ = provider_factory()
    counter = metrics.broker_identity_tokens_issued_total.labels(
        target="condor-token-service"
    )
    before = counter._value.get()

    await provider.issue(make_principal(subject="sub-abc"), "condor-token-service")
    # Second call is a cache hit -- must NOT count as an issuance.
    await provider.issue(make_principal(subject="sub-abc"), "condor-token-service")

    assert counter._value.get() == before + 1
