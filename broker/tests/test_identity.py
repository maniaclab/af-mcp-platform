from __future__ import annotations

import time

import pytest
from conftest import make_claims
from fastapi import HTTPException

from af_mcp_broker.identity import get_principal
from af_mcp_broker.token_registry import InMemoryTokenRegistryBackend, RevokedJtiCache


async def test_get_principal_selects_signing_key_when_listed_second(
    settings, sig_key, enc_key, prime_jwks
):
    """Regression for JWKS key selection (bug 1).

    The JWKS lists the encryption key FIRST and the signing key SECOND. The old
    code decoded keys in list order and treated the first signature mismatch as
    fatal, so auth failed. Selecting by the token's ``kid`` must succeed.
    """
    prime_jwks([enc_key.jwk, sig_key.jwk])
    token = sig_key.sign(make_claims())

    principal = await get_principal(token, settings)

    assert principal.uid == 50123
    assert principal.gid == 5000
    assert principal.unixname == "auser"
    assert principal.subject == "user-123"


async def test_expired_token_raises_401(settings, sig_key, prime_jwks):
    prime_jwks([sig_key.jwk])
    now = int(time.time())
    token = sig_key.sign(make_claims(iat=now - 600, exp=now - 300))

    with pytest.raises(HTTPException) as exc:
        await get_principal(token, settings)
    assert exc.value.status_code == 401


async def test_wrong_audience_raises_401(settings, sig_key, prime_jwks):
    prime_jwks([sig_key.jwk])
    token = sig_key.sign(make_claims(aud="some-other-service"))

    with pytest.raises(HTTPException) as exc:
        await get_principal(token, settings)
    assert exc.value.status_code == 401


async def test_missing_posix_claim_authenticates_successfully(
    settings, sig_key, prime_jwks
):
    """Issue #148: POSIX identity is optional -- a JWT with no `posix` claim
    at all must authenticate successfully, not 401. This is the change that
    unblocks the operator's plan to remove the claim from tokens entirely."""
    prime_jwks([sig_key.jwk])
    claims = make_claims()
    del claims["posix"]
    token = sig_key.sign(claims)

    principal = await get_principal(token, settings)

    assert principal.uid is None
    assert principal.gid is None
    assert principal.unixname is None
    assert principal.subject == "user-123"


async def test_partial_posix_claim_resolves_available_fields(
    settings, sig_key, prime_jwks
):
    """A malformed/partial posix claim (some keys present, some absent) must
    still authenticate -- issue #148 resolves POSIX identity opportunistically
    per field rather than all-or-nothing. Regression for bug 4 in spirit: a
    missing key must never surface as a 500, and now not even as a 401."""
    prime_jwks([sig_key.jwk])
    token = sig_key.sign(make_claims(posix={"gid": 5000, "unixname": "auser"}))

    principal = await get_principal(token, settings)

    assert principal.uid is None
    assert principal.gid == 5000
    assert principal.unixname == "auser"


async def test_no_matching_kid_raises_401(settings, sig_key, enc_key, prime_jwks):
    """A token whose kid is absent from the JWKS is rejected, not accepted."""
    prime_jwks([enc_key.jwk])  # signing key not published
    token = sig_key.sign(make_claims())

    with pytest.raises(HTTPException) as exc:
        await get_principal(token, settings)
    assert exc.value.status_code == 401


# ---------------------------------------------------------------------------
# Revoked-jti enforcement (issue #115) — get_principal is the single choke
# point both keycloak_dependency (/v1) and IdentityMiddleware (/mcp) call,
# so testing it here covers both call sites.
# ---------------------------------------------------------------------------


async def test_revoked_jti_raises_401(settings, sig_key, prime_jwks):
    prime_jwks([sig_key.jwk])
    token = sig_key.sign(make_claims(jti="revoked-jti-1"))
    backend = InMemoryTokenRegistryBackend()
    from af_mcp_broker.token_registry import TokenRecord

    await backend.add(
        TokenRecord(
            lookup_id="revoked-jti-1",
            principal_id="user-123",
            secret_hash="unused-in-this-test",
            name="test-token",
            created_at=time.time(),
            expires_at=time.time() + 3600,
            revoked_at=None,
            last_used_at=None,
        )
    )
    await backend.revoke("user-123", "revoked-jti-1", revoked_at=time.time())
    cache = RevokedJtiCache(backend, refresh_interval_seconds=30.0)

    with pytest.raises(HTTPException) as exc:
        await get_principal(token, settings, revoked_jti_cache=cache)
    assert exc.value.status_code == 401


async def test_unrevoked_jti_still_succeeds(settings, sig_key, prime_jwks):
    prime_jwks([sig_key.jwk])
    token = sig_key.sign(make_claims(jti="an-active-jti"))
    cache = RevokedJtiCache(
        InMemoryTokenRegistryBackend(), refresh_interval_seconds=30.0
    )

    principal = await get_principal(token, settings, revoked_jti_cache=cache)

    assert principal.uid == 50123


async def test_ordinary_keycloak_session_token_unaffected_by_empty_registry(
    settings, sig_key, prime_jwks
):
    """A regular Keycloak-issued session token's jti was never minted through
    the manual-token registry at all -- it must never be rejected just
    because a RevokedJtiCache is wired in."""
    prime_jwks([sig_key.jwk])
    token = sig_key.sign(make_claims(jti="regular-keycloak-session-jti"))
    cache = RevokedJtiCache(
        InMemoryTokenRegistryBackend(), refresh_interval_seconds=30.0
    )

    principal = await get_principal(token, settings, revoked_jti_cache=cache)

    assert principal.uid == 50123


async def test_no_revoked_jti_cache_configured_does_not_check_revocation(
    settings, sig_key, prime_jwks
):
    """revoked_jti_cache defaults to None -- e.g. a broker with no token
    registry configured -- and validation must proceed exactly as before."""
    prime_jwks([sig_key.jwk])
    token = sig_key.sign(make_claims(jti="whatever"))

    principal = await get_principal(token, settings)

    assert principal.uid == 50123


async def test_token_with_no_jti_claim_is_unaffected_by_revocation_check(
    settings, sig_key, prime_jwks
):
    """Some tokens may not carry a jti at all -- revocation can never apply
    to them, so the check must be skipped rather than erroring."""
    prime_jwks([sig_key.jwk])
    claims = make_claims()
    assert "jti" not in claims
    token = sig_key.sign(claims)
    cache = RevokedJtiCache(
        InMemoryTokenRegistryBackend(), refresh_interval_seconds=30.0
    )

    principal = await get_principal(token, settings, revoked_jti_cache=cache)

    assert principal.uid == 50123
