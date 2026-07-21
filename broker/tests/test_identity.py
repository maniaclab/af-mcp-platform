from __future__ import annotations

import time

import pytest
from fastapi import HTTPException

from af_mcp_broker.identity import get_principal

from conftest import make_claims


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


async def test_missing_posix_claim_raises_401(settings, sig_key, prime_jwks):
    prime_jwks([sig_key.jwk])
    claims = make_claims()
    del claims["posix"]
    token = sig_key.sign(claims)

    with pytest.raises(HTTPException) as exc:
        await get_principal(token, settings)
    assert exc.value.status_code == 401


async def test_posix_missing_uid_raises_401(settings, sig_key, prime_jwks):
    """Regression for bug 4 — a malformed posix claim must be 401, not 500."""
    prime_jwks([sig_key.jwk])
    token = sig_key.sign(make_claims(posix={"gid": 5000, "unixname": "auser"}))

    with pytest.raises(HTTPException) as exc:
        await get_principal(token, settings)
    assert exc.value.status_code == 401


async def test_no_matching_kid_raises_401(settings, sig_key, enc_key, prime_jwks):
    """A token whose kid is absent from the JWKS is rejected, not accepted."""
    prime_jwks([enc_key.jwk])  # signing key not published
    token = sig_key.sign(make_claims())

    with pytest.raises(HTTPException) as exc:
        await get_principal(token, settings)
    assert exc.value.status_code == 401
