from __future__ import annotations

import time

import pytest
from conftest import make_claims
from fastapi import HTTPException

from af_mcp_broker.authorization import get_principal_permissions
from af_mcp_broker.identity import (
    PrincipalDirectoryUnavailableError,
    TokenAudienceError,
    get_principal,
)
from af_mcp_broker.pat import mint_pat
from af_mcp_broker.pat_auth import LastUsedTracker, resolve_pat_principal
from af_mcp_broker.token_registry import (
    InMemoryTokenRegistryBackend,
    RevokedJtiCache,
    TokenRecord,
)


async def test_get_principal_selects_signing_key_when_listed_second(
    settings, sig_key, enc_key, prime_jwks, static_principal_cache
):
    """Regression for JWKS key selection (bug 1).

    The JWKS lists the encryption key FIRST and the signing key SECOND. The old
    code decoded keys in list order and treated the first signature mismatch as
    fatal, so auth failed. Selecting by the token's ``kid`` must succeed.
    """
    cache, _directory = static_principal_cache
    prime_jwks([enc_key.jwk, sig_key.jwk])
    token = sig_key.sign(make_claims())

    principal = await get_principal(token, settings, cache)

    assert principal.subject == "user-123"


async def test_expired_token_raises_401(
    settings, sig_key, prime_jwks, static_principal_cache
):
    cache, _directory = static_principal_cache
    prime_jwks([sig_key.jwk])
    now = int(time.time())
    token = sig_key.sign(make_claims(iat=now - 600, exp=now - 300))

    with pytest.raises(HTTPException) as exc:
        await get_principal(token, settings, cache)
    assert exc.value.status_code == 401


async def test_wrong_audience_raises_401(
    settings, sig_key, prime_jwks, static_principal_cache
):
    cache, _directory = static_principal_cache
    prime_jwks([sig_key.jwk])
    token = sig_key.sign(make_claims(aud="some-other-service"))

    with pytest.raises(HTTPException) as exc:
        await get_principal(token, settings, cache)
    assert exc.value.status_code == 401


async def test_wrong_audience_raises_token_audience_error_with_correlation_id(
    settings, sig_key, prime_jwks, static_principal_cache
):
    """A structurally valid token missing the expected audience is not the
    same failure as an expired/malformed one -- it's permanent until an
    admin grants the audience via group membership (docs/auth.md's
    "cascading failure" section), so it gets its own exception type and a
    correlation_id the caller can quote, mirroring permission_required in
    api/permissions.py::_service_status (see
    docs/plans/2026-08-24-audience-mismatch-error-ui-design.md)."""
    cache, _directory = static_principal_cache
    prime_jwks([sig_key.jwk])
    token = sig_key.sign(make_claims(aud="some-other-service"))

    with pytest.raises(TokenAudienceError) as exc:
        await get_principal(token, settings, cache)

    assert exc.value.status_code == 401
    assert exc.value.detail["error"] == "insufficient_scope"
    correlation_id = exc.value.detail["correlation_id"]
    assert correlation_id
    assert correlation_id in exc.value.detail["message"]


async def test_no_matching_kid_raises_401(
    settings, sig_key, enc_key, prime_jwks, static_principal_cache
):
    """A token whose kid is absent from the JWKS is rejected, not accepted."""
    cache, _directory = static_principal_cache
    prime_jwks([enc_key.jwk])  # signing key not published
    token = sig_key.sign(make_claims())

    with pytest.raises(HTTPException) as exc:
        await get_principal(token, settings, cache)
    assert exc.value.status_code == 401


# ---------------------------------------------------------------------------
# Groups unification (issue #144 step 3) -- every credential type resolves
# groups from the PrincipalDirectory via the principal cache; the token no
# longer carries authorization data of its own, only identity.
# ---------------------------------------------------------------------------


async def test_jwt_with_no_groups_claim_resolves_via_directory(
    settings, sig_key, prime_jwks, static_principal_cache
):
    """A JWT that carries no `groups` claim at all must still resolve real
    permissions -- the directory, not the claim, is the only source now."""
    cache, directory = static_principal_cache
    directory.groups_by_subject["user-123"] = ["atlas"]
    prime_jwks([sig_key.jwk])
    claims = make_claims()
    del claims["groups"]
    token = sig_key.sign(claims)

    principal = await get_principal(token, settings, cache)

    assert principal.groups == ["atlas"]


async def test_jwt_groups_claim_is_ignored_directory_is_authoritative(
    settings, sig_key, prime_jwks, static_principal_cache
):
    """The crux of issue #144 step 3: even though this JWT DOES carry a
    `groups` claim, it must be ignored entirely in favor of the directory's
    current answer. This is what makes removing someone from a Keycloak group
    a real kill switch regardless of which credential type they present --
    before this change, a still-valid JWT's own claim would have kept working
    right up until it expired."""
    cache, directory = static_principal_cache
    directory.groups_by_subject["user-123"] = ["af-admins"]
    prime_jwks([sig_key.jwk])
    token = sig_key.sign(make_claims(groups=["atlas", "totally-different-group"]))

    principal = await get_principal(token, settings, cache)

    assert principal.groups == ["af-admins"]
    assert principal.groups != ["atlas", "totally-different-group"]


async def test_cold_cache_directory_outage_raises_actionable_error(
    settings, sig_key, prime_jwks, static_principal_cache
):
    """Availability regression (issue #144 step 3): a JWT used to be
    self-contained, so a Keycloak outage never blocked authentication. Now
    groups always come from the directory, so a principal this cache has
    never resolved before, hit while the directory is unreachable, has no
    last-known value to fall back on and cannot authenticate at all. The
    resulting error must tell the caller this is a platform outage, not a
    problem with their credentials -- distinct from the vague 401 every
    other validation failure raises."""
    cache, directory = static_principal_cache
    directory.unavailable_subjects.add("user-123")
    prime_jwks([sig_key.jwk])
    token = sig_key.sign(make_claims())

    with pytest.raises(PrincipalDirectoryUnavailableError) as exc:
        await get_principal(token, settings, cache)

    assert exc.value.status_code == 503
    detail = str(exc.value.detail).lower()
    assert "unavailable" in detail or "outage" in detail
    assert "invalid" not in detail  # must not read like a bad-credential 401


async def test_get_principal_without_a_configured_directory_raises_actionable_error(
    settings, sig_key, prime_jwks
):
    """No PrincipalCache configured at all (principal_cache=None) is a
    startup misconfiguration app.py's lifespan is meant to prevent -- but if
    it's ever reached anyway (e.g. a test, or a future embedding that skips
    the fail-fast check), it must fail the same actionable way an outage
    does, not crash with an AttributeError on a None cache."""
    prime_jwks([sig_key.jwk])
    token = sig_key.sign(make_claims())

    with pytest.raises(PrincipalDirectoryUnavailableError) as exc:
        await get_principal(token, settings, None)

    assert exc.value.status_code == 503


async def test_jwt_and_pat_for_same_principal_get_identical_permissions(
    settings, sig_key, prime_jwks, static_principal_cache, policy
):
    """The whole point of unifying groups resolution through the directory
    (issue #144 step 3): a JWT and an identity PAT for the *same* principal
    must resolve to the exact same permission set, since both now derive
    their groups from the same PrincipalCache/PrincipalDirectory rather than
    a JWT and a PAT being able to disagree about what one user can do."""
    principal_cache, directory = static_principal_cache
    directory.groups_by_subject["user-123"] = ["atlas"]

    prime_jwks([sig_key.jwk])
    jwt_token = sig_key.sign(make_claims())
    jwt_principal = await get_principal(jwt_token, settings, principal_cache)

    pat_backend = InMemoryTokenRegistryBackend()
    plaintext, lookup_id, secret_hash = mint_pat()
    await pat_backend.add(
        TokenRecord(
            lookup_id=lookup_id,
            principal_id="user-123",
            secret_hash=secret_hash,
            name="test-token",
            created_at=time.time(),
            expires_at=time.time() + 3600,
            revoked_at=None,
            last_used_at=None,
        )
    )
    pat_principal = await resolve_pat_principal(
        plaintext, settings, pat_backend, principal_cache, LastUsedTracker()
    )

    assert jwt_principal.groups == pat_principal.groups == ["atlas"]
    assert get_principal_permissions(
        jwt_principal, policy
    ) == get_principal_permissions(pat_principal, policy)
    assert get_principal_permissions(
        jwt_principal, policy
    )  # non-empty: a real assertion


# ---------------------------------------------------------------------------
# POSIX unification (issue #144 step 3b) -- every credential type resolves
# POSIX identity (uid/gid/unixname) from the PrincipalDirectory via the
# principal cache, completing what step 3 did for groups; the token no
# longer carries identity data of its own beyond `sub`/`email`.
# ---------------------------------------------------------------------------


async def test_jwt_with_no_posix_claim_resolves_via_directory(
    settings, sig_key, prime_jwks, static_principal_cache
):
    """A JWT that carries no `posix` claim at all must still resolve real
    POSIX identity -- the directory, not the claim, is the only source now."""
    cache, directory = static_principal_cache
    directory.posix_by_subject["user-123"] = {
        "uid": 60001,
        "gid": 6000,
        "unixname": "dirauser",
    }
    prime_jwks([sig_key.jwk])
    claims = make_claims()
    del claims["posix"]
    token = sig_key.sign(claims)

    principal = await get_principal(token, settings, cache)

    assert principal.uid == 60001
    assert principal.gid == 6000
    assert principal.unixname == "dirauser"


async def test_jwt_posix_claim_is_ignored_directory_is_authoritative(
    settings, sig_key, prime_jwks, static_principal_cache
):
    """The crux of issue #144 step 3b: even though this JWT DOES carry a
    `posix` claim, it must be ignored entirely in favor of the directory's
    current answer -- mirroring
    test_jwt_groups_claim_is_ignored_directory_is_authoritative above. This
    is what makes the four POSIX mappers safe to delete: a still-valid JWT's
    own claim can no longer keep serving a uid/gid/unixname the directory has
    since moved on from."""
    cache, directory = static_principal_cache
    directory.posix_by_subject["user-123"] = {
        "uid": 70002,
        "gid": 7000,
        "unixname": "realauser",
    }
    prime_jwks([sig_key.jwk])
    token = sig_key.sign(
        make_claims(posix={"uid": 50123, "gid": 5000, "unixname": "auser"})
    )

    principal = await get_principal(token, settings, cache)

    assert principal.uid == 70002
    assert principal.gid == 7000
    assert principal.unixname == "realauser"
    assert principal.uid != 50123


async def test_principal_with_no_posix_anywhere_still_authenticates(
    settings, sig_key, prime_jwks, static_principal_cache
):
    """Issue #149's optional-POSIX guarantee must survive the move to the
    directory: a principal the directory has no POSIX attributes for at all
    still authenticates successfully, with uid/gid/unixname left None rather
    than 401ing -- the point-of-use check in credentials/x509.py is the only
    place that requirement is enforced (see test_x509.py)."""
    cache, _directory = static_principal_cache
    prime_jwks([sig_key.jwk])
    claims = make_claims()
    del claims["posix"]
    token = sig_key.sign(claims)

    principal = await get_principal(token, settings, cache)

    assert principal.uid is None
    assert principal.gid is None
    assert principal.unixname is None
    assert principal.subject == "user-123"


async def test_jwt_and_pat_for_same_principal_get_identical_posix(
    settings, sig_key, prime_jwks, static_principal_cache
):
    """The POSIX counterpart to test_jwt_and_pat_for_same_principal_get_identical_permissions:
    a JWT and an identity PAT for the *same* principal must resolve to the
    exact same uid/gid/unixname, since both now derive POSIX identity from
    the same PrincipalCache/PrincipalDirectory rather than a JWT's own claim
    and a PAT being able to disagree about who one user is on the
    filesystem."""
    principal_cache, directory = static_principal_cache
    directory.posix_by_subject["user-123"] = {
        "uid": 60001,
        "gid": 6000,
        "unixname": "dirauser",
    }

    prime_jwks([sig_key.jwk])
    jwt_token = sig_key.sign(make_claims())
    jwt_principal = await get_principal(jwt_token, settings, principal_cache)

    pat_backend = InMemoryTokenRegistryBackend()
    plaintext, lookup_id, secret_hash = mint_pat()
    await pat_backend.add(
        TokenRecord(
            lookup_id=lookup_id,
            principal_id="user-123",
            secret_hash=secret_hash,
            name="test-token",
            created_at=time.time(),
            expires_at=time.time() + 3600,
            revoked_at=None,
            last_used_at=None,
        )
    )
    pat_principal = await resolve_pat_principal(
        plaintext, settings, pat_backend, principal_cache, LastUsedTracker()
    )

    assert jwt_principal.uid == pat_principal.uid == 60001
    assert jwt_principal.gid == pat_principal.gid == 6000
    assert jwt_principal.unixname == pat_principal.unixname == "dirauser"


# ---------------------------------------------------------------------------
# Revoked-jti enforcement (issue #115) — get_principal is the single choke
# point both keycloak_dependency (/v1) and IdentityMiddleware (/mcp) call,
# so testing it here covers both call sites.
# ---------------------------------------------------------------------------


async def test_revoked_jti_raises_401(
    settings, sig_key, prime_jwks, static_principal_cache
):
    principal_cache, _directory = static_principal_cache
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
    revoked_cache = RevokedJtiCache(backend, refresh_interval_seconds=30.0)

    with pytest.raises(HTTPException) as exc:
        await get_principal(
            token, settings, principal_cache, revoked_jti_cache=revoked_cache
        )
    assert exc.value.status_code == 401


async def test_unrevoked_jti_still_succeeds(
    settings, sig_key, prime_jwks, static_principal_cache
):
    principal_cache, _directory = static_principal_cache
    prime_jwks([sig_key.jwk])
    token = sig_key.sign(make_claims(jti="an-active-jti"))
    revoked_cache = RevokedJtiCache(
        InMemoryTokenRegistryBackend(), refresh_interval_seconds=30.0
    )

    principal = await get_principal(
        token, settings, principal_cache, revoked_jti_cache=revoked_cache
    )

    assert principal.subject == "user-123"


async def test_ordinary_keycloak_session_token_unaffected_by_empty_registry(
    settings, sig_key, prime_jwks, static_principal_cache
):
    """A regular Keycloak-issued session token's jti was never minted through
    the manual-token registry at all -- it must never be rejected just
    because a RevokedJtiCache is wired in."""
    principal_cache, _directory = static_principal_cache
    prime_jwks([sig_key.jwk])
    token = sig_key.sign(make_claims(jti="regular-keycloak-session-jti"))
    revoked_cache = RevokedJtiCache(
        InMemoryTokenRegistryBackend(), refresh_interval_seconds=30.0
    )

    principal = await get_principal(
        token, settings, principal_cache, revoked_jti_cache=revoked_cache
    )

    assert principal.subject == "user-123"


async def test_no_revoked_jti_cache_configured_does_not_check_revocation(
    settings, sig_key, prime_jwks, static_principal_cache
):
    """revoked_jti_cache defaults to None -- e.g. a broker with no token
    registry configured -- and validation must proceed exactly as before."""
    principal_cache, _directory = static_principal_cache
    prime_jwks([sig_key.jwk])
    token = sig_key.sign(make_claims(jti="whatever"))

    principal = await get_principal(token, settings, principal_cache)

    assert principal.subject == "user-123"


async def test_token_with_no_jti_claim_is_unaffected_by_revocation_check(
    settings, sig_key, prime_jwks, static_principal_cache
):
    """Some tokens may not carry a jti at all -- revocation can never apply
    to them, so the check must be skipped rather than erroring."""
    principal_cache, _directory = static_principal_cache
    prime_jwks([sig_key.jwk])
    claims = make_claims()
    assert "jti" not in claims
    token = sig_key.sign(claims)
    revoked_cache = RevokedJtiCache(
        InMemoryTokenRegistryBackend(), refresh_interval_seconds=30.0
    )

    principal = await get_principal(
        token, settings, principal_cache, revoked_jti_cache=revoked_cache
    )

    assert principal.subject == "user-123"
