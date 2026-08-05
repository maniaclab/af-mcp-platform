"""Tests for pat_auth.resolve_pat_principal (issue #144 step 2a).

Fakes the PAT backend (InMemoryTokenRegistryBackend -- a real implementation,
not a mock, since it's fast and in-process) and PrincipalCache/PrincipalDirectory
(a fake ABC subclass -- never a real Keycloak) to isolate the validation
orchestration this module owns.
"""

from __future__ import annotations

import time

import pytest
from fastapi import HTTPException

from af_mcp_broker.config import Settings
from af_mcp_broker.identity import TokenExpiredError
from af_mcp_broker.pat import mint_pat
from af_mcp_broker.pat_auth import LastUsedTracker, resolve_pat_principal
from af_mcp_broker.principal_cache import PrincipalCache
from af_mcp_broker.principal_directory import PrincipalAttributes, PrincipalDirectory
from af_mcp_broker.token_registry import InMemoryTokenRegistryBackend, TokenRecord


class _FakeDirectory(PrincipalDirectory):
    def __init__(self) -> None:
        self.responses: dict[str, PrincipalAttributes] = {}

    async def resolve(self, principal_id: str) -> PrincipalAttributes:
        return self.responses[principal_id]


@pytest.fixture
def settings() -> Settings:
    return Settings(portal_url="https://mcp-portal.test")


@pytest.fixture
def pat_backend() -> InMemoryTokenRegistryBackend:
    return InMemoryTokenRegistryBackend()


@pytest.fixture
def directory() -> _FakeDirectory:
    return _FakeDirectory()


@pytest.fixture
def principal_cache(directory: _FakeDirectory) -> PrincipalCache:
    return PrincipalCache(
        directory, refresh_interval_seconds=1000.0, max_staleness_seconds=3600.0
    )


@pytest.fixture
def tracker() -> LastUsedTracker:
    return LastUsedTracker()


async def _mint_and_store(
    pat_backend: InMemoryTokenRegistryBackend,
    *,
    principal_id: str = "kc-sub-1",
    expires_at: float | None = None,
    revoked: bool = False,
    name: str = "test-token",
) -> str:
    plaintext, lookup_id, secret_hash = mint_pat()
    now = time.time()
    record = TokenRecord(
        lookup_id=lookup_id,
        principal_id=principal_id,
        secret_hash=secret_hash,
        name=name,
        created_at=now,
        expires_at=expires_at if expires_at is not None else now + 3600,
        revoked_at=None,
        last_used_at=None,
    )
    await pat_backend.add(record)
    if revoked:
        await pat_backend.revoke(principal_id, lookup_id, revoked_at=now)
    return plaintext


async def test_valid_pat_resolves_principal(
    settings, pat_backend, principal_cache, directory, tracker
) -> None:
    directory.responses["kc-sub-1"] = PrincipalAttributes(
        uid=50123, gid=5000, unixname="auser", groups=["atlas"], email="a@x.org"
    )
    token = await _mint_and_store(pat_backend, principal_id="kc-sub-1")

    principal = await resolve_pat_principal(
        token, settings, pat_backend, principal_cache, tracker
    )

    assert principal.subject == "kc-sub-1"
    assert principal.uid == 50123
    assert principal.gid == 5000
    assert principal.unixname == "auser"
    assert principal.groups == ["atlas"]
    assert principal.email == "a@x.org"
    assert principal.raw_token.get_secret_value() == token


async def test_valid_pat_with_no_posix_identity_resolves_principal(
    settings, pat_backend, principal_cache, directory, tracker
) -> None:
    """Issue #148: a PAT for a Keycloak user with no POSIX profile
    attributes must still authenticate successfully, with uid/gid/unixname
    left None -- mirroring the JWT path's same relaxation."""
    directory.responses["kc-sub-1"] = PrincipalAttributes(
        uid=None, gid=None, unixname=None, groups=["atlas"], email="a@x.org"
    )
    token = await _mint_and_store(pat_backend, principal_id="kc-sub-1")

    principal = await resolve_pat_principal(
        token, settings, pat_backend, principal_cache, tracker
    )

    assert principal.subject == "kc-sub-1"
    assert principal.uid is None
    assert principal.gid is None
    assert principal.unixname is None
    assert principal.groups == ["atlas"]


async def test_malformed_token_rejected(
    settings, pat_backend, principal_cache, tracker
) -> None:
    with pytest.raises(HTTPException) as exc:
        await resolve_pat_principal(
            "mcp_pat_not-well-formed", settings, pat_backend, principal_cache, tracker
        )
    assert exc.value.status_code == 401


async def test_unknown_lookup_id_rejected(
    settings, pat_backend, principal_cache, tracker
) -> None:
    plaintext, _, _ = mint_pat()  # never stored

    with pytest.raises(HTTPException) as exc:
        await resolve_pat_principal(
            plaintext, settings, pat_backend, principal_cache, tracker
        )
    assert exc.value.status_code == 401


async def test_wrong_secret_rejected(
    settings, pat_backend, principal_cache, directory, tracker
) -> None:
    directory.responses["kc-sub-1"] = PrincipalAttributes(
        uid=1, gid=1, unixname="u", groups=[], email=""
    )
    token = await _mint_and_store(pat_backend, principal_id="kc-sub-1")
    lookup_id = token.split("_")[2]
    tampered = f"mcp_pat_{lookup_id}_wrong-secret-value"

    with pytest.raises(HTTPException) as exc:
        await resolve_pat_principal(
            tampered, settings, pat_backend, principal_cache, tracker
        )
    assert exc.value.status_code == 401


async def test_revoked_pat_rejected(
    settings, pat_backend, principal_cache, directory, tracker
) -> None:
    directory.responses["kc-sub-1"] = PrincipalAttributes(
        uid=1, gid=1, unixname="u", groups=[], email=""
    )
    token = await _mint_and_store(pat_backend, principal_id="kc-sub-1", revoked=True)

    with pytest.raises(HTTPException) as exc:
        await resolve_pat_principal(
            token, settings, pat_backend, principal_cache, tracker
        )
    assert exc.value.status_code == 401


async def test_expired_pat_raises_token_expired_error_with_portal_hint(
    settings, pat_backend, principal_cache, directory, tracker
) -> None:
    directory.responses["kc-sub-1"] = PrincipalAttributes(
        uid=1, gid=1, unixname="u", groups=[], email=""
    )
    token = await _mint_and_store(
        pat_backend, principal_id="kc-sub-1", expires_at=time.time() - 10
    )

    with pytest.raises(TokenExpiredError) as exc:
        await resolve_pat_principal(
            token, settings, pat_backend, principal_cache, tracker
        )
    assert exc.value.status_code == 401
    assert "expired" in exc.value.detail
    assert "https://mcp-portal.test/tokens" in exc.value.detail


async def test_never_expiring_pat_never_raises_expired(
    settings, pat_backend, principal_cache, directory, tracker
) -> None:
    directory.responses["kc-sub-1"] = PrincipalAttributes(
        uid=1, gid=1, unixname="u", groups=[], email=""
    )
    token = await _mint_and_store(pat_backend, principal_id="kc-sub-1", expires_at=None)

    principal = await resolve_pat_principal(
        token, settings, pat_backend, principal_cache, tracker
    )
    assert principal.subject == "kc-sub-1"


async def test_principal_cache_unavailable_maps_to_vague_401(
    settings, pat_backend, tracker
) -> None:
    """A principal_cache resolution failure (e.g. Keycloak outage past the
    staleness bound) must be exactly as vague as any other PAT failure --
    see this module's docstring on why it doesn't get a distinct status."""
    directory = _FakeDirectory()  # no responses registered -> resolve() raises KeyError
    principal_cache = PrincipalCache(
        directory, refresh_interval_seconds=1000.0, max_staleness_seconds=3600.0
    )
    token = await _mint_and_store(pat_backend, principal_id="kc-sub-1")

    with pytest.raises(HTTPException) as exc:
        await resolve_pat_principal(
            token, settings, pat_backend, principal_cache, tracker
        )
    assert exc.value.status_code == 401
    assert exc.value.detail == "Invalid bearer token"


# ---------------------------------------------------------------------------
# last_used_at throttling
# ---------------------------------------------------------------------------


async def test_successful_validation_touches_last_used_at(
    settings, pat_backend, principal_cache, directory, tracker
) -> None:
    directory.responses["kc-sub-1"] = PrincipalAttributes(
        uid=1, gid=1, unixname="u", groups=[], email=""
    )
    token = await _mint_and_store(pat_backend, principal_id="kc-sub-1")
    lookup_id = token.split("_")[2]

    await resolve_pat_principal(token, settings, pat_backend, principal_cache, tracker)

    record = await pat_backend.get_by_lookup_id(lookup_id)
    assert record is not None
    assert record.last_used_at is not None


async def test_last_used_at_write_is_throttled(
    settings, pat_backend, principal_cache, directory, tracker
) -> None:
    directory.responses["kc-sub-1"] = PrincipalAttributes(
        uid=1, gid=1, unixname="u", groups=[], email=""
    )
    token = await _mint_and_store(pat_backend, principal_id="kc-sub-1")
    lookup_id = token.split("_")[2]

    await resolve_pat_principal(token, settings, pat_backend, principal_cache, tracker)
    first_touch = (await pat_backend.get_by_lookup_id(lookup_id)).last_used_at

    # Manually clear it to prove a second call within the throttle window
    # does NOT write again (rather than merely writing the same value twice,
    # which wouldn't distinguish "throttled" from "wrote, coincidentally
    # same value").
    await pat_backend.touch_last_used("kc-sub-1", lookup_id, at=0.0)

    await resolve_pat_principal(token, settings, pat_backend, principal_cache, tracker)
    second_touch = (await pat_backend.get_by_lookup_id(lookup_id)).last_used_at

    assert first_touch is not None
    assert second_touch == 0.0  # untouched by the second call -- throttled


async def test_last_used_at_write_happens_again_after_throttle_window(
    settings, pat_backend, principal_cache, directory
) -> None:
    directory.responses["kc-sub-1"] = PrincipalAttributes(
        uid=1, gid=1, unixname="u", groups=[], email=""
    )
    token = await _mint_and_store(pat_backend, principal_id="kc-sub-1")
    lookup_id = token.split("_")[2]
    tracker = LastUsedTracker(throttle_seconds=0.0)

    await resolve_pat_principal(token, settings, pat_backend, principal_cache, tracker)
    await pat_backend.touch_last_used("kc-sub-1", lookup_id, at=0.0)
    await resolve_pat_principal(token, settings, pat_backend, principal_cache, tracker)

    record = await pat_backend.get_by_lookup_id(lookup_id)
    assert record.last_used_at != 0.0


def test_last_used_tracker_due_is_false_within_window() -> None:
    tracker = LastUsedTracker(throttle_seconds=1000.0)
    assert tracker.due("x") is True
    assert tracker.due("x") is False


def test_last_used_tracker_due_true_for_different_lookup_ids() -> None:
    tracker = LastUsedTracker(throttle_seconds=1000.0)
    assert tracker.due("a") is True
    assert tracker.due("b") is True
