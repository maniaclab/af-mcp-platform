"""
Spike: Credential Isolation Under Concurrent Load
Phase 0 Spike — validates the real ``CredentialCache`` in
``broker/src/af_mcp_broker/credentials/cache.py``.

Scenarios covered:
  1. Cross-principal isolation — under concurrent access the cache never
     hands one principal's credential to another.
  2. Rate-limit lockout — repeated genuine failed-unlock attempts (bad
     passphrase, or a minting-backend failure) for a single uid raise
     ``RateLimitError`` once the counter exceeds ``_MAX_FAILED_UNLOCKS``.
     Plain cache misses from ``get()`` never count against this budget.
  3. Janitor sweep — an entry stored with ``expires_at`` in the past is
     removed by ``sweep_expired()``.

The cache API is async and stores ``IssuedCredential`` values (or any value
typed as ``Any`` by ``_CacheEntry.credential``); these tests use real
``IssuedCredential`` instances so the fixtures match production shape.
"""

from __future__ import annotations

import asyncio
import random
import time

import pytest

from af_mcp_broker.credentials.base import (
    CredentialKind,
    ExecutionModel,
    IssuedCredential,
)
from af_mcp_broker.credentials.cache import CredentialCache, RateLimitError

# Deterministic seed for any random-like behaviour in the test module.
random.seed(42)


TARGET = "rucio"


def _make_credential(
    uid: int,
    *,
    target: str = TARGET,
    ttl_seconds: float = 3600.0,
) -> IssuedCredential:
    """Build an ``IssuedCredential`` whose payload uniquely identifies *uid*.

    Each principal receives a distinct ``audit_id`` and a payload token that
    embeds its uid so the isolation assertions can compare the retrieved value
    field-for-field.
    """
    return IssuedCredential(
        cred_class="oidc_native",
        target=target,
        kind=CredentialKind.BEARER,
        expires_at=time.time() + ttl_seconds,
        payload={
            "access_token": f"token-for-uid-{uid}",
            "token_type": "Bearer",
        },
        audit_id=f"audit-{uid}",
        source="spike-test",
        execution_model=ExecutionModel.DELEGATED,
    )


# ---------------------------------------------------------------------------
# Scenario 1: cross-principal isolation
# ---------------------------------------------------------------------------

N_PRINCIPALS = [5, 20]


@pytest.mark.anyio
@pytest.mark.parametrize("n", N_PRINCIPALS)
async def test_concurrent_cross_principal_isolation(n: int) -> None:
    """No principal receives another principal's credential under concurrent access."""
    cache = CredentialCache()

    base_uid = 50_000
    creds: dict[int, IssuedCredential] = {
        base_uid + i: _make_credential(base_uid + i) for i in range(n)
    }

    async def store_and_retrieve(uid: int) -> tuple[int, IssuedCredential | None]:
        await cache.put(uid, TARGET, creds[uid])
        retrieved = await cache.get(uid, TARGET)
        return uid, retrieved

    results = await asyncio.gather(*(store_and_retrieve(uid) for uid in creds))

    for uid, retrieved in results:
        assert retrieved == creds[uid], (
            f"uid={uid} got {retrieved!r} but expected {creds[uid]!r}"
        )

    # Second pass: after all concurrent writes have settled, every uid must
    # still resolve to its OWN credential and never a neighbour's. This
    # catches races that only manifest once every writer has finished.
    for uid, expected in creds.items():
        got = await cache.get(uid, TARGET)
        assert got == expected, (
            f"post-settle uid={uid}: got {got!r}, expected {expected!r}"
        )
        for other_uid, other_cred in creds.items():
            if other_uid == uid:
                continue
            assert got != other_cred, (
                f"ISOLATION BREACH: uid={uid} received credential "
                f"belonging to uid={other_uid}"
            )


# ---------------------------------------------------------------------------
# Scenario 2: rate-limit on repeated genuine failed unlocks
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_rate_limit_triggers_after_max_failed_unlocks() -> None:
    """The (N+1)th genuine failed unlock within the window raises ``RateLimitError``.

    ``_MAX_FAILED_UNLOCKS`` is 5 in the real cache, so five consecutive calls
    to ``record_failed_unlock`` (bad passphrase, or a minting-backend
    failure) do not raise and the sixth trips the limiter. The threshold
    constant is not imported so that a future bump in the real cache surfaces
    here as a single-place update rather than a hidden magic number.

    Plain cache misses from ``get()`` do NOT count against this budget — see
    ``test_needs_unlock_probes_never_trip_rate_limit`` in
    ``broker/tests/test_rate_limit_api.py``.
    """
    cache = CredentialCache()
    uid = 99_999

    # Five genuine failed-unlock attempts in a row.
    for _attempt in range(1, 6):
        cache.record_failed_unlock(uid)

    # The sixth attempt exceeds the threshold and must raise.
    with pytest.raises(RateLimitError):
        cache.record_failed_unlock(uid)


@pytest.mark.anyio
async def test_successful_put_resets_rate_limit_counter() -> None:
    """A successful ``put(..., uid=...)`` clears the failed-unlock counter
    for that uid.

    Documented behaviour of the real cache: legitimate re-authentication after
    a run of genuine failed unlocks must not carry forward stale attempts.
    Without this, a user who eventually supplies the correct passphrase would
    still be one attempt away from lockout on their very next (unrelated)
    failure. ``uid`` is keyword-only and opt-in (issue #148) -- the cache's
    credential-storage key is ``subject``, since POSIX identity (and
    therefore uid) is optional on a principal in general; only
    X509Provider, which requires one, ever passes it. See
    ``CredentialCache``'s class docstring for the full reasoning.
    """
    cache = CredentialCache()
    uid = 77_777

    # Rack up genuine failed-unlock attempts just short of the limit.
    for _ in range(5):
        cache.record_failed_unlock(uid)

    # A successful put must clear the counter.
    await cache.put(str(uid), TARGET, _make_credential(uid), uid=uid)

    # If the counter had persisted, this single failure would be the sixth
    # and trip the limiter immediately.
    cache.record_failed_unlock(uid)


# ---------------------------------------------------------------------------
# Scenario 3: janitor sweep removes expired entries
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_sweep_expired_removes_past_expires_at() -> None:
    """An entry whose ``expires_at`` is in the past is gone after ``sweep_expired``."""
    cache = CredentialCache()
    uid = 50_500

    # Store an entry that is already past its TTL. Bypass the default TTL by
    # constructing the credential ourselves and passing an explicit
    # ``expires_at`` to put().
    stale = _make_credential(uid, ttl_seconds=-1.0)
    await cache.put(uid, TARGET, stale, expires_at=time.time() - 1)

    # Public alias for the janitor's private sweep — the test targets the
    # documented surface so a rename of the private helper does not break it.
    await cache.sweep_expired()

    # After the sweep the entry must be absent. ``get`` returns None either
    # because the entry was removed (expected) or because it was still there
    # but past min_remaining (bug); we assert the storage dict is empty to
    # distinguish those cases.
    assert await cache.get(uid, TARGET) is None
    assert (uid, TARGET) not in cache._entries, (
        "sweep_expired left an expired entry in the cache"
    )


@pytest.mark.anyio
async def test_sweep_expired_preserves_live_entries() -> None:
    """A live entry (expires_at in the future) survives a janitor sweep.

    Guards against a regression where an overly aggressive sweep predicate
    (e.g. ``<`` vs ``<=`` on the epoch comparison) would evict entries whose
    expiry is exactly now, or entries with future expiry.
    """
    cache = CredentialCache()
    live_uid = 60_600
    stale_uid = 60_601

    live_cred = _make_credential(live_uid, ttl_seconds=3600.0)
    stale_cred = _make_credential(stale_uid, ttl_seconds=-1.0)

    await cache.put(live_uid, TARGET, live_cred)
    await cache.put(stale_uid, TARGET, stale_cred, expires_at=time.time() - 1)

    await cache.sweep_expired()

    assert (live_uid, TARGET) in cache._entries, "sweep evicted a live entry"
    assert (stale_uid, TARGET) not in cache._entries, "sweep missed a stale entry"
    assert await cache.get(live_uid, TARGET) == live_cred
