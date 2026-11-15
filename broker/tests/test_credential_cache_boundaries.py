"""Boundary tests for ``CredentialCache`` expiry and the unlock lockout.

Pins the exact comparison operators and defaults: the Nth failed unlock is
tolerated and the (N+1)th is refused ("5 failures / 15 min" in
docs/architecture.md), a cached value is served while its remaining lifetime
is at least ``min_remaining``, and the janitor drops an entry at the instant
its ``expires_at`` is reached. Unit tests only; no app, Redis or Vault.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from af_mcp_broker.credentials import cache as cache_module
from af_mcp_broker.credentials.cache import CredentialCache, ProxyMeta
from af_mcp_broker.credentials.errors import UnlockRateLimitError
from af_mcp_broker.shared_state import InMemorySharedState, WindowCount

NOW = 1_000_000.0
SUBJECT = "user-1"
TARGET = "rucio"
UID = 4242


class ScriptedWindowState(InMemorySharedState):
    """In-memory store whose failed-unlock window is a fixed WindowCount."""

    def __init__(self, window: WindowCount | None) -> None:
        super().__init__()
        self.window = window
        self.incr_calls: list[tuple[str, int]] = []

    async def incr_window(self, key: str, window_seconds: int) -> WindowCount:
        self.incr_calls.append((key, window_seconds))
        assert self.window is not None
        return self.window

    async def get_window(self, key: str) -> WindowCount | None:
        return self.window


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    """Controllable wall clock for ``cache.time.time()``."""
    state = SimpleNamespace(now=NOW)
    monkeypatch.setattr(cache_module, "time", SimpleNamespace(time=lambda: state.now))
    return state


class TestDefaults:
    async def test_default_limit_is_five_failures(self):
        cache = CredentialCache()
        for _ in range(5):
            await cache.record_failed_unlock(UID)
        with pytest.raises(UnlockRateLimitError):
            await cache.record_failed_unlock(UID)

    async def test_default_window_is_fifteen_minutes(self):
        state = ScriptedWindowState(WindowCount(count=1, ttl_seconds=900))
        cache = CredentialCache(shared_state=state)
        await cache.record_failed_unlock(UID)
        assert state.incr_calls == [(f"unlock-failures:{UID}", 900)]

    async def test_configured_window_is_passed_to_the_store(self):
        state = ScriptedWindowState(WindowCount(count=1, ttl_seconds=60))
        cache = CredentialCache(unlock_window_seconds=60, shared_state=state)
        await cache.record_failed_unlock(UID)
        assert state.incr_calls == [(f"unlock-failures:{UID}", 60)]


class TestUnlockLockoutBoundary:
    @pytest.mark.parametrize("limit", [1, 3, 5])
    async def test_limit_failures_tolerated_next_one_refused(self, limit: int):
        cache = CredentialCache(max_failed_unlocks=limit)
        for _ in range(limit):
            await cache.record_failed_unlock(UID)
            await cache.check_unlock_rate_limit(UID)  # still allowed
        with pytest.raises(UnlockRateLimitError):
            await cache.record_failed_unlock(UID)
        with pytest.raises(UnlockRateLimitError):
            await cache.check_unlock_rate_limit(UID)

    async def test_check_passes_at_exactly_the_limit(self):
        state = ScriptedWindowState(WindowCount(count=3, ttl_seconds=100))
        cache = CredentialCache(max_failed_unlocks=3, shared_state=state)
        await cache.check_unlock_rate_limit(UID)

    async def test_check_refuses_one_past_the_limit(self):
        state = ScriptedWindowState(WindowCount(count=4, ttl_seconds=100))
        cache = CredentialCache(max_failed_unlocks=3, shared_state=state)
        with pytest.raises(UnlockRateLimitError):
            await cache.check_unlock_rate_limit(UID)

    async def test_check_passes_with_no_open_window(self):
        await CredentialCache(max_failed_unlocks=1).check_unlock_rate_limit(UID)

    async def test_counters_are_per_uid(self):
        cache = CredentialCache(max_failed_unlocks=1)
        await cache.record_failed_unlock(1)
        await cache.record_failed_unlock(2)
        await cache.check_unlock_rate_limit(1)
        await cache.check_unlock_rate_limit(2)


class TestRetryAfter:
    @pytest.mark.parametrize(
        ("ttl_seconds", "expected"),
        [(42.9, 42), (1.0, 1), (0.0, 0), (-3.5, 0)],
    )
    @pytest.mark.parametrize("entry_point", ["record", "check"])
    async def test_retry_after_is_truncated_and_never_negative(
        self, entry_point: str, ttl_seconds: float, expected: int
    ):
        state = ScriptedWindowState(WindowCount(count=2, ttl_seconds=ttl_seconds))
        cache = CredentialCache(max_failed_unlocks=1, shared_state=state)
        call = (
            cache.record_failed_unlock
            if entry_point == "record"
            else cache.check_unlock_rate_limit
        )
        with pytest.raises(UnlockRateLimitError) as excinfo:
            await call(UID)
        assert excinfo.value.retry_after_seconds == expected
        assert f"Try again in {expected}s." in str(excinfo.value)


class TestPutResetsFailedUnlocks:
    async def test_put_with_uid_clears_the_counter(self):
        cache = CredentialCache(max_failed_unlocks=1)
        await cache.record_failed_unlock(UID)
        await cache.put(SUBJECT, TARGET, "cred", uid=UID)
        await cache.record_failed_unlock(UID)  # back to a fresh budget

    async def test_put_without_uid_keeps_the_counter(self):
        cache = CredentialCache(max_failed_unlocks=1)
        await cache.record_failed_unlock(UID)
        await cache.put(SUBJECT, TARGET, "cred")
        with pytest.raises(UnlockRateLimitError):
            await cache.record_failed_unlock(UID)


class TestEntryFreshness:
    async def test_remaining_seconds_is_expiry_minus_now(self, clock):
        cache = CredentialCache()
        await cache.put(SUBJECT, TARGET, "cred", expires_at=NOW + 100)
        entry = cache._entries[(SUBJECT, TARGET)]
        assert cache.remaining_seconds(entry) == pytest.approx(100.0)

    async def test_put_defaults_to_one_hour(self, clock):
        cache = CredentialCache()
        await cache.put(SUBJECT, TARGET, "cred")
        assert cache._entries[(SUBJECT, TARGET)].expires_at == NOW + 3600

    async def test_get_serves_value_with_exactly_min_remaining_left(self, clock):
        cache = CredentialCache()
        await cache.put(SUBJECT, TARGET, "cred", expires_at=NOW + 300)
        assert await cache.get(SUBJECT, TARGET, min_remaining=300) == "cred"

    async def test_get_misses_just_under_min_remaining(self, clock):
        cache = CredentialCache()
        await cache.put(SUBJECT, TARGET, "cred", expires_at=NOW + 299.5)
        assert await cache.get(SUBJECT, TARGET, min_remaining=300) is None

    async def test_get_default_min_remaining_is_five_minutes(self, clock):
        cache = CredentialCache()
        await cache.put(SUBJECT, TARGET, "fresh", expires_at=NOW + 300)
        await cache.put(SUBJECT, "stale", "stale", expires_at=NOW + 299)
        assert await cache.get(SUBJECT, TARGET) == "fresh"
        assert await cache.get(SUBJECT, "stale") is None

    async def test_peek_default_serves_until_the_expiry_instant(self, clock):
        cache = CredentialCache()
        await cache.put(SUBJECT, TARGET, "cred", expires_at=NOW)
        assert await cache.peek(SUBJECT, TARGET) == "cred"
        clock.now = NOW + 0.5
        assert await cache.peek(SUBJECT, TARGET) is None

    async def test_get_or_mint_rechecks_with_the_same_min_remaining(self, clock):
        cache = CredentialCache()
        await cache.put(SUBJECT, TARGET, "cached", expires_at=NOW + 100)

        async def mint() -> str:
            return "minted"

        assert await cache.get_or_mint(SUBJECT, TARGET, 100, mint) == "cached"
        assert await cache.get_or_mint(SUBJECT, TARGET, 101, mint) == "minted"


class TestSweep:
    async def test_entry_is_dropped_at_its_expiry_instant(self, clock):
        cache = CredentialCache()
        await cache.put(SUBJECT, "at-expiry", "a", expires_at=NOW)
        await cache.put(SUBJECT, "later", "b", expires_at=NOW + 0.5)
        await cache.sweep_expired()
        assert set(cache._entries) == {(SUBJECT, "later")}

    async def test_sweep_does_not_fire_the_revoke_hook(self, clock):
        revoked: list[tuple[str, str]] = []
        cache = CredentialCache(on_revoke=lambda s, t: revoked.append((s, t)))
        await cache.put(SUBJECT, TARGET, "a", expires_at=NOW - 1)
        await cache.sweep_expired()
        assert cache._entries == {}
        assert revoked == []

    async def test_janitor_sweeps_every_sixty_seconds(
        self, monkeypatch: pytest.MonkeyPatch
    ):
        cache = CredentialCache()
        sleeps: list[float] = []
        sweeps = 0

        async def fake_sleep(seconds: float) -> None:
            sleeps.append(seconds)
            if len(sleeps) > 2:
                raise asyncio.CancelledError

        async def fake_sweep() -> None:
            nonlocal sweeps
            sweeps += 1

        monkeypatch.setattr(cache_module.asyncio, "sleep", fake_sleep)
        monkeypatch.setattr(cache, "_sweep_expired", fake_sweep)
        with pytest.raises(asyncio.CancelledError):
            await cache._janitor_loop()
        assert sleeps == [60, 60, 60]
        assert sweeps == 2


class TestRevoke:
    async def test_revoke_all_only_touches_the_subject(self):
        revoked: list[tuple[str, str]] = []
        cache = CredentialCache(on_revoke=lambda s, t: revoked.append((s, t)))
        await cache.put(SUBJECT, "a", 1)
        await cache.put(SUBJECT, "b", 2)
        await cache.put("other", "a", 3)
        await cache.revoke_all(SUBJECT)
        assert set(cache._entries) == {("other", "a")}
        assert sorted(revoked) == [(SUBJECT, "a"), (SUBJECT, "b")]

    async def test_get_proxy_meta_is_per_subject_and_target(self):
        meta = ProxyMeta(dn="/dn", voms_attributes=["/atlas"], not_after=NOW)
        cache = CredentialCache()
        await cache.put(SUBJECT, TARGET, "cred", proxy_meta=meta)
        assert cache.get_proxy_meta(SUBJECT, TARGET) is meta
        assert cache.get_proxy_meta(SUBJECT, "other") is None
        assert cache.get_proxy_meta("other", TARGET) is None
