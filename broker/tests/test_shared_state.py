"""Unit tests for the in-memory ``SharedState`` backend and the backend factory."""

from __future__ import annotations

import pytest
import structlog.testing

from af_mcp_broker import shared_state
from af_mcp_broker.shared_state import (
    FallbackSharedState,
    InMemorySharedState,
    RedisSharedState,
    SharedState,
    SharedStateUnavailableError,
    WindowCount,
    build_shared_state,
)


class _Clock:
    """Controllable replacement for ``time.monotonic``."""

    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> _Clock:
    fake = _Clock()
    monkeypatch.setattr(shared_state.time, "monotonic", fake)
    return fake


async def test_incr_window_counts_up_within_a_window(clock: _Clock) -> None:
    store = InMemorySharedState()
    counts = [(await store.incr_window("k", 60)).count for _ in range(3)]
    assert counts == [1, 2, 3]


async def test_window_is_fixed_from_the_first_increment(clock: _Clock) -> None:
    store = InMemorySharedState()
    await store.incr_window("k", 60)
    clock.now += 50
    window = await store.incr_window("k", 60)
    assert window.count == 2
    assert window.ttl_seconds == pytest.approx(10)


async def test_window_resets_after_it_elapses(clock: _Clock) -> None:
    store = InMemorySharedState()
    await store.incr_window("k", 60)
    await store.incr_window("k", 60)
    clock.now += 61
    assert (await store.incr_window("k", 60)).count == 1


async def test_get_window_is_none_when_absent_or_expired(clock: _Clock) -> None:
    store = InMemorySharedState()
    assert await store.get_window("k") is None
    await store.incr_window("k", 60)
    window = await store.get_window("k")
    assert window is not None
    assert window.count == 1
    clock.now += 61
    assert await store.get_window("k") is None


async def test_get_window_does_not_count(clock: _Clock) -> None:
    store = InMemorySharedState()
    await store.incr_window("k", 60)
    await store.get_window("k")
    assert (await store.incr_window("k", 60)).count == 2


async def test_delete_clears_the_counter(clock: _Clock) -> None:
    store = InMemorySharedState()
    await store.incr_window("k", 60)
    await store.delete("k")
    assert await store.get_window("k") is None
    await store.delete("k")  # deleting an absent key is not an error


async def test_keys_are_independent(clock: _Clock) -> None:
    store = InMemorySharedState()
    await store.incr_window("a", 60)
    await store.incr_window("a", 60)
    assert (await store.incr_window("b", 60)).count == 1


def test_build_shared_state_defaults_to_in_memory() -> None:
    assert isinstance(build_shared_state(None), InMemorySharedState)
    assert isinstance(build_shared_state(""), InMemorySharedState)


@pytest.mark.parametrize("url", ["redis://cache:6379/0", "rediss://cache:6380/0"])
def test_build_shared_state_selects_redis_for_redis_urls(url: str) -> None:
    assert isinstance(build_shared_state(url), RedisSharedState)


@pytest.mark.parametrize("url", ["http://cache:6379", "cache:6379", "valkey://x"])
def test_build_shared_state_rejects_other_schemes(url: str) -> None:
    with pytest.raises(ValueError, match="redis://"):
        build_shared_state(url)


class _DownState(SharedState):
    """A store that is always unreachable."""

    async def incr_window(self, key: str, window_seconds: int) -> WindowCount:
        raise SharedStateUnavailableError("down")

    async def get_window(self, key: str) -> WindowCount | None:
        raise SharedStateUnavailableError("down")

    async def delete(self, key: str) -> None:
        raise SharedStateUnavailableError("down")


def _fallback(primary: SharedState) -> FallbackSharedState:
    return FallbackSharedState(primary, component="test", effect="per-replica")


async def test_fallback_delegates_to_a_reachable_primary(clock: _Clock) -> None:
    primary = InMemorySharedState()
    store = _fallback(primary)
    await store.incr_window("k", 60)
    window = await primary.get_window("k")
    assert window is not None
    assert window.count == 1


async def test_fallback_counts_per_replica_and_logs_when_the_primary_is_down(
    clock: _Clock,
) -> None:
    store = _fallback(_DownState())
    with structlog.testing.capture_logs() as logs:
        counts = [(await store.incr_window("k", 60)).count for _ in range(3)]
        window = await store.get_window("k")
    assert counts == [1, 2, 3]
    assert window is not None
    assert window.count == 3
    assert {log["event"] for log in logs} == {"test.shared_state_unavailable"}
    assert {log["effect"] for log in logs} == {"per-replica"}


async def test_fallback_delete_clears_the_per_replica_count_even_when_down(
    clock: _Clock,
) -> None:
    store = _fallback(_DownState())
    await store.incr_window("k", 60)
    await store.delete("k")
    assert await store.get_window("k") is None
