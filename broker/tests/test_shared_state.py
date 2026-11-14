"""Unit tests for the in-memory ``SharedState`` backend and the backend factory."""

from __future__ import annotations

import asyncio

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

    async def get(self, key: str) -> str | None:
        raise SharedStateUnavailableError("down")

    async def set(self, key: str, value: str, ttl_seconds: float) -> None:
        raise SharedStateUnavailableError("down")

    async def publish(self, channel: str, message: str) -> None:
        raise SharedStateUnavailableError("down")

    def subscribe(self, channel: str):
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


# --- publish / subscribe -----------------------------------------------------


async def _next_message(messages) -> str:
    return await asyncio.wait_for(anext(messages), timeout=2)


async def test_publish_reaches_every_subscriber_on_the_channel() -> None:
    store = InMemorySharedState()
    async with store.subscribe("c") as first, store.subscribe("c") as second:
        await store.publish("c", "hello")
        assert await _next_message(first) == "hello"
        assert await _next_message(second) == "hello"


async def test_subscriber_only_sees_its_own_channel() -> None:
    store = InMemorySharedState()
    async with store.subscribe("wanted") as messages:
        await store.publish("other", "ignored")
        await store.publish("wanted", "kept")
        assert await _next_message(messages) == "kept"


async def test_messages_arrive_in_publish_order() -> None:
    store = InMemorySharedState()
    async with store.subscribe("c") as messages:
        for text in ("1", "2", "3"):
            await store.publish("c", text)
        assert [await _next_message(messages) for _ in range(3)] == ["1", "2", "3"]


async def test_subscriber_misses_messages_published_before_it_subscribed() -> None:
    store = InMemorySharedState()
    await store.publish("c", "early")
    async with store.subscribe("c") as messages:
        await store.publish("c", "late")
        assert await _next_message(messages) == "late"


async def test_publish_after_unsubscribing_is_a_noop() -> None:
    store = InMemorySharedState()
    async with store.subscribe("c"):
        pass
    await store.publish("c", "nobody-listening")
    assert not store._subscribers["c"]


async def test_fallback_delegates_pubsub_to_the_primary() -> None:
    primary = InMemorySharedState()
    store = FallbackSharedState(primary, component="test", effect="degraded")
    async with store.subscribe("c") as messages:
        await primary.publish("c", "via-primary")
        assert await _next_message(messages) == "via-primary"
        await store.publish("c", "via-fallback-wrapper")
        assert await _next_message(messages) == "via-fallback-wrapper"


# --- get / set with TTL --------------------------------------------------------


async def test_set_then_get_round_trips(clock: _Clock) -> None:
    store = InMemorySharedState()
    await store.set("k", "v", 60)
    assert await store.get("k") == "v"


async def test_get_of_an_absent_key_is_none(clock: _Clock) -> None:
    assert await InMemorySharedState().get("k") is None


async def test_set_overwrites_and_restarts_the_ttl(clock: _Clock) -> None:
    store = InMemorySharedState()
    await store.set("k", "old", 60)
    clock.now += 50
    await store.set("k", "new", 60)
    clock.now += 50
    assert await store.get("k") == "new"


async def test_value_expires_after_its_ttl(clock: _Clock) -> None:
    store = InMemorySharedState()
    await store.set("k", "v", 60)
    clock.now += 61
    assert await store.get("k") is None


async def test_delete_clears_a_value(clock: _Clock) -> None:
    store = InMemorySharedState()
    await store.set("k", "v", 60)
    await store.delete("k")
    assert await store.get("k") is None


async def test_fallback_keeps_values_per_replica_and_logs_when_the_primary_is_down(
    clock: _Clock,
) -> None:
    store = _fallback(_DownState())
    with structlog.testing.capture_logs() as logs:
        await store.set("k", "v", 60)
        assert await store.get("k") == "v"
    assert [e["event"] for e in logs] == ["test.shared_state_unavailable"] * 2


async def test_fallback_delegates_values_to_a_reachable_primary(clock: _Clock) -> None:
    primary = InMemorySharedState()
    store = _fallback(primary)
    await store.set("k", "v", 60)
    assert await primary.get("k") == "v"
    assert await store.get("k") == "v"
