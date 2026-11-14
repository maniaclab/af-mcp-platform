"""Unit tests for ``ListCacheInvalidator`` on the in-memory store.

Two invalidators sharing one ``InMemorySharedState`` stand in for two
replicas. The cross-process behaviour against a real redis server is in
``test_cache_invalidation_redis.py``.
"""

from __future__ import annotations

import asyncio
import json
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING

import pytest
import structlog.testing

from af_mcp_broker.mcp.cache_invalidation import (
    LIST_CACHE_INVALIDATION_CHANNEL,
    ListCacheInvalidator,
)
from af_mcp_broker.shared_state import InMemorySharedState, SharedStateUnavailableError

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable

pytestmark = pytest.mark.usefixtures("unpinned_loggers")


class _Replica:
    """One replica's invalidator plus a record of what it was told to drop."""

    def __init__(self, store: InMemorySharedState) -> None:
        self.dropped: list[tuple[str, str | None]] = []
        self.dropped_all = 0
        self.invalidator = ListCacheInvalidator(
            store,
            invalidate=lambda subject, target: self.dropped.append((subject, target)),
            invalidate_all=self._drop_all,
            retry_delays=(0.01, 0.05),
        )

    def _drop_all(self) -> None:
        self.dropped_all += 1


def _subscriber_count(store: InMemorySharedState) -> int:
    return len(store._subscribers.get(LIST_CACHE_INVALIDATION_CHANNEL, ()))


async def _eventually(condition: Callable[[], bool], timeout: float = 2.0) -> None:
    async with asyncio.timeout(timeout):
        while not condition():
            await asyncio.sleep(0.01)


@pytest.fixture
async def replicas() -> AsyncIterator[tuple[_Replica, _Replica]]:
    store = InMemorySharedState()
    pair = (_Replica(store), _Replica(store))
    for replica in pair:
        replica.invalidator.start()
    # Let each subscriber task reach its subscription.
    await _eventually(lambda: _subscriber_count(store) == 2)
    yield pair
    for replica in pair:
        await replica.invalidator.stop()


async def test_invalidate_drops_the_local_entry_before_any_await(
    replicas: tuple[_Replica, _Replica],
) -> None:
    """The replica that handled the link must not serve the stale entry on the very next request."""
    replica_a, _ = replicas
    replica_a.invalidator.invalidate("alice", "rucio")
    assert replica_a.dropped == [("alice", "rucio")]


async def test_invalidate_reaches_the_other_replica(
    replicas: tuple[_Replica, _Replica],
) -> None:
    replica_a, replica_b = replicas
    replica_a.invalidator.invalidate("alice", "rucio")
    await _eventually(lambda: replica_b.dropped == [("alice", "rucio")])


async def test_a_replica_does_not_reapply_its_own_message(
    replicas: tuple[_Replica, _Replica],
) -> None:
    """Re-dropping would discard the listing refetched right after the link."""
    replica_a, replica_b = replicas
    replica_a.invalidator.invalidate("alice", "rucio")
    await _eventually(lambda: replica_b.dropped == [("alice", "rucio")])
    await asyncio.sleep(0.05)
    assert replica_a.dropped == [("alice", "rucio")]


async def test_a_subject_wide_invalidation_has_no_target(
    replicas: tuple[_Replica, _Replica],
) -> None:
    replica_a, replica_b = replicas
    replica_a.invalidator.invalidate("alice", None)
    await _eventually(lambda: replica_b.dropped == [("alice", None)])


async def test_malformed_messages_are_logged_and_ignored(
    replicas: tuple[_Replica, _Replica],
) -> None:
    store = replicas[0].invalidator._shared_state
    with structlog.testing.capture_logs() as logs:
        for bad in ("not json", json.dumps({"subject": 1}), json.dumps([1])):
            await store.publish(LIST_CACHE_INVALIDATION_CHANNEL, bad)
        replicas[0].invalidator.invalidate("alice", "rucio")
        await _eventually(lambda: replicas[1].dropped == [("alice", "rucio")])

    assert replicas[1].dropped == [("alice", "rucio")]
    bad_events = [
        e for e in logs if e["event"] == "list_cache_invalidation.bad_message"
    ]
    assert len(bad_events) == 6  # two replicas x three bad messages


class _FlakySubscribeStore(InMemorySharedState):
    """Fails the first *failures* subscriptions, then behaves like the in-memory store."""

    def __init__(self, failures: int) -> None:
        super().__init__()
        self.failures = failures
        self.attempts = 0

    @asynccontextmanager
    async def subscribe(self, channel: str) -> AsyncIterator[AsyncIterator[str]]:
        self.attempts += 1
        if self.attempts <= self.failures:
            raise SharedStateUnavailableError("down")
        async with super().subscribe(channel) as messages:
            yield messages


async def test_subscriber_retries_and_drops_every_cache_once_connected() -> None:
    """Messages published while it was not subscribed are gone, so it forgets everything."""
    store = _FlakySubscribeStore(failures=2)
    replica = _Replica(store)
    with structlog.testing.capture_logs() as logs:
        replica.invalidator.start()
        await _eventually(lambda: replica.dropped_all == 1)
        await replica.invalidator.stop()

    assert store.attempts == 3
    unavailable = [
        e
        for e in logs
        if e["event"] == "list_cache_invalidation.shared_state_unavailable"
    ]
    assert len(unavailable) == 2
    assert all("TTL" in e["effect"] for e in unavailable)


async def test_a_clean_first_subscription_does_not_drop_anything() -> None:
    store = InMemorySharedState()
    replica = _Replica(store)
    replica.invalidator.start()
    await _eventually(lambda: _subscriber_count(store) == 1)
    await replica.invalidator.stop()
    assert replica.dropped_all == 0


async def test_stop_unsubscribes() -> None:
    store = InMemorySharedState()
    replica = _Replica(store)
    replica.invalidator.start()
    await _eventually(lambda: _subscriber_count(store) == 1)
    await replica.invalidator.stop()
    assert _subscriber_count(store) == 0


async def test_invalidate_before_start_only_drops_locally() -> None:
    replica = _Replica(InMemorySharedState())
    with structlog.testing.capture_logs() as logs:
        replica.invalidator.invalidate("alice", "rucio")

    assert replica.dropped == [("alice", "rucio")]
    assert [e["event"] for e in logs] == ["list_cache_invalidation.not_broadcast"]


async def test_invalidate_from_another_thread_still_broadcasts(
    replicas: tuple[_Replica, _Replica],
) -> None:
    """The hooks are plain callbacks; the store client must be driven from its own loop."""
    replica_a, replica_b = replicas
    await asyncio.to_thread(replica_a.invalidator.invalidate, "alice", "rucio")
    await _eventually(lambda: replica_b.dropped == [("alice", "rucio")])
