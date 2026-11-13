"""Integration tests for ``RedisSharedState`` against a real redis server.

These exercise the same client path an operator's redis, valkey, dragonfly or
keydb instance would, since they all speak the redis protocol. The server is
started by the ``shared_state_url`` fixture; nothing here is mocked.
"""

from __future__ import annotations

import asyncio
import uuid
from typing import TYPE_CHECKING

import pytest

from af_mcp_broker.shared_state import RedisSharedState, SharedStateUnavailableError

if TYPE_CHECKING:
    from collections.abc import AsyncIterator


@pytest.fixture
async def store(shared_state_url: str) -> AsyncIterator[RedisSharedState]:
    backend = RedisSharedState(shared_state_url, key_prefix="")
    yield backend
    await backend.close()


@pytest.fixture
def key() -> str:
    # The server outlives each test, so every test gets its own key.
    return f"test:{uuid.uuid4()}"


async def test_incr_window_counts_and_reports_ttl(
    store: RedisSharedState, key: str
) -> None:
    first = await store.incr_window(key, 60)
    second = await store.incr_window(key, 60)
    assert (first.count, second.count) == (1, 2)
    assert 0 < second.ttl_seconds <= 60


async def test_window_expires(store: RedisSharedState, key: str) -> None:
    await store.incr_window(key, 1)
    await asyncio.sleep(1.2)
    assert await store.get_window(key) is None
    assert (await store.incr_window(key, 1)).count == 1


async def test_get_window_does_not_count(store: RedisSharedState, key: str) -> None:
    assert await store.get_window(key) is None
    await store.incr_window(key, 60)
    window = await store.get_window(key)
    assert window is not None
    assert window.count == 1


async def test_delete_clears_the_counter(store: RedisSharedState, key: str) -> None:
    await store.incr_window(key, 60)
    await store.delete(key)
    assert await store.get_window(key) is None


async def test_two_clients_share_one_counter(shared_state_url: str, key: str) -> None:
    """Two replicas are two clients on one store: their counts add up."""
    replica_a = RedisSharedState(shared_state_url)
    replica_b = RedisSharedState(shared_state_url)
    try:
        await replica_a.incr_window(key, 60)
        assert (await replica_b.incr_window(key, 60)).count == 2
    finally:
        await replica_a.close()
        await replica_b.close()


async def test_concurrent_increments_are_atomic(
    store: RedisSharedState, key: str
) -> None:
    windows = await asyncio.gather(*(store.incr_window(key, 60) for _ in range(50)))
    assert sorted(w.count for w in windows) == list(range(1, 51))


async def test_counter_without_expiry_is_repaired(
    store: RedisSharedState, key: str
) -> None:
    """A key that somehow lost its TTL must not become a permanent lockout."""
    await store._client.set(key, 7)
    window = await store.incr_window(key, 60)
    assert window.count == 8
    assert 0 < window.ttl_seconds <= 60


async def test_prefix_namespaces_keys(shared_state_url: str, key: str) -> None:
    a = RedisSharedState(shared_state_url, key_prefix="a:")
    b = RedisSharedState(shared_state_url, key_prefix="b:")
    try:
        await a.incr_window(key, 60)
        assert await b.get_window(key) is None
    finally:
        await a.close()
        await b.close()


async def test_unreachable_store_raises_unavailable(
    unreachable_shared_state_url: str,
) -> None:
    backend = RedisSharedState(unreachable_shared_state_url)
    try:
        for call in (
            backend.incr_window("k", 60),
            backend.get_window("k"),
            backend.delete("k"),
        ):
            with pytest.raises(SharedStateUnavailableError):
                await call
    finally:
        await backend.close()
