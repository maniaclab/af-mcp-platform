"""Tests for CachingMaintenanceModeStore -- the TTL cache in front of a store's get()."""

from __future__ import annotations

import asyncio

import pytest

from af_mcp_broker.config import Settings
from af_mcp_broker.maintenance import (
    CachingMaintenanceModeStore,
    InMemoryMaintenanceModeStore,
    MaintenanceState,
)

_ON = MaintenanceState(enabled=True, reason="r", enabled_by="x", enabled_at=1.0)
_OFF = MaintenanceState(enabled=False, reason=None, enabled_by=None, enabled_at=None)


class _CountingStore(InMemoryMaintenanceModeStore):
    """A real in-memory store that counts ``get()`` calls and can fail or stall on demand."""

    def __init__(self) -> None:
        super().__init__()
        self.gets = 0
        self.fail: Exception | None = None
        self.gate: asyncio.Event | None = None

    async def get(self) -> MaintenanceState:
        self.gets += 1
        if self.gate is not None:
            await self.gate.wait()
        if self.fail is not None:
            raise self.fail
        return await super().get()


class _Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def inner() -> _CountingStore:
    return _CountingStore()


@pytest.fixture
def clock() -> _Clock:
    return _Clock()


def _cache(
    inner: _CountingStore, clock: _Clock, ttl: float = 5.0
) -> CachingMaintenanceModeStore:
    return CachingMaintenanceModeStore(inner, ttl_seconds=ttl, clock=clock)


async def test_hits_within_ttl_do_not_query(inner: _CountingStore, clock: _Clock):
    cache = _cache(inner, clock)
    for _ in range(3):
        assert await cache.get() == _OFF
        clock.now += 1.0
    assert inner.gets == 1


async def test_expiry_refetches(inner: _CountingStore, clock: _Clock):
    cache = _cache(inner, clock)
    assert await cache.get() == _OFF
    await inner.set(_ON)  # another replica's write, invisible to this cache
    clock.now += 4.9
    assert await cache.get() == _OFF
    clock.now += 0.2
    assert await cache.get() == _ON
    assert inner.gets == 2


async def test_own_write_invalidates_immediately(inner: _CountingStore, clock: _Clock):
    cache = _cache(inner, clock)
    assert await cache.get() == _OFF
    await cache.set(_ON)
    assert await cache.get() == _ON
    await cache.set(_OFF)
    assert await cache.get() == _OFF


async def test_ttl_zero_queries_every_time(inner: _CountingStore, clock: _Clock):
    cache = _cache(inner, clock, ttl=0)
    for _ in range(3):
        await cache.get()
    assert inner.gets == 3


async def test_errors_propagate_and_are_not_cached(
    inner: _CountingStore, clock: _Clock
):
    cache = _cache(inner, clock)
    inner.fail = RuntimeError("store down")
    with pytest.raises(RuntimeError, match="store down"):
        await cache.get()
    inner.fail = None
    assert await cache.get() == _OFF
    assert inner.gets == 2


async def test_expired_entry_is_not_served_when_store_fails(
    inner: _CountingStore, clock: _Clock
):
    cache = _cache(inner, clock)
    await cache.get()
    clock.now += 6.0
    inner.fail = RuntimeError("store down")
    with pytest.raises(RuntimeError, match="store down"):
        await cache.get()


async def test_concurrent_misses_share_one_fetch(inner: _CountingStore, clock: _Clock):
    cache = _cache(inner, clock)
    inner.gate = asyncio.Event()
    tasks = [asyncio.create_task(cache.get()) for _ in range(10)]
    await asyncio.sleep(0)
    await asyncio.sleep(0)
    inner.gate.set()
    assert await asyncio.gather(*tasks) == [_OFF] * 10
    assert inner.gets == 1


async def test_concurrent_misses_share_one_failure(
    inner: _CountingStore, clock: _Clock
):
    cache = _cache(inner, clock)
    inner.gate = asyncio.Event()
    inner.fail = RuntimeError("store down")
    tasks = [asyncio.create_task(cache.get()) for _ in range(5)]
    await asyncio.sleep(0)
    await asyncio.sleep(0)
    inner.gate.set()
    results = await asyncio.gather(*tasks, return_exceptions=True)
    assert all(isinstance(r, RuntimeError) for r in results)
    assert inner.gets == 1


async def test_write_during_inflight_fetch_is_not_overwritten_by_stale_read(
    inner: _CountingStore, clock: _Clock
):
    cache = _cache(inner, clock)
    inner.gate = asyncio.Event()
    reader = asyncio.create_task(cache.get())
    await asyncio.sleep(0)
    await asyncio.sleep(0)
    # The fetch has read nothing yet-visible to the write; the write lands while it is in flight.
    await cache.set(_ON)
    inner.gate.set()
    await reader
    inner.gate = None
    assert await cache.get() == _ON


async def test_start_and_aclose_delegate(clock: _Clock):
    calls: list[str] = []

    class _Recording(InMemoryMaintenanceModeStore):
        async def start(self) -> None:
            calls.append("start")

        async def aclose(self) -> None:
            calls.append("aclose")

    cache = CachingMaintenanceModeStore(_Recording(), ttl_seconds=5.0, clock=clock)
    await cache.start()
    await cache.aclose()
    assert calls == ["start", "aclose"]


def test_ttl_setting_defaults_to_five_and_rejects_negative():
    assert Settings().maintenance_mode_cache_ttl_seconds == 5.0
    with pytest.raises(ValueError, match="maintenance_mode_cache_ttl_seconds"):
        Settings(maintenance_mode_cache_ttl_seconds=-1)
