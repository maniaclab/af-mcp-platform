"""Integration tests: link and revoke invalidate listing caches on every replica.

Each "replica" is its own ``ServiceRegistry``, aggregator provider and
``ListCacheInvalidator`` over its own client of one real redis server (see the
``shared_state_url`` fixture); nothing in the store path is mocked. The fake
backend client and request context are the ones ``test_mcp_aggregator.py``
uses for the listing cache itself.
"""

from __future__ import annotations

import asyncio
import uuid
from typing import TYPE_CHECKING

import pytest
import structlog.testing
from conftest import find_available_port, run_redis_server
from fastmcp import FastMCP
from test_mcp_aggregator import _CountingListClient, _patch_context, _spec, _tool

from af_mcp_broker.mcp import aggregator
from af_mcp_broker.mcp.cache_invalidation import ListCacheInvalidator
from af_mcp_broker.mcp.registry import ServiceRegistry
from af_mcp_broker.shared_state import RedisSharedState

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable
    from pathlib import Path

    from af_mcp_broker.identity import Principal

pytestmark = pytest.mark.usefixtures("unpinned_loggers")


class _Replica:
    """One broker replica's listing cache, backend client and invalidator."""

    def __init__(self, store_url: str, client: _CountingListClient) -> None:
        self.client = client
        self.store = RedisSharedState(store_url)
        self.registry = ServiceRegistry()
        self.registry.register(_spec())
        self.provider = aggregator._ObservableProxyProvider(
            "example", lambda: client, registry=self.registry, cache_ttl=300.0
        )
        self.mcp = FastMCP(name="replica")
        self.mcp.add_provider(self.provider)
        self.invalidator = ListCacheInvalidator(
            self.store,
            invalidate=lambda subject, target: aggregator.invalidate_subject_cache(
                self.mcp, subject, target
            ),
            invalidate_all=lambda: aggregator.invalidate_all_subject_caches(self.mcp),
            retry_delays=(0.05, 0.2),
        )

    async def list_tools(self) -> list[str]:
        return [t.name for t in await self.provider._list_tools()]

    async def stop(self) -> None:
        await self.invalidator.stop()
        await self.store.close()


async def _eventually(condition: Callable[[], bool], timeout: float = 5.0) -> None:
    async with asyncio.timeout(timeout):
        while not condition():
            await asyncio.sleep(0.02)


async def _await_subscribed(store_url: str, replicas: list[_Replica]) -> None:
    """Block until every replica's subscriber is registered on the server."""
    probe = RedisSharedState(store_url)
    try:
        async with asyncio.timeout(5):
            while True:
                counts = await probe._client.pubsub_numsub(
                    probe._prefix + "list-cache-invalidation"
                )
                if counts[0][1] >= len(replicas):
                    return
                await asyncio.sleep(0.02)
    finally:
        await probe.close()


@pytest.fixture
def alice(make_principal: Callable[..., Principal]) -> Principal:
    # The server outlives each test, so every test gets its own subject.
    return make_principal(subject=f"alice-{uuid.uuid4()}")


@pytest.fixture
async def replicas(shared_state_url: str) -> AsyncIterator[tuple[_Replica, _Replica]]:
    pair = (
        _Replica(shared_state_url, _CountingListClient(tools=[_tool("widget_old")])),
        _Replica(shared_state_url, _CountingListClient(tools=[_tool("widget_old")])),
    )
    for replica in pair:
        replica.invalidator.start()
    await _await_subscribed(shared_state_url, list(pair))
    yield pair
    for replica in pair:
        await replica.stop()


async def _list_until(replica: _Replica, expected: list[str]) -> None:
    """List on *replica* until it serves *expected* (the invalidation arrived)."""

    async def served() -> bool:
        try:
            return await replica.list_tools() == expected
        except ConnectionError:
            return False  # the cached failure, until the invalidation arrives

    async with asyncio.timeout(5):
        while not await served():
            await asyncio.sleep(0.02)


@pytest.mark.parametrize("target", ["example", None], ids=["one-service", "all"])
async def test_a_link_on_one_replica_refreshes_the_other_replicas_cache(
    replicas: tuple[_Replica, _Replica],
    monkeypatch: pytest.MonkeyPatch,
    alice: Principal,
    target: str | None,
) -> None:
    replica_a, replica_b = replicas
    _patch_context(monkeypatch, alice, active_backend=None)
    assert await replica_b.list_tools() == ["widget_old"]  # cached on B
    replica_b.client.tools = [_tool("widget_new")]

    replica_a.invalidator.invalidate(alice.subject, target)

    await _list_until(replica_b, ["widget_new"])


async def test_a_link_clears_a_cached_failure_on_the_other_replica(
    replicas: tuple[_Replica, _Replica],
    monkeypatch: pytest.MonkeyPatch,
    alice: Principal,
) -> None:
    """The negative entry (30 s) cached before the caller linked is not served after."""
    replica_a, replica_b = replicas
    ctx = _patch_context(monkeypatch, alice, active_backend=None)
    ctx.recorded_state["__list_credential_status__:example"] = (False, "unavailable")
    replica_b.client.error = ConnectionError("refused")
    with pytest.raises(ConnectionError):
        await replica_b.provider._list_tools()
    replica_b.client.error = None
    replica_b.client.tools = [_tool("widget_new")]

    replica_a.invalidator.invalidate(alice.subject, "example")

    await _list_until(replica_b, ["widget_new"])


async def test_other_subjects_stay_cached_on_the_other_replica(
    replicas: tuple[_Replica, _Replica],
    monkeypatch: pytest.MonkeyPatch,
    alice: Principal,
    make_principal: Callable[..., Principal],
) -> None:
    replica_a, replica_b = replicas
    bob = make_principal(subject=f"bob-{uuid.uuid4()}")
    for principal in (alice, bob):
        _patch_context(monkeypatch, principal, active_backend=None)
        await replica_b.list_tools()
    assert replica_b.client.call_count == 2
    replica_b.client.tools = [_tool("widget_new")]

    replica_a.invalidator.invalidate(alice.subject, "example")
    _patch_context(monkeypatch, alice, active_backend=None)
    await _list_until(replica_b, ["widget_new"])
    assert replica_b.client.call_count == 3  # only alice was refetched

    _patch_context(monkeypatch, bob, active_backend=None)
    assert await replica_b.list_tools() == ["widget_old"]  # bob's entry is untouched


async def test_store_down_keeps_the_local_drop_and_logs_the_broadcast_failure(
    unreachable_shared_state_url: str,
    monkeypatch: pytest.MonkeyPatch,
    alice: Principal,
) -> None:
    replica = _Replica(
        unreachable_shared_state_url, _CountingListClient(tools=[_tool("widget_old")])
    )
    _patch_context(monkeypatch, alice, active_backend=None)
    await replica.list_tools()
    replica.client.tools = [_tool("widget_new")]
    try:
        with structlog.testing.capture_logs() as logs:
            replica.invalidator.start()
            replica.invalidator.invalidate(alice.subject, "example")
            assert await replica.list_tools() == [
                "widget_new"
            ]  # local drop is immediate
            await _eventually(
                lambda: any(
                    e.get("subject") == alice.subject
                    and e["event"] == "list_cache_invalidation.shared_state_unavailable"
                    for e in logs
                )
            )
    finally:
        await replica.stop()

    events = [e for e in logs if e["event"].startswith("list_cache_invalidation.")]
    assert {e["log_level"] for e in events} == {"warning"}


async def test_store_down_leaves_other_replicas_on_ttl_staleness(
    shared_state_url: str,
    unreachable_shared_state_url: str,
    monkeypatch: pytest.MonkeyPatch,
    alice: Principal,
) -> None:
    """With no store the broadcast cannot arrive; the other replica is no worse off than before this feature."""
    reachable = _Replica(
        shared_state_url, _CountingListClient(tools=[_tool("widget_old")])
    )
    cut_off = _Replica(
        unreachable_shared_state_url, _CountingListClient(tools=[_tool("widget_old")])
    )
    _patch_context(monkeypatch, alice, active_backend=None)
    await reachable.list_tools()
    reachable.client.tools = [_tool("widget_new")]
    try:
        reachable.invalidator.start()
        cut_off.invalidator.start()
        await _await_subscribed(shared_state_url, [reachable])
        cut_off.invalidator.invalidate(alice.subject, "example")
        await asyncio.sleep(0.5)
        assert await reachable.list_tools() == ["widget_old"]  # still the cached entry
    finally:
        await reachable.stop()
        await cut_off.stop()


async def test_resubscribing_after_a_store_restart_drops_every_cached_listing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    alice: Principal,
) -> None:
    """Messages sent while the store was down are lost, so recovery forgets everything cached."""
    port = find_available_port()
    client = _CountingListClient(tools=[_tool("widget_old")])
    with run_redis_server(tmp_path, port) as url:
        replica = _Replica(url, client)
        _patch_context(monkeypatch, alice, active_backend=None)
        await replica.list_tools()
        replica.invalidator.start()
        await _await_subscribed(url, [replica])
    client.tools = [_tool("widget_new")]

    try:
        with structlog.testing.capture_logs() as logs:
            # The server is gone: the subscription fails and is retried.
            await _eventually(
                lambda: any(
                    e["event"] == "list_cache_invalidation.shared_state_unavailable"
                    for e in logs
                )
            )
            assert await replica.list_tools() == [
                "widget_old"
            ]  # TTL staleness meanwhile

            with run_redis_server(tmp_path, port) as url:
                await _eventually(
                    lambda: any(
                        e["event"] == "list_cache_invalidation.resubscribed"
                        for e in logs
                    )
                )
                assert await replica.list_tools() == ["widget_new"]
    finally:
        await replica.stop()
