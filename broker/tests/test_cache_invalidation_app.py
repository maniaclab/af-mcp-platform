"""Integration tests: the real broker app wires cache invalidation to the shared store.

The app boots from the shipped YAML with ``SHARED_STATE_URL`` pointing at a
real redis server (see the ``shared_state_url`` fixture). The unlink route is
the real revoke path; the "other replica" is a plain store client.
"""

from __future__ import annotations

import asyncio
import json
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from typing import TYPE_CHECKING, Any

import pytest
from test_identities import _AUTH, ALIAS, _configure_oauth21_env

from af_mcp_broker.app import app as broker_app
from af_mcp_broker.mcp.aggregator import (
    _ObservableProxyProvider,
    _SubjectListCacheEntry,
)
from af_mcp_broker.mcp.cache_invalidation import LIST_CACHE_INVALIDATION_CHANNEL
from af_mcp_broker.shared_state import RedisSharedState

if TYPE_CHECKING:
    from collections.abc import Callable

pytestmark = pytest.mark.usefixtures("unpinned_loggers")


_PUBSUB_TIMEOUT_SECONDS = 5


def _first_provider() -> _ObservableProxyProvider:
    return next(
        p
        for p in broker_app.state.mcp_aggregator.providers
        if isinstance(p, _ObservableProxyProvider)
    )


async def _await_app_subscribed(shared_state_url: str) -> None:
    store = RedisSharedState(shared_state_url)
    try:
        async with asyncio.timeout(_PUBSUB_TIMEOUT_SECONDS):
            while True:
                counts = await store._client.pubsub_numsub(
                    store._prefix + LIST_CACHE_INVALIDATION_CHANNEL
                )
                if counts[0][1] >= 1:
                    return
                await asyncio.sleep(0.02)
    finally:
        await store.close()


def test_app_drops_cached_listings_when_another_replica_publishes(
    monkeypatch: pytest.MonkeyPatch,
    app_client_factory: Callable[..., Any],
    shared_state_url: str,
) -> None:
    monkeypatch.setenv("SHARED_STATE_URL", shared_state_url)
    subject = f"alice-{uuid.uuid4()}"

    async def publish_from_another_replica(service: str) -> None:
        await _await_app_subscribed(shared_state_url)
        other_replica = RedisSharedState(shared_state_url)
        try:
            await other_replica.publish(
                LIST_CACHE_INVALIDATION_CHANNEL,
                json.dumps(
                    {"origin": "another-replica", "subject": subject, "target": service}
                ),
            )
        finally:
            await other_replica.close()

    with app_client_factory():
        provider = _first_provider()
        key = ("tools", subject)
        provider._subject_list_cache[key] = _SubjectListCacheEntry(
            items=[], timestamp=time.monotonic()
        )

        asyncio.run(publish_from_another_replica(provider._service_name))

        deadline = time.monotonic() + _PUBSUB_TIMEOUT_SECONDS
        while key in provider._subject_list_cache and time.monotonic() < deadline:
            time.sleep(0.02)
        assert key not in provider._subject_list_cache


def test_app_publishes_an_unlink_for_other_replicas(
    monkeypatch: pytest.MonkeyPatch,
    app_client_factory: Callable[..., Any],
    shared_state_url: str,
) -> None:
    monkeypatch.setenv("SHARED_STATE_URL", shared_state_url)
    _configure_oauth21_env(monkeypatch)
    subscribed = threading.Event()

    async def other_replica_receives_one_message() -> dict[str, Any]:
        store = RedisSharedState(shared_state_url)
        try:
            async with store.subscribe(LIST_CACHE_INVALIDATION_CHANNEL) as messages:
                subscribed.set()
                raw = await asyncio.wait_for(
                    anext(messages), timeout=_PUBSUB_TIMEOUT_SECONDS
                )
                return json.loads(raw)
        finally:
            await store.close()

    with (
        app_client_factory() as (client, state),
        ThreadPoolExecutor(max_workers=1) as pool,
    ):
        received = pool.submit(asyncio.run, other_replica_receives_one_message())
        assert subscribed.wait(_PUBSUB_TIMEOUT_SECONDS)

        resp = client.delete(f"/v1/identities/link/{ALIAS}", headers=_AUTH)
        assert resp.status_code == 204, resp.text

        message = received.result(timeout=_PUBSUB_TIMEOUT_SECONDS + 1)

    assert message["subject"] == state["principal"].subject
    assert message["target"] is not None
