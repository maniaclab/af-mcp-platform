"""Unit tests for the area ``test_cache_invalidation_redis.py`` covers; the integration tests live in ``integration/test_cache_invalidation_redis.py``."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
import structlog.testing
from cache_invalidation_redis_support import (  # noqa: F401
    _eventually,
    _Replica,
    alice_fixture,
)
from test_mcp_aggregator import (
    _CountingListClient,
    _patch_context,
    _tool,
)

if TYPE_CHECKING:
    from af_mcp_broker.principal import Principal

pytestmark = pytest.mark.usefixtures("unpinned_loggers")


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
