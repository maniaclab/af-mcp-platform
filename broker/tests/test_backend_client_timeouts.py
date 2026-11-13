"""The backend client ``_build_client`` returns is bounded by ``ServiceSpec.timeout_seconds`` on connect and initialize, not only on later requests (issue #386).

The suite-wide ``_bound_client_timeouts`` fixture defaults ``init_timeout`` and
``timeout`` on every ``fastmcp.Client``; it is disabled here so only the
production bounds are in effect.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

import pytest
from conftest import run_inprocess_asgi_app

from af_mcp_broker.mcp.aggregator import _build_client
from af_mcp_broker.mcp.registry import ServiceSpec

_SERVICE_TIMEOUT_SECONDS = 1.0
# Well past the service timeout, far below the unbounded keep-alive case, so a regression fails by deadline rather than by
# hanging the suite.
_MAX_CONNECT_SECONDS = 5.0


@pytest.fixture(autouse=True)
def _bound_client_timeouts() -> None:
    """Override the suite-wide Client timeout defaults with nothing."""


async def keepalive_only_backend(scope: Any, receive: Any, send: Any) -> None:
    """ASGI app that answers every request with an event stream carrying only keep-alive comments, never a JSON-RPC reply."""
    if scope["type"] == "lifespan":
        # run_asgi_lifespan (the in-process harness) requires the handshake.
        while True:
            message = await receive()
            if message["type"] == "lifespan.startup":
                await send({"type": "lifespan.startup.complete"})
            else:
                await send({"type": "lifespan.shutdown.complete"})
                return
    if scope["type"] != "http":
        return
    await send(
        {
            "type": "http.response.start",
            "status": 200,
            "headers": [(b"content-type", b"text/event-stream")],
        }
    )
    while True:
        await send(
            {"type": "http.response.body", "body": b": ping\n\n", "more_body": True}
        )
        try:
            message = await asyncio.wait_for(receive(), timeout=0.2)
        except TimeoutError:
            continue
        if message["type"] == "http.disconnect":
            return


def _spec(url: str) -> ServiceSpec:
    return ServiceSpec(
        name="stalled",
        prefix="stalled",
        url=url,
        transport="http",
        required_permission="__none__",
        auth_type="none",
        timeout_seconds=_SERVICE_TIMEOUT_SECONDS,
    )


async def _seconds_to_fail_connecting(app: Any) -> float:
    async with run_inprocess_asgi_app(app) as base_url:
        client = _build_client(_spec(f"{base_url}/mcp"))
        started = time.monotonic()
        try:
            async with asyncio.timeout(_MAX_CONNECT_SECONDS):
                await client.__aenter__()
        except Exception:  # noqa: BLE001
            # Which exception is irrelevant; only how long it took.
            return time.monotonic() - started
        pytest.fail("connected to a backend that never answers")


async def test_http_backend_that_only_sends_keepalives_fails_within_service_timeout() -> (
    None
):
    elapsed = await _seconds_to_fail_connecting(keepalive_only_backend)

    assert elapsed < 2 * _SERVICE_TIMEOUT_SECONDS + 1
