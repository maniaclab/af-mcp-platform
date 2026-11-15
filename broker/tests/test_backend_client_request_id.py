"""Backend HTTP clients send the broker's correlation id as ``X-Request-ID``."""

from __future__ import annotations

import httpx2
import structlog

from af_mcp_broker.backend_client import _checked_httpx_client_factory
from af_mcp_broker.logging import bind_new_correlation_id


async def _sent_headers(headers: dict[str, str] | None = None) -> httpx2.Headers:
    seen: list[httpx2.Headers] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        seen.append(request.headers)
        return httpx2.Response(200, json={})

    client = _checked_httpx_client_factory("svc")(
        headers=headers, transport=httpx2.MockTransport(handler)
    )
    async with client:
        await client.get("http://backend.invalid/mcp")
    return seen[0]


async def test_request_carries_the_current_correlation_id() -> None:
    bind_new_correlation_id()

    headers = await _sent_headers()

    correlation_id = structlog.contextvars.get_contextvars()["correlation_id"]
    assert headers["x-request-id"] == correlation_id


async def test_a_request_id_already_on_the_client_is_replaced() -> None:
    bind_new_correlation_id()

    headers = await _sent_headers({"X-Request-ID": "chosen-by-the-caller"})

    correlation_id = structlog.contextvars.get_contextvars()["correlation_id"]
    assert headers.get_list("x-request-id") == [correlation_id]


async def test_no_request_id_is_sent_outside_a_request() -> None:
    structlog.contextvars.clear_contextvars()

    headers = await _sent_headers()

    assert "x-request-id" not in headers
