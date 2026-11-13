"""Regression tests for the in-process test harness.

CI runs used to hang silently (until the 6-hour Actions job timeout) on the
real-socket harness: a uvicorn server task that failed to start (the
``find_available_port`` TOCTOU race), and an MCP client whose connection died
mid-flight or went dead-but-open (modelcontextprotocol/python-sdk#1144), which
a ``ClientSession`` patch used to bound. Servers now run through fastmcp's
``asgi_server`` and the aggregator's backends through an in-process transport,
so there is no port to lose and no connection to leave dead. These tests pin
the two failure modes that remain expressible in-process -- a transport that
dies mid-response, and a server that never answers -- and assert the client
fails promptly instead of hanging. The ``timeout`` marks keep a regression
from wedging this very file.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Self

import anyio
import httpx2
import pytest
from conftest import HungBackend

# Import from conftest at module level ONLY: pytest imports every collected
# conftest.py under the bare name "conftest", and the CI invocation
# (`pytest broker/ spikes/`) collects spikes/credential-isolation/conftest.py
# AFTER this module is imported -- replacing sys.modules["conftest"]. A
# module-level import here binds broker's conftest at collection time (like
# every other test file); a function-level `from conftest import ...` would
# resolve at test time and get the spikes one.
from fastmcp import Client, FastMCP
from fastmcp.client.transports import StreamableHttpTransport
from fastmcp.exceptions import McpError
from fastmcp.utilities.asgi_transport import run_asgi_lifespan
from fastmcp.utilities.tests import ASGIServer, asgi_server

if TYPE_CHECKING:
    from collections.abc import AsyncIterator


class _DiesMidBody(httpx2.AsyncByteStream):
    """A response body that delivers one SSE line, then fails like a reset connection."""

    async def __aiter__(self) -> AsyncIterator[bytes]:
        yield b"event: message\n"
        raise httpx2.ReadError("connection died mid-body")


class _DiesOnToolCall(httpx2.AsyncBaseTransport):
    """Wraps an in-process transport, answering ``tools/call`` with a body that dies mid-stream."""

    def __init__(self, inner: httpx2.AsyncBaseTransport) -> None:
        self._inner = inner

    async def __aenter__(self) -> Self:
        await self._inner.__aenter__()
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self._inner.__aexit__(*exc_info)

    async def handle_async_request(self, request: httpx2.Request) -> httpx2.Response:
        if b"tools/call" not in request.content:
            return await self._inner.handle_async_request(request)
        return httpx2.Response(
            200,
            headers={"content-type": "text/event-stream"},
            stream=_DiesMidBody(),
            request=request,
        )


@pytest.mark.timeout(30)
async def test_transport_dying_mid_response_fails_pending_request_instead_of_hanging() -> (
    None
):
    """A response body that dies mid-stream (the transport exception python-sdk#1144 hung on) must fail the pending request promptly."""
    mcp = FastMCP("dies-mid-response")

    @mcp.tool
    def ping() -> str:
        return "pong"

    async with asgi_server(mcp) as server:

        def factory(**kwargs: object) -> httpx2.AsyncClient:
            client = server.http_client(**kwargs)  # type: ignore[arg-type]
            client._transport = _DiesOnToolCall(client._transport)
            return client

        async with Client(
            StreamableHttpTransport(server.url, httpx_client_factory=factory)
        ) as client:
            with anyio.fail_after(10), pytest.raises(McpError):
                await client.call_tool("ping", {})


@pytest.mark.timeout(30)
async def test_server_that_never_answers_times_out_instead_of_hanging() -> None:
    """A server that reads a request and never replies (the dead-but-open connection behind the CI hang observed on #237) must fail at the client's timeout rather than wait forever."""
    hung = HungBackend()
    async with run_asgi_lifespan(hung):
        server = ASGIServer(url="http://127.0.0.1/mcp", app=hung, transport_type="http")
        # fastmcp's Client has no default init timeout: without init_timeout
        # this client waits on the never-sent initialize reply forever (only
        # pytest-timeout would end it), exactly the hang the removed
        # ClientSession read-timeout patch used to bound.
        with anyio.fail_after(10), pytest.raises(RuntimeError, match="connect"):
            async with server.client(init_timeout=0.5) as client:
                await client.ping()
    assert hung.requests >= 1
