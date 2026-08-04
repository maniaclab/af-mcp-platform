from __future__ import annotations

import asyncio
import time
from typing import Any

import mcp.types as mt
import pytest
from conftest import make_claims
from fastmcp import Client, FastMCP
from fastmcp.client.transports import StreamableHttpTransport
from fastmcp.exceptions import ToolError
from fastmcp.server.providers.proxy import ProxyTool
from fastmcp.utilities.http import find_available_port
from fastmcp.utilities.tests import run_server_async

from af_mcp_broker.authorization import EntitlementPolicy
from af_mcp_broker.credentials import CredentialRegistry
from af_mcp_broker.mcp.aggregator import _make_client_factory, build_aggregator
from af_mcp_broker.mcp.registry import BackendRegistry, BackendSpec

# ---------------------------------------------------------------------------
# Call-time upstream-failure mapping.
#
# tools/list already tolerates a dead backend (provider_error_strategy
# defaults to "warn", covered by PR A's
# test_mcp_aggregator_integration.py::test_entitled_principal_sees_namespaced_...).
# This file is about what happens once a tool *is* known (its schema was
# already listed/cached while the backend was reachable) and a later
# tools/call finds the backend down, or the backend's own tool raises an
# application-level error.
#
# Investigation finding (see aggregator.py's _make_client_factory and
# fastmcp/server/server.py's call_tool): fastmcp's own core call_tool logic
# already converts any exception a Tool.run() raises into a ToolError
# (mask_error_details defaults to False, so the original detail is kept,
# never a raw traceback) before it reaches a caller. AuthorizationMiddleware
# (mcp/middleware/authorization_mw.py) deliberately re-raises whatever
# call_next() raises *unchanged* -- test_mcp_middleware_authorization.py's
# test_call_next_failure_audited_as_error_and_reraised already locks that
# contract in, auditing the failure without rewrapping it. So the clean,
# non-traceback surfacing this file asserts is existing fastmcp/aggregator
# behavior; these are regression tests for it, not new production code.
# ---------------------------------------------------------------------------


async def test_dead_backend_call_surfaces_as_clean_tool_error_not_a_traceback(
    settings: Any,
) -> None:
    """A backend that is DOWN (connection refused) when a known tool is
    actually called must raise a ToolError identifying the tool/backend --
    never leak a raw httpx/anyio exception or a Python traceback to the
    caller. The tool is registered directly (bypassing a live tools/list)
    because ProxyProvider's tools/list is exactly what "warn"-tolerates a
    dead backend by never listing its tools in the first place; this
    reproduces the case where the schema was already cached while the
    backend was up and it has since gone down."""
    dead_url = f"http://127.0.0.1:{find_available_port()}/mcp"
    spec = BackendSpec(
        name="dead",
        prefix="dead",
        url=dead_url,
        transport="http",
        required_capability="__none__",
        auth_type="none",
    )
    factory = _make_client_factory(spec, CredentialRegistry([]), settings)
    mcp_tool = mt.Tool(
        name="dead_echo", inputSchema={"type": "object", "properties": {}}
    )
    proxy_tool = ProxyTool.from_mcp_tool(factory, mcp_tool)

    agg = FastMCP(name="agg")
    agg.add_tool(proxy_tool)

    async with Client(agg) as client:
        with pytest.raises(ToolError) as excinfo:
            await client.call_tool("dead_echo", {})

    message = str(excinfo.value)
    assert "dead_echo" in message
    # A clean error message, not a Python traceback leaking to the caller.
    assert "Traceback" not in message
    assert "site-packages" not in message


def _toy_backend_with_failing_tool() -> FastMCP:
    mcp = FastMCP(name="toy-backend")

    @mcp.tool
    def boom() -> str:
        raise ToolError("boom from backend")

    return mcp


async def test_upstream_mcp_level_error_passes_through_unchanged(
    settings: Any, sig_key: Any, prime_jwks: Any
) -> None:
    """When the backend's own tool raises an MCP-level (application) tool
    error, ProxyTool.run() passes the isError CallToolResult through
    faithfully rather than raising -- see the comment in fastmcp's
    ProxyTool.run(). The aggregator must not intercept or rewrap that
    content: the caller should see exactly the backend's own error text,
    once, not double-wrapped with our own "Error calling tool" framing."""
    prime_jwks([sig_key.jwk])
    token = sig_key.sign(make_claims(groups=[]))

    async with run_server_async(_toy_backend_with_failing_tool(), path="/mcp") as url:
        registry = BackendRegistry()
        registry.register(
            BackendSpec(
                name="toy",
                prefix="toy",
                url=url,
                transport="http",
                required_capability="__none__",
                auth_type="none",
            )
        )
        policy = EntitlementPolicy()
        mcp = build_aggregator(registry, settings, policy, CredentialRegistry([]))

        async with run_server_async(mcp, path="/mcp") as agg_url:
            transport = StreamableHttpTransport(
                agg_url, headers={"Authorization": f"Bearer {token}"}
            )
            async with Client(transport) as client:
                result = await client.call_tool_mcp("toy_boom", {})

    assert result.isError is True
    assert len(result.content) == 1
    assert result.content[0].text == "boom from backend"


def _toy_backend_with_slow_tool() -> FastMCP:
    mcp = FastMCP(name="slow-backend")

    @mcp.tool
    async def slow() -> str:
        await asyncio.sleep(2)
        return "eventually done"

    return mcp


async def test_slow_backend_call_times_out_cleanly_instead_of_hanging(
    settings: Any, sig_key: Any, prime_jwks: Any
) -> None:
    """BackendSpec.timeout_seconds must actually be enforced on the wire, not
    just recorded on the Client -- a backend that never responds within that
    window must fail the call quickly with a clean ToolError, rather than
    the aggregator hanging on it indefinitely."""
    prime_jwks([sig_key.jwk])
    token = sig_key.sign(make_claims(groups=[]))

    async with run_server_async(_toy_backend_with_slow_tool(), path="/mcp") as url:
        registry = BackendRegistry()
        registry.register(
            BackendSpec(
                name="slow",
                prefix="slow",
                url=url,
                transport="http",
                required_capability="__none__",
                auth_type="none",
                timeout_seconds=0.2,
            )
        )
        policy = EntitlementPolicy()
        mcp = build_aggregator(registry, settings, policy, CredentialRegistry([]))

        async with run_server_async(mcp, path="/mcp") as agg_url:
            transport = StreamableHttpTransport(
                agg_url, headers={"Authorization": f"Bearer {token}"}
            )
            async with Client(transport) as client:
                started = time.monotonic()
                with pytest.raises(ToolError, match="Timed out"):
                    await client.call_tool("slow_slow", {})
                elapsed = time.monotonic() - started

    # Well under the backend's 2s sleep -- proves the call actually failed
    # on the configured 0.2s timeout rather than eventually completing.
    assert elapsed < 1.5
