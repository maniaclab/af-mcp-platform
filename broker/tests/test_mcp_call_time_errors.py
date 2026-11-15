from __future__ import annotations

import asyncio
from typing import Any

import mcp.types as mt
import pytest
from broker_state_helpers import aggregator_inputs
from conftest import make_claims, run_aggregator_async, run_inprocess_server
from fastmcp import Client, FastMCP
from fastmcp.exceptions import ToolError
from fastmcp.server.providers.proxy import ProxyTool
from fastmcp.utilities.http import find_available_port

from af_mcp_broker.authorization import EntitlementPolicy
from af_mcp_broker.credentials import CredentialRegistry
from af_mcp_broker.mcp.aggregator import _make_client_factory, build_aggregator
from af_mcp_broker.service_registry import ServiceRegistry, ServiceSpec

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
    never leak a raw httpx2/anyio exception or a Python traceback to the
    caller. The tool is registered directly (bypassing a live tools/list)
    because ProxyProvider's tools/list is exactly what "warn"-tolerates a
    dead backend by never listing its tools in the first place; this
    reproduces the case where the schema was already cached while the
    backend was up and it has since gone down."""
    dead_url = f"http://127.0.0.1:{find_available_port()}/mcp"
    spec = ServiceSpec(
        name="dead",
        prefix="dead",
        url=dead_url,
        transport="http",
        required_permission="__none__",
        auth_type="none",
    )
    factory = _make_client_factory(
        spec, CredentialRegistry(), settings, EntitlementPolicy()
    )
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
    settings: Any, sig_key: Any, prime_jwks: Any, static_principal_cache: Any
) -> None:
    """When the backend's own tool raises an MCP-level (application) tool
    error, ProxyTool.run() passes the isError CallToolResult through
    faithfully rather than raising -- see the comment in fastmcp's
    ProxyTool.run(). The aggregator must not intercept or rewrap that
    content: the caller should see exactly the backend's own error text,
    once, not double-wrapped with our own "Error calling tool" framing."""
    principal_cache, _directory = static_principal_cache
    prime_jwks([sig_key.jwk])
    token = sig_key.sign(make_claims())

    async with run_inprocess_server(
        _toy_backend_with_failing_tool(), path="/mcp"
    ) as url:
        registry = ServiceRegistry()
        registry.register(
            ServiceSpec(
                name="toy",
                prefix="toy",
                url=url,
                transport="http",
                required_permission="__none__",
                auth_type="none",
            )
        )
        policy = EntitlementPolicy()
        mcp = build_aggregator(
            registry, settings, policy, CredentialRegistry(), **aggregator_inputs()
        )

        async with (
            run_aggregator_async(
                mcp, path="/mcp", settings=settings, principal_cache=principal_cache
            ) as server,
            server.client(headers={"Authorization": f"Bearer {token}"}) as client,
        ):
            result = await client.call_tool_mcp("toy_boom", {})

    assert result.is_error is True
    assert len(result.content) == 1
    assert result.content[0].text == "boom from backend"


def _toy_backend_with_slow_tool(entered: asyncio.Event) -> FastMCP:
    mcp = FastMCP(name="slow-backend")

    @mcp.tool
    async def slow() -> str:
        entered.set()
        # Never completes on its own: the only way the caller's call can
        # return is the aggregator's timeout, whatever the machine's speed.
        await asyncio.Event().wait()
        return "unreachable"

    return mcp


# Upper bound on how long the whole call may take. It only guards against a
# hang; the assertion that matters is that the call fails with a timeout.
_HANG_GUARD_SECONDS = 10.0


async def test_slow_backend_call_times_out_cleanly_instead_of_hanging(
    settings: Any, sig_key: Any, prime_jwks: Any, static_principal_cache: Any
) -> None:
    """ServiceSpec.timeout_seconds must actually be enforced on the wire, not
    just recorded on the Client -- a backend that never responds within that
    window must fail the call quickly with a clean ToolError, rather than
    the aggregator hanging on it indefinitely.

    ServiceSpec.timeout_seconds also bounds the tools/list and initialize
    round trips (backend_client.build_client), and a failed listing makes the
    tool "Unknown" rather than slow. The tool is therefore listed under the
    default timeout first, and the spec's timeout is lowered only for the
    call, so the timeout under test can only fire inside the tool call. The
    backend signals when the call reaches it, which proves that."""
    principal_cache, _directory = static_principal_cache
    prime_jwks([sig_key.jwk])
    token = sig_key.sign(make_claims())
    entered = asyncio.Event()

    async with run_inprocess_server(
        _toy_backend_with_slow_tool(entered), path="/mcp"
    ) as url:
        spec = ServiceSpec(
            name="slow",
            prefix="slow",
            url=url,
            transport="http",
            required_permission="__none__",
            auth_type="none",
        )
        registry = ServiceRegistry()
        registry.register(spec)
        policy = EntitlementPolicy()
        mcp = build_aggregator(
            registry, settings, policy, CredentialRegistry(), **aggregator_inputs()
        )

        async with (
            run_aggregator_async(
                mcp, path="/mcp", settings=settings, principal_cache=principal_cache
            ) as server,
            server.client(headers={"Authorization": f"Bearer {token}"}) as client,
        ):
            listed = {tool.name for tool in await client.list_tools()}
            assert "slow_slow" in listed

            # Each backend connection reads spec.timeout_seconds when it is
            # built, so this applies to the call's connection only.
            spec.timeout_seconds = 0.5
            # fastmcp v4 normalizes a proxy transport timeout to its own
            # "Upstream request timed out" message (raised via
            # _proxy_upstream_error), replacing mcp v1's raw "Timed out
            # while waiting for response to..." text -- match
            # case-insensitively on the substring both wordings share.
            async with asyncio.timeout(_HANG_GUARD_SECONDS):
                with pytest.raises(ToolError, match=r"(?i)timed out"):
                    await client.call_tool("slow_slow", {})

    assert entered.is_set(), "timeout fired before the call reached the backend"
