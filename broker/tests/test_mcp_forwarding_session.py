from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import pytest
from broker_state_helpers import aggregator_inputs
from conftest import (
    make_claims,
    run_aggregator_async,
    run_inprocess_asgi_app,
)
from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from fastmcp.tools.base import ToolResult

from af_mcp_broker.authorization import EntitlementPolicy
from af_mcp_broker.credentials import CredentialRegistry
from af_mcp_broker.mcp.aggregator import build_aggregator
from af_mcp_broker.service_registry import ServiceRegistry, ServiceSpec

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

# ---------------------------------------------------------------------------
# A proxied tools/call must cost the backend exactly the request the caller
# asked for. A plain fastmcp Client validates a call result against the
# tool's advertised output schema, which it learns by listing the backend's
# tools -- one extra full tools/list per call. The aggregator only relays
# results (the end client validates for itself), so it must not do that.
# ---------------------------------------------------------------------------

_COUNT_SCHEMA = {
    "type": "object",
    "properties": {"n": {"type": "integer"}},
    "required": ["n"],
}


class _MethodRecorder:
    """ASGI wrapper recording the JSON-RPC ``method`` of every POST the backend receives."""

    def __init__(self, app: Any) -> None:
        self._app = app
        self.methods: list[str] = []

    def __getattr__(self, name: str) -> Any:
        return getattr(self._app, name)

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] != "http" or scope["method"] != "POST":
            await self._app(scope, receive, send)
            return
        body = b""
        more = True
        while more:
            message = await receive()
            body += message.get("body", b"")
            more = message.get("more_body", False)
        payload = json.loads(body)
        for item in payload if isinstance(payload, list) else [payload]:
            self.methods.append(item.get("method", "<response>"))

        sent = False

        async def replay() -> dict[str, Any]:
            nonlocal sent
            if sent:
                return await receive()
            sent = True
            return {"type": "http.request", "body": body, "more_body": False}

        await self._app(scope, replay, send)


def _backend() -> FastMCP:
    mcp = FastMCP(name="forwarding-backend")

    @mcp.tool
    def echo(message: str) -> str:
        return message

    @mcp.tool(output_schema=_COUNT_SCHEMA)
    def violates_schema() -> ToolResult:
        """Returns structured content that contradicts its own output schema."""
        return ToolResult(structured_content={"n": "not-an-integer"})

    @mcp.tool
    def fails() -> str:
        raise ValueError("backend exploded")

    return mcp


@pytest.fixture
async def recorded_backend() -> AsyncIterator[tuple[str, _MethodRecorder]]:
    recorder = _MethodRecorder(_backend().http_app(path="/mcp"))
    async with run_inprocess_asgi_app(recorder) as base_url:
        yield f"{base_url}/mcp", recorder


@pytest.fixture
def aggregator(settings, recorded_backend, static_principal_cache):
    url, _recorder = recorded_backend
    principal_cache, _directory = static_principal_cache
    registry = ServiceRegistry()
    registry.register(
        ServiceSpec(
            name="fwd",
            prefix="fwd",
            url=url,
            transport="http",
            required_permission="__none__",
            auth_type="none",
        )
    )

    async def _run():
        mcp = build_aggregator(
            registry,
            settings,
            EntitlementPolicy(),
            CredentialRegistry(),
            **aggregator_inputs(),
        )
        async with run_aggregator_async(
            mcp, path="/mcp", settings=settings, principal_cache=principal_cache
        ) as server:
            yield server

    return _run


async def test_proxied_call_forwards_only_tools_call(
    aggregator, recorded_backend, sig_key, prime_jwks
) -> None:
    """After the aggregator's tool listing is warm, one proxied tools/call is
    exactly one ``tools/call`` at the backend, preceded by at most the
    connection handshake -- never a second ``tools/list``."""
    prime_jwks([sig_key.jwk])
    token = sig_key.sign(make_claims())
    _url, recorder = recorded_backend

    async for server in aggregator():
        client = server.client(headers={"Authorization": f"Bearer {token}"})
        async with client:
            await client.list_tools()
            recorder.methods.clear()
            result = await client.call_tool("fwd_echo", {"message": "hi"})

    assert result.data == "hi"
    assert "tools/list" not in recorder.methods
    assert recorder.methods.count("tools/call") == 1
    assert set(recorder.methods) <= {"tools/call", "initialize", "server/discover"}
    assert result.content[0].text == "hi"
    assert result.structured_content == {"result": "hi"}
    assert result.is_error is False


async def test_backend_error_result_is_relayed_unchanged(
    aggregator, sig_key, prime_jwks
) -> None:
    prime_jwks([sig_key.jwk])
    token = sig_key.sign(make_claims())

    async for server in aggregator():
        client = server.client(headers={"Authorization": f"Bearer {token}"})
        async with client:
            result = await client.call_tool("fwd_fails", {}, raise_on_error=False)

    assert result.is_error is True
    assert "backend exploded" in result.content[0].text


async def test_output_schema_violation_is_relayed_not_policed(
    aggregator, sig_key, prime_jwks
) -> None:
    """Output-schema policing belongs to the end consumer, as in fastmcp's own
    proxy: the aggregator relays the backend's structured content as sent."""
    prime_jwks([sig_key.jwk])
    token = sig_key.sign(make_claims())

    async for server in aggregator():
        client = server.client(headers={"Authorization": f"Bearer {token}"})
        async with client:
            try:
                result = await client.call_tool("fwd_violates_schema", {})
            except ToolError as exc:
                pytest.fail(f"aggregator policed the backend output schema: {exc}")

    assert result.structured_content == {"n": "not-an-integer"}
    assert result.is_error is False
