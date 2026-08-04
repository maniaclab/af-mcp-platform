from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, Any

import pytest
import uvicorn
from conftest import AUDIENCE, ISSUER, make_claims
from fastmcp import Client, FastMCP
from fastmcp.client.transports import StreamableHttpTransport
from fastmcp.server.dependencies import get_http_headers
from fastmcp.utilities.http import find_available_port
from fastmcp.utilities.tests import run_server_async
from mcp.shared.exceptions import McpError

from af_mcp_broker.config import get_settings

if TYPE_CHECKING:
    from collections.abc import AsyncIterator
    from pathlib import Path

# ---------------------------------------------------------------------------
# Toy backends. One echoes its own inbound headers back (to prove the
# aggregator never forwards the caller's Authorization to a backend), one
# is self-prefixed like rucio-mcp (to exercise apply_namespace=False), and
# a third URL is never served at all (to exercise dead-backend tolerance).
# ---------------------------------------------------------------------------


def _toy_backend() -> FastMCP:
    mcp = FastMCP(name="toy-backend")

    @mcp.tool
    def echo(message: str) -> str:
        return message

    @mcp.tool
    def seen_headers() -> list[str]:
        """Returns the names of every header this backend actually
        received, so the test can assert "authorization" is absent."""
        return sorted(get_http_headers(include_all=True).keys())

    return mcp


def _self_prefixed_backend() -> FastMCP:
    """Mimics rucio-mcp: its own tools are already prefixed."""
    mcp = FastMCP(name="selfpfx-backend")

    @mcp.tool
    def selfpfx_ping() -> str:
        return "pong"

    return mcp


@asynccontextmanager
async def _run_asgi_app(app: Any) -> AsyncIterator[str]:
    """Run an arbitrary ASGI app (not necessarily a FastMCP server) behind a
    real uvicorn server on an ephemeral port, for testing app.py's actual
    mount + combine_lifespans wiring end-to-end -- not just the aggregator
    FastMCP instance in isolation."""
    port = find_available_port()
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
    server = uvicorn.Server(config)
    task = asyncio.create_task(server.serve())
    while not server.started:
        await asyncio.sleep(0.01)
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        await task


@pytest.fixture
async def toy_backend_url() -> AsyncIterator[str]:
    async with run_server_async(_toy_backend(), path="/mcp") as url:
        yield url


@pytest.fixture
async def selfpfx_backend_url() -> AsyncIterator[str]:
    async with run_server_async(_self_prefixed_backend(), path="/mcp") as url:
        yield url


@pytest.fixture
def dead_backend_url() -> str:
    """A URL nobody is listening on -- connections must fail fast
    (connection refused), not hang."""
    port = find_available_port()
    return f"http://127.0.0.1:{port}/mcp"


@pytest.fixture
def running_broker(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    toy_backend_url: str,
    selfpfx_backend_url: str,
    dead_backend_url: str,
    sig_key: Any,
    prime_jwks: Any,
):
    """Boot the real af_mcp_broker.app.app (module-level singleton, same
    object every test module shares) behind a real HTTP server, wired to
    three test backends via a temp backends.yaml/policy.yaml."""
    backends_file = tmp_path / "backends.yaml"
    # auth_type: none on all three -- these tests exercise aggregator
    # plumbing (namespacing, entitlement filtering, dead-backend tolerance,
    # header non-forwarding), not credential injection, which has its own
    # dedicated tests/fixtures registering real credential providers.
    backends_file.write_text(
        f"""
backends:
  - name: toy
    prefix: toy
    url: "{toy_backend_url}"
    transport: http
    required_capability: read_data
    auth_type: none
  - name: selfpfx
    prefix: selfpfx
    url: "{selfpfx_backend_url}"
    transport: http
    required_capability: __none__
    apply_namespace: false
    auth_type: none
  - name: dead
    prefix: dead
    url: "{dead_backend_url}"
    transport: http
    required_capability: __none__
    auth_type: none
"""
    )
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text(
        """
group_capabilities:
  atlas: [read_data]
  __authenticated__: []
"""
    )

    monkeypatch.setenv("BACKENDS_FILE", str(backends_file))
    monkeypatch.setenv("POLICY_FILE", str(policy_file))
    monkeypatch.setenv("OIDC_ISSUER", ISSUER)
    monkeypatch.setenv("OIDC_AUDIENCE", AUDIENCE)
    monkeypatch.setenv("METRICS_PORT", "0")
    monkeypatch.delenv("BROKER_DEV_INSECURE_PRINCIPAL", raising=False)
    get_settings.cache_clear()
    prime_jwks([sig_key.jwk])

    from af_mcp_broker.app import app

    return app


def _bearer_client(url: str, token: str) -> Client:
    return Client(
        StreamableHttpTransport(url, headers={"Authorization": f"Bearer {token}"})
    )


async def _list_tool_names(mcp_url: str, token: str) -> set[str]:
    async with _bearer_client(f"{mcp_url}/mcp/", token) as client:
        tools = await client.list_tools()
    return {t.name for t in tools}


async def test_entitled_principal_sees_namespaced_and_selfprefixed_tools(
    running_broker, sig_key
):
    token = sig_key.sign(make_claims(groups=["atlas"]))

    async with _run_asgi_app(running_broker) as base_url:
        names = await _list_tool_names(base_url, token)

    # toy's tools are namespaced ("toy_echo"); selfpfx's are not
    # (apply_namespace=false) -- and the never-served "dead" backend
    # contributes nothing, but does not prevent the others from listing
    # (provider_error_strategy defaults to "warn").
    assert "toy_echo" in names
    assert "toy_seen_headers" in names
    assert "selfpfx_ping" in names
    assert not any(n.startswith("dead_") for n in names)


async def test_unentitled_principal_does_not_see_gated_tools(running_broker, sig_key):
    token = sig_key.sign(make_claims(groups=[]))

    async with _run_asgi_app(running_broker) as base_url:
        names = await _list_tool_names(base_url, token)

    # No read_data capability -> toy's tools (required_capability=read_data)
    # are filtered out, but the open selfpfx tool is still visible.
    assert "toy_echo" not in names
    assert "toy_seen_headers" not in names
    assert "selfpfx_ping" in names


async def test_missing_bearer_rejected(running_broker):
    async with _run_asgi_app(running_broker) as base_url:
        with pytest.raises(McpError):
            async with Client(f"{base_url}/mcp/") as client:
                await client.list_tools()


async def test_tool_call_round_trips_to_backend(running_broker, sig_key):
    token = sig_key.sign(make_claims(groups=["atlas"]))

    async with (
        _run_asgi_app(running_broker) as base_url,
        _bearer_client(f"{base_url}/mcp/", token) as client,
    ):
        result = await client.call_tool("toy_echo", {"message": "hello"})

    assert result.data == "hello"


async def test_authorization_header_not_forwarded_to_backend(running_broker, sig_key):
    """The core security property of PR A's client_factory: the caller's
    inbound Authorization header must never reach a backend."""
    token = sig_key.sign(make_claims(groups=["atlas"]))

    async with (
        _run_asgi_app(running_broker) as base_url,
        _bearer_client(f"{base_url}/mcp/", token) as client,
    ):
        result = await client.call_tool("toy_seen_headers", {})

    assert "authorization" not in result.data
