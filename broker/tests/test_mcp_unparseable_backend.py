from __future__ import annotations

import gzip
import json
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import pytest
from conftest import AUDIENCE, ISSUER, make_claims, run_aggregator_async, run_asgi_app
from fastmcp import Client, FastMCP
from fastmcp.client.transports import StreamableHttpTransport
from fastmcp.exceptions import ToolError

from af_mcp_broker.authorization import EntitlementPolicy
from af_mcp_broker.config import Settings
from af_mcp_broker.credentials import CredentialRegistry
from af_mcp_broker.mcp import aggregator as aggregator_module
from af_mcp_broker.mcp.aggregator import build_aggregator, fetch_service_tool_listing
from af_mcp_broker.mcp.registry import ServiceRegistry, ServiceSpec

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

# ---------------------------------------------------------------------------
# A backend that answers at once, HTTP 200, with something the mcp SDK
# transport cannot parse as a JSON-RPC reply (issue #280: a gzip body nobody
# decoded, an HTML page from a proxy, plain text). The caller must hear about
# it promptly and specifically -- not after the per-service timeout and not as
# a generic "temporarily unavailable" -- and the backend's body must never
# reach a log line or the caller.
# ---------------------------------------------------------------------------

# Far above anything the assertions allow, so a regression to waiting out the
# service timeout fails them.
_SERVICE_TIMEOUT_SECONDS = 20.0
_MAX_SECONDS = 5.0
_BODY_MARKER = "SECRET-BODY-MARKER"


@dataclass(frozen=True)
class _BadResponse:
    body: bytes
    content_type: str
    problem: str


_BAD_RESPONSES = {
    "undecoded_gzip": _BadResponse(
        gzip.compress(f"{_BODY_MARKER}".encode() * 4),
        "application/json",
        "body is not valid JSON",
    ),
    "html_page": _BadResponse(
        f"<html>{_BODY_MARKER}</html>".encode(),
        "text/html; charset=utf-8",
        "unexpected content type",
    ),
    "garbage_json_content_type": _BadResponse(
        f"{_BODY_MARKER} not json".encode(),
        "application/json",
        "body is not valid JSON",
    ),
}


class _CorruptingBackend:
    """Wraps a real MCP backend, answering the given JSON-RPC methods with a fixed bad HTTP 200 response and passing everything else through."""

    def __init__(self, app: Any, methods: set[str], bad: _BadResponse) -> None:
        self.app = app
        self.methods = methods
        self.bad = bad

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] != "http" or scope["method"] != "POST":
            await self.app(scope, receive, send)
            return
        chunks = []
        more = True
        while more:
            message = await receive()
            chunks.append(message.get("body", b""))
            more = message.get("more_body", False)
        raw = b"".join(chunks)
        if json.loads(raw).get("method") in self.methods:
            await send(
                {
                    "type": "http.response.start",
                    "status": 200,
                    "headers": [(b"content-type", self.bad.content_type.encode())],
                }
            )
            await send({"type": "http.response.body", "body": self.bad.body})
            return
        replayed = False

        async def replay() -> Any:
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": raw, "more_body": False}
            return await receive()

        await self.app(scope, replay, send)


def _backend() -> FastMCP:
    mcp = FastMCP(name="backend")

    @mcp.tool
    def ping() -> str:
        return "pong"

    return mcp


def _spec(url: str) -> ServiceSpec:
    return ServiceSpec(
        name="bad",
        prefix="bad",
        url=url,
        transport="http",
        required_permission="__none__",
        auth_type="none",
        timeout_seconds=_SERVICE_TIMEOUT_SECONDS,
    )


@pytest.fixture(params=list(_BAD_RESPONSES))
def bad(request: pytest.FixtureRequest) -> _BadResponse:
    return _BAD_RESPONSES[request.param]


@pytest.fixture
def events(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, dict[str, Any]]]:
    """Every event the aggregator logs, as ``(event, fields)``.

    The logger is patched rather than captured with structlog's
    ``capture_logs``: a logger already bound earlier in the session ignores
    that context manager.
    """
    recorded: list[tuple[str, dict[str, Any]]] = []

    def _record(event: str, **kwargs: Any) -> None:
        recorded.append((event, kwargs))

    for level in ("debug", "info", "warning", "error", "exception"):
        monkeypatch.setattr(aggregator_module.logger, level, _record)
    return recorded


@asynccontextmanager
async def _aggregator_url(
    backend_url: str, registry: ServiceRegistry, principal_cache: Any
) -> AsyncIterator[str]:
    settings = Settings(oidc_issuer=ISSUER, oidc_audience=AUDIENCE)
    registry.register(_spec(backend_url))
    mcp = build_aggregator(
        registry,
        settings,
        EntitlementPolicy(),
        CredentialRegistry(),
        principal_cache=principal_cache,
    )
    async with run_aggregator_async(mcp, path="/mcp") as url:
        yield url


def _client(url: str, token: str) -> Client:
    return Client(
        StreamableHttpTransport(url, headers={"Authorization": f"Bearer {token}"})
    )


def _invalid_response_events(
    events: list[tuple[str, dict[str, Any]]],
) -> list[dict[str, Any]]:
    return [f for e, f in events if e == "aggregator.backend_invalid_response"]


def _assert_logged_without_body(
    events: list[tuple[str, dict[str, Any]]], bad: _BadResponse
) -> None:
    [logged] = _invalid_response_events(events)
    assert logged["service"] == "bad"
    assert logged["status_code"] == 200
    assert logged["content_type"] == bad.content_type.split(";")[0]
    assert logged["problem"] == bad.problem
    assert _BODY_MARKER not in repr(events)


async def test_tools_list_with_unparseable_backend_response_fails_fast_and_is_logged(
    bad: _BadResponse,
    events: list[tuple[str, dict[str, Any]]],
    sig_key: Any,
    prime_jwks: Any,
    static_principal_cache: Any,
) -> None:
    principal_cache, _ = static_principal_cache
    registry = ServiceRegistry()
    app = _CorruptingBackend(_backend().http_app(path="/mcp"), {"tools/list"}, bad)
    prime_jwks([sig_key.jwk])
    token = sig_key.sign(make_claims())
    async with (
        run_asgi_app(app) as backend_url,
        _aggregator_url(f"{backend_url}/mcp", registry, principal_cache) as url,
    ):
        started = time.monotonic()
        async with _client(url, token) as client:
            names = {t.name for t in await client.list_tools()}
        elapsed = time.monotonic() - started

    assert elapsed < _MAX_SECONDS
    assert "af_whoami" in names
    assert not any(n.startswith("bad_") for n in names)
    _assert_logged_without_body(events, bad)
    # Mapped to the same caller-facing status as any other unreachable backend.
    assert registry.recent_list_failure("bad", "user-123") == "unavailable"
    [failure] = [f for e, f in events if e == "aggregator.service_list_failed"]
    assert failure["reason"] == "unavailable"
    assert "invalid response" in failure["error"]


async def test_tools_call_with_unparseable_backend_response_fails_fast_and_specifically(
    bad: _BadResponse,
    events: list[tuple[str, dict[str, Any]]],
    sig_key: Any,
    prime_jwks: Any,
    static_principal_cache: Any,
) -> None:
    principal_cache, _ = static_principal_cache
    app = _CorruptingBackend(_backend().http_app(path="/mcp"), {"tools/call"}, bad)
    prime_jwks([sig_key.jwk])
    token = sig_key.sign(make_claims())
    async with (
        run_asgi_app(app) as backend_url,
        _aggregator_url(
            f"{backend_url}/mcp", ServiceRegistry(), principal_cache
        ) as url,
    ):
        started = time.monotonic()
        async with _client(url, token) as client:
            with pytest.raises(ToolError) as excinfo:
                await client.call_tool("bad_ping", {})
        elapsed = time.monotonic() - started

    assert elapsed < _MAX_SECONDS
    message = str(excinfo.value)
    assert "Service 'bad' returned an invalid response" in message
    assert "HTTP 200" in message
    assert _BODY_MARKER not in message
    assert "unavailable" not in message.lower()
    _assert_logged_without_body(events, bad)


async def test_one_shot_service_listing_reports_unavailable_for_unparseable_response(
    bad: _BadResponse, events: list[tuple[str, dict[str, Any]]]
) -> None:
    app = _CorruptingBackend(_backend().http_app(path="/mcp"), {"tools/list"}, bad)
    async with run_asgi_app(app) as backend_url:
        started = time.monotonic()
        status, tools = await fetch_service_tool_listing(
            _spec(f"{backend_url}/mcp"), None, None
        )
        elapsed = time.monotonic() - started

    assert elapsed < _MAX_SECONDS
    assert (status, tools) == ("unavailable", [])
    _assert_logged_without_body(events, bad)


async def test_well_formed_backend_is_not_flagged(
    events: list[tuple[str, dict[str, Any]]],
) -> None:
    async with run_asgi_app(_backend().http_app(path="/mcp")) as backend_url:
        status, tools = await fetch_service_tool_listing(
            _spec(f"{backend_url}/mcp"), None, None
        )

    assert status == "ok"
    assert [t.name for t in tools] == ["bad_ping"]
    assert _invalid_response_events(events) == []
