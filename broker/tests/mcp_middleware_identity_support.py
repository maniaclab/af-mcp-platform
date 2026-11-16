"""Fixtures and helpers shared by the unit and integration tests of ``test_mcp_middleware_identity``."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from af_mcp_broker.mcp.middleware.identity_mw import (
        AsgiAuthMiddleware,
    )

# ---------------------------------------------------------------------------
# AsgiAuthMiddleware -- the ASGI-layer identity check that runs in front of
# FastMCP's own message pipeline (issue #138/#144 step 1). These tests drive
# it directly with a bare ASGI scope/receive/send rather than a live uvicorn
# server -- no JSON-RPC dispatch is involved at this layer, so a raw ASGI
# harness exercises it faithfully; the real-server round trip (initialize,
# tools/list, tools/call through a live aggregator) is covered separately in
# test_mcp_list_time_credentials.py / test_mcp_aggregator_integration.py.
# ---------------------------------------------------------------------------


class _InnerApp:
    """Records the scope it was called with and answers a trivial 200."""

    def __init__(self) -> None:
        self.called = False
        self.scope: dict[str, Any] | None = None

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        self.called = True
        self.scope = scope
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})


async def _run(
    middleware: AsgiAuthMiddleware, scope: dict[str, Any]
) -> list[dict[str, Any]]:
    messages: list[dict[str, Any]] = []

    async def receive() -> dict[str, Any]:
        return {"type": "http.disconnect"}

    async def send(message: dict[str, Any]) -> None:
        messages.append(message)

    await middleware(scope, receive, send)
    return messages
