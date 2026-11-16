from __future__ import annotations

from typing import Any

from broker_state_helpers import asgi_auth_middleware
from test_mcp_middleware_identity import (
    _InnerApp,
    _run,
)

from af_mcp_broker.maintenance import (
    InMemoryMaintenanceModeStore,
)
from af_mcp_broker.mcp.middleware.maintenance_mw import AsgiMaintenanceMiddleware


async def test_non_http_scope_passes_through_untouched(settings):
    inner = _InnerApp()
    middleware = asgi_auth_middleware(inner, settings)

    async def receive() -> dict[str, Any]:
        return {}

    async def send(message: dict[str, Any]) -> None:
        pass

    await middleware({"type": "lifespan"}, receive, send)

    assert inner.called


async def test_maintenance_middleware_passes_non_http_scopes_through(settings):
    inner = _InnerApp()
    middleware = AsgiMaintenanceMiddleware(
        inner, settings, InMemoryMaintenanceModeStore()
    )

    await _run(middleware, {"type": "lifespan"})

    assert inner.called
