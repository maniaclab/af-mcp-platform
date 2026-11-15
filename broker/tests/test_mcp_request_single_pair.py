"""One /mcp request leaves exactly one ``http.request.received``/``finished``
pair and one ``correlation_id``, with the caller's ``subject`` on the pair.

The real app wraps the /mcp mount in /v1's ``_bind_request_logging_context``
BaseHTTPMiddleware, so a /mcp request crosses two request-logging layers.
This drives that same stack (outer middleware + Mount + AsgiAuthMiddleware)
on a minimal Starlette app, capturing both layers' loggers.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import structlog
from broker_state_helpers import asgi_auth_middleware
from conftest import make_claims
from starlette.applications import Starlette
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.routing import Mount
from starlette.testclient import TestClient
from test_request_logging import _capturing_info

import af_mcp_broker.app as app_module
from af_mcp_broker.mcp.middleware import identity_mw

if TYPE_CHECKING:
    import pytest


class _ContextRecordingApp:
    """Inner /mcp app that records the contextvars bound while it runs."""

    def __init__(self) -> None:
        self.contextvars: dict[str, Any] = {}

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        self.contextvars = dict(structlog.contextvars.get_contextvars())
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})


def test_one_mcp_request_logs_one_pair_with_one_correlation_id_and_subject(
    monkeypatch: pytest.MonkeyPatch,
    settings: Any,
    sig_key: Any,
    prime_jwks: Any,
    static_principal_cache: Any,
) -> None:
    principal_cache, directory = static_principal_cache
    directory.posix_by_subject["user-123"] = {"uid": 50123, "unixname": "auser"}
    prime_jwks([sig_key.jwk])
    token = sig_key.sign(make_claims())
    app_events = _capturing_info(monkeypatch, app_module.logger)
    mcp_events = _capturing_info(monkeypatch, identity_mw.logger)
    inner = _ContextRecordingApp()
    mcp = asgi_auth_middleware(inner, settings, principal_cache=principal_cache)
    test_app = Starlette(routes=[Mount("/mcp", mcp)])
    test_app.add_middleware(
        BaseHTTPMiddleware, dispatch=app_module._bind_request_logging_context
    )

    with TestClient(test_app) as client:
        resp = client.post(
            "/mcp/?secret=hunter2", headers={"Authorization": f"Bearer {token}"}
        )

    assert resp.status_code == 200
    events = app_events + mcp_events
    received = [e for e in events if e["event"] == "http.request.received"]
    finished = [e for e in events if e["event"] == "http.request.finished"]
    assert len(received) == 1
    assert len(finished) == 1
    correlation_ids = {
        received[0]["correlation_id"],
        finished[0]["correlation_id"],
        inner.contextvars["correlation_id"],
    }
    assert len(correlation_ids) == 1
    assert finished[0]["subject"] == "user-123"
    assert finished[0]["method"] == "POST"
    assert finished[0]["path"] == "/mcp/"
    assert finished[0]["status_code"] == 200
    assert "hunter2" not in str(events)
