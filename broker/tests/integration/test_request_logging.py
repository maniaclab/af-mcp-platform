"""Tests for issue #322: ``http.request.received``/``http.request.finished``
log lines at both ASGI entry points -- /v1's ``_bind_request_logging_context``
middleware (app.py) and /mcp's ``AsgiAuthMiddleware`` (identity_mw.py) -- so a
request that stalls or dies before anything downstream logs still leaves a
trace (the production incident behind this issue).

/v1 coverage drives ``app_module._bind_request_logging_context`` directly on
a minimal Starlette app (the decorator that registers it on the real ``app``
just returns the function unchanged, so it's reusable exactly like this) --
this avoids the full app boot's unrelated startup dependencies (Keycloak
admin creds, policy/services files, ...), which this middleware has none of.

/mcp coverage reuses test_mcp_middleware_identity.py's bare ASGI harness
(``_http_scope``/``_run``/``_InnerApp``) -- no JSON-RPC dispatch is involved
at this layer, so the harness exercises ``AsgiAuthMiddleware`` faithfully,
same as that file's own tests.

Both surfaces capture log output by patching the module's ``logger.info``
attribute directly (test_health.py's/test_app.py's established pattern),
not ``structlog.testing.capture_logs()`` -- test_identity.py's docstring
explains why that helper can silently miss a logger already resolved by an
earlier test's real app boot under ``cache_logger_on_first_use=True``.
Patching the instance attribute sidesteps that regardless of cache state.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest
from fastapi import FastAPI
from request_logging_support import (
    _capturing_info,
)
from starlette.applications import Starlette
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse, Response
from starlette.routing import Route
from starlette.testclient import TestClient

if TYPE_CHECKING:
    from starlette.requests import Request


import af_mcp_broker.app as app_module
from af_mcp_broker.logging import bind_parent_request_id, bind_subject

# ---------------------------------------------------------------------------
# /v1: app.py's _bind_request_logging_context
# ---------------------------------------------------------------------------


async def _v1_ok(request: Request) -> Response:
    del request
    return JSONResponse({"ok": True})


async def _v1_boom(request: Request) -> Response:
    del request
    raise RuntimeError("boom")


async def _v1_healthz(request: Request) -> Response:
    del request
    return JSONResponse({"status": "ok"})


@pytest.fixture
def v1_logging_app() -> Starlette:
    test_app = Starlette(
        routes=[
            Route("/v1/ok", _v1_ok),
            Route("/v1/boom", _v1_boom),
            Route("/v1/healthz", _v1_healthz),
        ]
    )
    test_app.add_middleware(
        BaseHTTPMiddleware, dispatch=app_module._bind_request_logging_context
    )
    return test_app


def test_v1_success_logs_received_and_finished_with_matching_request_id(
    monkeypatch: pytest.MonkeyPatch, v1_logging_app: Starlette
) -> None:
    events = _capturing_info(monkeypatch, app_module.logger)

    with TestClient(v1_logging_app) as client:
        resp = client.get(
            "/v1/ok?token=super-secret&foo=bar",
            headers={"Authorization": "Bearer sekrit-token"},
        )

    assert resp.status_code == 200
    received = next(e for e in events if e["event"] == "http.request.received")
    finished = next(e for e in events if e["event"] == "http.request.finished")

    assert received["method"] == "GET"
    assert received["path"] == "/v1/ok"  # no query string
    assert finished["status_code"] == 200
    assert finished["level"] == "info"
    assert finished["duration_ms"] >= 0
    assert finished["exc_type"] is None
    assert received["request_id"]
    assert received["request_id"] == finished["request_id"]

    # No query string, headers, or token anywhere in either logged line.
    dumped = json.dumps([received, finished])
    assert "super-secret" not in dumped
    assert "sekrit-token" not in dumped
    assert "authorization" not in dumped.lower()
    assert "query" not in dumped.lower()


def test_v1_exception_logs_finished_with_exc_type_and_still_returns_500(
    monkeypatch: pytest.MonkeyPatch, v1_logging_app: Starlette
) -> None:
    events = _capturing_info(monkeypatch, app_module.logger)

    with TestClient(v1_logging_app, raise_server_exceptions=False) as client:
        resp = client.get("/v1/boom")

    assert resp.status_code == 500
    received = next(e for e in events if e["event"] == "http.request.received")
    finished = next(e for e in events if e["event"] == "http.request.finished")

    assert finished["exc_type"] == "RuntimeError"
    # call_next raised before any response; the server answers 500 for it, and
    # an unhandled exception is the broker's failure, so it logs at error.
    assert finished["status_code"] == 500
    assert finished["level"] == "error"
    assert received["request_id"] == finished["request_id"]


def test_v1_exception_still_propagates_when_client_asks_for_it(
    monkeypatch: pytest.MonkeyPatch, v1_logging_app: Starlette
) -> None:
    """The finished-log wrapping must not swallow the exception -- a client
    that wants it raised (TestClient's default) still gets exactly that."""
    _capturing_info(monkeypatch, app_module.logger)

    with (
        TestClient(v1_logging_app) as client,
        pytest.raises(RuntimeError, match="boom"),
    ):
        client.get("/v1/boom")


def test_v1_health_endpoints_excluded_from_request_logging(
    monkeypatch: pytest.MonkeyPatch, v1_logging_app: Starlette
) -> None:
    events = _capturing_info(monkeypatch, app_module.logger)

    with TestClient(v1_logging_app) as client:
        resp = client.get("/v1/healthz")

    assert resp.status_code == 200
    assert not any(e["event"].startswith("http.request.") for e in events)


# ---------------------------------------------------------------------------
# finished lines name the request they close
# ---------------------------------------------------------------------------


def test_v1_finished_carries_method_and_path(
    monkeypatch: pytest.MonkeyPatch, v1_logging_app: Starlette
) -> None:
    events = _capturing_info(monkeypatch, app_module.logger)

    with TestClient(v1_logging_app) as client:
        client.get("/v1/ok?token=super-secret")

    finished = next(e for e in events if e["event"] == "http.request.finished")
    assert finished["method"] == "GET"
    assert finished["path"] == "/v1/ok"


def test_v1_finished_path_is_the_route_template_when_one_matched(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    test_app = FastAPI()
    test_app.add_api_route("/v1/things/{thing_id}", _v1_ok)
    test_app.add_middleware(
        BaseHTTPMiddleware, dispatch=app_module._bind_request_logging_context
    )
    events = _capturing_info(monkeypatch, app_module.logger)

    with TestClient(test_app) as client:
        client.get("/v1/things/abc123")

    received = next(e for e in events if e["event"] == "http.request.received")
    finished = next(e for e in events if e["event"] == "http.request.finished")
    assert received["path"] == "/v1/things/abc123"
    assert finished["path"] == "/v1/things/{thing_id}"


async def _v1_binds_subject(request: Request) -> Response:
    del request
    bind_subject("user-123")
    return JSONResponse({"ok": True})


def test_v1_finished_carries_the_subject_bound_while_handling(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """BaseHTTPMiddleware runs the app in a child task, so a subject bound by
    the handler (JWT, PAT, or a backend's broker token) is invisible to the
    middleware's own contextvars; ``bind_subject`` must hand it back."""
    test_app = Starlette(routes=[Route("/v1/who", _v1_binds_subject)])
    test_app.add_middleware(
        BaseHTTPMiddleware, dispatch=app_module._bind_request_logging_context
    )
    events = _capturing_info(monkeypatch, app_module.logger)

    with TestClient(test_app) as client:
        client.get("/v1/who")

    finished = next(e for e in events if e["event"] == "http.request.finished")
    assert finished["subject"] == "user-123"


async def _v1_binds_parent_request_id(request: Request) -> Response:
    del request
    bind_parent_request_id("tool-call-id")
    return JSONResponse({"ok": True})


def test_v1_finished_carries_the_parent_request_id_bound_while_handling(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Like the subject, a parent request id bound by the handler's child task
    must reach the middleware's ``finished`` line."""
    test_app = Starlette(routes=[Route("/v1/redeem", _v1_binds_parent_request_id)])
    test_app.add_middleware(
        BaseHTTPMiddleware, dispatch=app_module._bind_request_logging_context
    )
    events = _capturing_info(monkeypatch, app_module.logger)

    with TestClient(test_app) as client:
        client.get("/v1/redeem")

    finished = next(e for e in events if e["event"] == "http.request.finished")
    assert finished["parent_request_id"] == "tool-call-id"


def test_v1_finished_has_no_parent_request_id_when_none_was_bound(
    monkeypatch: pytest.MonkeyPatch, v1_logging_app: Starlette
) -> None:
    events = _capturing_info(monkeypatch, app_module.logger)

    with TestClient(v1_logging_app) as client:
        client.get("/v1/ok")

    finished = next(e for e in events if e["event"] == "http.request.finished")
    assert "parent_request_id" not in finished
