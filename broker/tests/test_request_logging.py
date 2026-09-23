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
from typing import TYPE_CHECKING, Any

import pytest
import structlog
from conftest import make_claims
from starlette.applications import Starlette
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse, Response
from starlette.routing import Route
from starlette.testclient import TestClient
from test_mcp_middleware_identity import _http_scope, _InnerApp, _run, _status

if TYPE_CHECKING:
    from starlette.requests import Request

import af_mcp_broker.app as app_module
from af_mcp_broker.mcp.middleware import identity_mw
from af_mcp_broker.mcp.middleware.identity_mw import (
    AsgiAuthMiddleware,
    IdentityMiddleware,
)


def _capturing_info(
    monkeypatch: pytest.MonkeyPatch, logger: Any
) -> list[dict[str, Any]]:
    """Record every ``logger.info(...)`` call's event, explicit kwargs, and
    currently-bound structlog contextvars (correlation_id/subject) together
    -- the contextvar merge normally only happens inside structlog's
    processor chain on the way to output, which patching the method this way
    bypasses for the *recorded* copy (the original call still runs, so real
    output/processing is unaffected).
    """
    events: list[dict[str, Any]] = []
    original_info = logger.info

    def _capture(event: str, **kwargs: Any) -> Any:
        events.append(
            {"event": event, **structlog.contextvars.get_contextvars(), **kwargs}
        )
        return original_info(event, **kwargs)

    monkeypatch.setattr(logger, "info", _capture)
    return events


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


def test_v1_success_logs_received_and_finished_with_matching_correlation_id(
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
    assert finished["duration_ms"] >= 0
    assert finished["exc_type"] is None
    assert received["correlation_id"]
    assert received["correlation_id"] == finished["correlation_id"]

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
    assert finished["status_code"] is None  # call_next raised before any response
    assert received["correlation_id"] == finished["correlation_id"]


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
# /mcp: identity_mw.AsgiAuthMiddleware
# ---------------------------------------------------------------------------


async def test_mcp_received_and_finished_have_matching_correlation_id(
    monkeypatch: pytest.MonkeyPatch, settings: Any
) -> None:
    events = _capturing_info(monkeypatch, identity_mw.logger)
    inner = _InnerApp()
    middleware = AsgiAuthMiddleware(inner, IdentityMiddleware(settings))

    # No Authorization header -- an early 401 still must log both lines.
    messages = await _run(middleware, _http_scope())

    assert _status(messages) == 401
    received = next(e for e in events if e["event"] == "http.request.received")
    finished = next(e for e in events if e["event"] == "http.request.finished")
    assert received["correlation_id"]
    assert received["correlation_id"] == finished["correlation_id"]
    assert finished["status_code"] == 401
    assert finished["exc_type"] is None


async def test_mcp_finished_carries_subject_for_an_authenticated_request(
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
    events = _capturing_info(monkeypatch, identity_mw.logger)
    inner = _InnerApp()
    middleware = AsgiAuthMiddleware(
        inner, IdentityMiddleware(settings, principal_cache=principal_cache)
    )

    messages = await _run(middleware, _http_scope({"authorization": f"Bearer {token}"}))

    assert _status(messages) == 200
    finished = next(e for e in events if e["event"] == "http.request.finished")
    # subject is bound by identity.get_principal (via bind_subject) before
    # this line logs -- structlog's merge_contextvars processor puts it on
    # automatically, no explicit threading through log_request_finished.
    assert finished["subject"]


async def test_mcp_logs_leak_no_header_or_token(
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
    events = _capturing_info(monkeypatch, identity_mw.logger)
    inner = _InnerApp()
    middleware = AsgiAuthMiddleware(
        inner, IdentityMiddleware(settings, principal_cache=principal_cache)
    )

    await _run(middleware, _http_scope({"authorization": f"Bearer {token}"}))

    dumped = json.dumps(events, default=str)
    assert token not in dumped
    assert "authorization" not in dumped.lower()
