"""Unit tests for the area ``test_request_logging.py`` covers; the integration tests live in ``integration/test_request_logging.py``."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from conftest import make_claims
from mcp_middleware_identity_support import _http_scope, _InnerApp, _run, _status
from request_logging_support import (
    _capturing_info,
)

if TYPE_CHECKING:
    import pytest

from broker_state_helpers import asgi_auth_middleware

from af_mcp_broker.mcp.middleware import identity_mw

# ---------------------------------------------------------------------------
# /mcp: identity_mw.AsgiAuthMiddleware
# ---------------------------------------------------------------------------


async def test_mcp_received_and_finished_have_matching_request_id(
    monkeypatch: pytest.MonkeyPatch, settings: Any
) -> None:
    events = _capturing_info(monkeypatch, identity_mw.logger)
    inner = _InnerApp()
    middleware = asgi_auth_middleware(inner, settings)

    # No Authorization header -- an early 401 still must log both lines.
    messages = await _run(middleware, _http_scope())

    assert _status(messages) == 401
    received = next(e for e in events if e["event"] == "http.request.received")
    finished = next(e for e in events if e["event"] == "http.request.finished")
    assert received["request_id"]
    assert received["request_id"] == finished["request_id"]
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
    middleware = asgi_auth_middleware(inner, settings, principal_cache=principal_cache)

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
    middleware = asgi_auth_middleware(inner, settings, principal_cache=principal_cache)

    await _run(middleware, _http_scope({"authorization": f"Bearer {token}"}))

    dumped = json.dumps(events, default=str)
    assert token not in dumped
    assert "authorization" not in dumped.lower()


async def test_mcp_finished_carries_method_and_path(
    monkeypatch: pytest.MonkeyPatch, settings: Any
) -> None:
    events = _capturing_info(monkeypatch, identity_mw.logger)
    middleware = asgi_auth_middleware(_InnerApp(), settings)
    scope = {**_http_scope(), "method": "POST", "path": "/mcp/"}

    await _run(middleware, scope)

    finished = next(e for e in events if e["event"] == "http.request.finished")
    assert finished["method"] == "POST"
    assert finished["path"] == "/mcp/"
