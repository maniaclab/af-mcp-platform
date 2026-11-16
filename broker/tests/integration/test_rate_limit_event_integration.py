"""Integration tests for the area ``test_rate_limit_event.py`` covers; the unit tests live in ``unit/test_rate_limit_event.py``."""

from __future__ import annotations

from typing import Any

import pytest
from mcp_aggregator_support import _FakeProvider
from request_logging_support import _capturing_info

from af_mcp_broker import app as app_module
from af_mcp_broker import retry_after as retry_after_module
from af_mcp_broker.api.auth import keycloak_dependency
from af_mcp_broker.credentials.errors import (
    CredentialRateLimitedError,
    UnlockRateLimitError,
)
from af_mcp_broker.logging import bind_subject

_TARGET = "rate-limit-target"
_SUBJECT = "sub-abc"


@pytest.mark.parametrize(
    ("exc", "limiter", "retry_after"),
    [
        (
            UnlockRateLimitError("locked", retry_after_seconds=42),
            "x509_unlock",
            42,
        ),
        (
            CredentialRateLimitedError("slow", retry_after="17"),
            "credential_service",
            17,
        ),
    ],
)
def test_v1_429_logs_the_dedicated_event_beside_the_generic_line(
    exc: Exception,
    limiter: str,
    retry_after: int,
    app_client_factory: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with app_client_factory() as (client, state):
        # An async override runs in the request's own task, so the subject it
        # binds reaches the exception handler, as identity.get_principal's does.
        async def _principal_binding_subject() -> object:
            bind_subject(_SUBJECT)
            return state["principal"]

        client.app.dependency_overrides[keycloak_dependency] = (
            _principal_binding_subject
        )
        client.app.state.broker.credential_registry.register(
            _TARGET,
            _FakeProvider(http_error=exc),  # type: ignore[arg-type]
        )
        # A booted app pins module loggers to its processor list, which
        # hides their events from capture (see conftest's ``unpinned_loggers``).
        events = _capturing_info(monkeypatch, retry_after_module.logger)
        generic = _capturing_info(monkeypatch, app_module.logger)
        resp = client.post("/v1/credential", json={"target": _TARGET})

    assert resp.status_code == 429
    [event] = [e for e in events if e["event"] == "rate_limit.exceeded"]
    assert event["subject"] == _SUBJECT
    assert event["limiter"] == limiter
    assert event["retry_after_seconds"] == retry_after
    assert [e for e in generic if e["event"] == "http.exception"]
