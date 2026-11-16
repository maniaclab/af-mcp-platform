"""Log level of the ``/v1`` error responses: 5xx is the broker's failure, 4xx the caller's."""

from __future__ import annotations

import pytest
import structlog
from test_mcp_aggregator import _FakeProvider

from af_mcp_broker import app as app_module
from af_mcp_broker.credentials.errors import (
    CredentialForbiddenError,
    CredentialNotFoundError,
    CredentialRateLimitedError,
    CredentialReauthRequiredError,
    CredentialServiceError,
)

_TARGET = "level-target"


@pytest.mark.parametrize(
    ("exc", "status_code", "level"),
    [
        (CredentialReauthRequiredError("expired"), 401, "info"),
        (CredentialForbiddenError("no"), 403, "info"),
        (CredentialNotFoundError("none"), 404, "info"),
        (CredentialRateLimitedError("slow", retry_after="5"), 429, "info"),
        (CredentialServiceError("down"), 502, "error"),
    ],
)
def test_http_exception_logs_5xx_at_error_and_4xx_at_info(
    exc: Exception,
    status_code: int,
    level: str,
    app_client_factory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with app_client_factory() as (client, _state):
        client.app.state.broker.credential_registry.register(
            _TARGET,
            _FakeProvider(http_error=exc),  # type: ignore[arg-type]
        )
        # A booted app pins module loggers to its processor list (see
        # conftest's ``unpinned_loggers``), which hides their events from
        # ``capture_logs``.
        monkeypatch.setattr(
            app_module, "logger", structlog.get_logger(app_module.__name__)
        )
        with structlog.testing.capture_logs() as logs:
            resp = client.post("/v1/credential", json={"target": _TARGET})

    assert resp.status_code == status_code
    [entry] = [e for e in logs if e["event"] == "http.exception"]
    assert entry["log_level"] == level
    assert entry["status_code"] == status_code
    assert entry["path"] == "/v1/credential"
