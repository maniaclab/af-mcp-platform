"""Tests for mapping ``RateLimitError`` to HTTP 429 with ``Retry-After`` (issue #25).

``RateLimitError`` is raised by ``CredentialCache.get()``/``check_unlock_rate_limit()``
when a uid exceeds the configured failed-unlock threshold. Before this change the
error was unhandled at the API layer and surfaced as a bare 500; the global handler
in ``app.py`` now maps it to 429 with a ``Retry-After`` header and a matching JSON body.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

    import pytest
    from fastapi.testclient import TestClient

_AUTH = {"Authorization": "Bearer test"}


def _trip_rate_limit(client: TestClient, max_failures: int):
    """POST /v1/credential for the x509 'ami' target until RateLimitError trips.

    Each call misses the (empty) cache, which counts against the uid; with no
    passphrase supplied the first *max_failures* calls surface as 409
    (NeedsUnlock) and the next one trips the limiter -> 429.
    """
    for _ in range(max_failures):
        resp = client.post("/v1/credential", json={"target": "ami"}, headers=_AUTH)
        assert resp.status_code == 409, resp.text
    return client.post("/v1/credential", json={"target": "ami"}, headers=_AUTH)


def test_rate_limit_returns_429_with_retry_after(
    app_client_factory: Callable[..., object], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CREDENTIAL_UNLOCK_MAX_FAILURES", "2")
    monkeypatch.setenv("CREDENTIAL_UNLOCK_WINDOW_SECONDS", "60")

    with app_client_factory() as (client, _state):
        resp = _trip_rate_limit(client, max_failures=2)

    assert resp.status_code == 429, resp.text

    retry_after_header = resp.headers.get("Retry-After")
    assert retry_after_header is not None
    assert retry_after_header.isdigit()
    retry_after = int(retry_after_header)
    assert 0 <= retry_after <= 60

    body = resp.json()
    assert body["retry_after_seconds"] == retry_after
    assert "Too many failed unlock attempts" in body["detail"]
    assert str(retry_after) in body["detail"]

    # retry_at must be a parseable UTC ISO-8601 timestamp with a Z suffix.
    retry_at = datetime.strptime(body["retry_at"], "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=UTC
    )
    assert retry_at is not None


def test_retry_after_matches_configured_window(
    app_client_factory: Callable[..., object], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CREDENTIAL_UNLOCK_MAX_FAILURES", "1")
    monkeypatch.setenv("CREDENTIAL_UNLOCK_WINDOW_SECONDS", "60")

    with app_client_factory() as (client, _state):
        resp = _trip_rate_limit(client, max_failures=1)

    assert resp.status_code == 429, resp.text
    retry_after = int(resp.headers["Retry-After"])
    # Tripped immediately after the window opened, so almost the full window
    # should remain — but never more than the configured window.
    assert 0 <= retry_after <= 60
    assert resp.json()["retry_after_seconds"] == retry_after


def test_rate_limit_no_regression(
    app_client_factory: Callable[..., object], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Below the threshold, requests keep surfacing NeedsUnlock as 409, not 429."""
    monkeypatch.setenv("CREDENTIAL_UNLOCK_MAX_FAILURES", "5")
    monkeypatch.setenv("CREDENTIAL_UNLOCK_WINDOW_SECONDS", "900")

    with app_client_factory() as (client, _state):
        for _ in range(5):
            resp = client.post("/v1/credential", json={"target": "ami"}, headers=_AUTH)
            assert resp.status_code == 409, resp.text
