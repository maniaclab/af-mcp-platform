"""Tests for mapping ``RateLimitError`` to HTTP 429 with ``Retry-After`` (issue #25)
and for the miss-vs-bad-passphrase rate-limit fix (issue #93).

``RateLimitError`` is raised by ``CredentialCache.record_failed_unlock()``/
``check_unlock_rate_limit()`` when a uid exceeds the configured failed-unlock
threshold. Before issue #93's fix, ordinary cache misses -- including the
"not cached yet, no passphrase given" probe that surfaces as 409 -- counted
against that same budget, so a handful of routine `NeedsUnlock` probes could
lock a user out of their own next (correct) unlock attempt. The global
handler in `app.py` maps `RateLimitError` to 429 with a `Retry-After` header
and a matching JSON body.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from fastapi import HTTPException

if TYPE_CHECKING:
    from collections.abc import Callable

    import pytest
    from fastapi.testclient import TestClient

_AUTH = {"Authorization": "Bearer test"}


class _FakeSucceedingBackend:
    """Fake ``X509Backend`` that mints instantly, without touching k8s."""

    async def available(self, principal) -> bool:
        return True

    async def mint(self, principal, passphrase, valid, voms, cache):
        from af_mcp_broker.credentials.cache import ProxyMeta

        cache.check_unlock_rate_limit(principal.uid)
        return ProxyMeta(
            dn="CN=Fake User",
            voms_attributes=[],
            not_after=time.time() + 3600,
            proxy_path="/tmp/fake-proxy.pem",
        )


class _FakeFailingBackend:
    """Fake ``X509Backend`` that always fails the unlock (bad passphrase).

    Mirrors what ``HomeDirVomsBackend`` does on a real minting-backend
    failure: call ``record_failed_unlock`` then surface the failure as a
    4xx ``HTTPException`` (the API layer has no dedicated handler for a
    bad-passphrase ``ValueError``, so a plain 422 stands in for it here).
    """

    async def available(self, principal) -> bool:
        return True

    async def mint(self, principal, passphrase, valid, voms, cache):
        cache.check_unlock_rate_limit(principal.uid)
        cache.record_failed_unlock(principal.uid)
        raise HTTPException(status_code=422, detail="bad passphrase (fake)")


def _probe(client: TestClient):
    """POST /v1/credential for the x509 'ami' target with no passphrase.

    Misses the (empty) cache and surfaces as 409 (NeedsUnlock) -- the
    ordinary "not cached yet" probe an MCP client makes before ever prompting
    for a passphrase.
    """
    return client.post("/v1/credential", json={"target": "ami"}, headers=_AUTH)


def _unlock(client: TestClient, passphrase: str = "correct-horse-battery-staple"):
    """POST /v1/x509/proxy -- the actual passphrase-submission endpoint."""
    return client.post("/v1/x509/proxy", json={"passphrase": passphrase}, headers=_AUTH)


def test_needs_unlock_probes_never_trip_rate_limit(
    app_client_factory: Callable[..., object], monkeypatch: pytest.MonkeyPatch
) -> None:
    """N plain NeedsUnlock probes must never consume unlock budget (issue #93):
    every probe keeps surfacing 409, never degrading to 429."""
    monkeypatch.setenv("CREDENTIAL_UNLOCK_MAX_FAILURES", "2")
    monkeypatch.setenv("CREDENTIAL_UNLOCK_WINDOW_SECONDS", "60")

    with app_client_factory() as (client, _state):
        # Many more probes than max_failures -- none of them should count.
        for _ in range(10):
            resp = _probe(client)
            assert resp.status_code == 409, resp.text


def test_correct_passphrase_succeeds_after_probes(
    app_client_factory: Callable[..., object], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A correct-passphrase unlock after N NeedsUnlock probes must succeed --
    not be rejected with 429, since the probes never should have consumed any
    unlock budget in the first place (issue #93's failure scenario: the
    correct POST /v1/x509/proxy call also goes through cache.get() first)."""
    monkeypatch.setenv("CREDENTIAL_UNLOCK_MAX_FAILURES", "2")
    monkeypatch.setenv("CREDENTIAL_UNLOCK_WINDOW_SECONDS", "60")

    with app_client_factory() as (client, _state):
        client.app.state.x509_provider.backends = [_FakeSucceedingBackend()]

        for _ in range(5):
            assert _probe(client).status_code == 409

        resp = _unlock(client)
        assert resp.status_code == 201, resp.text


def test_genuinely_failed_unlocks_still_trip_the_limit(
    app_client_factory: Callable[..., object], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A real bad-passphrase attempt (minting backend fails and calls
    ``record_failed_unlock``) still counts, and still trips 429 once the
    threshold is exceeded."""
    monkeypatch.setenv("CREDENTIAL_UNLOCK_MAX_FAILURES", "2")
    monkeypatch.setenv("CREDENTIAL_UNLOCK_WINDOW_SECONDS", "60")

    with app_client_factory() as (client, _state):
        client.app.state.x509_provider.backends = [_FakeFailingBackend()]

        for _ in range(2):
            resp = _unlock(client)
            assert resp.status_code == 422, resp.text  # bad passphrase (fake)

        resp = _unlock(client)
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


def test_rate_limit_resets_after_successful_unlock(
    app_client_factory: Callable[..., object], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A successful unlock resets the failed-unlock counter, so a fresh round
    of failures is needed to trip the limit again."""
    monkeypatch.setenv("CREDENTIAL_UNLOCK_MAX_FAILURES", "2")
    monkeypatch.setenv("CREDENTIAL_UNLOCK_WINDOW_SECONDS", "60")

    with app_client_factory() as (client, _state):
        client.app.state.x509_provider.backends = [_FakeFailingBackend()]
        # One failure -- one short of the limit.
        assert _unlock(client).status_code == 422

        client.app.state.x509_provider.backends = [_FakeSucceedingBackend()]
        assert _unlock(client).status_code == 201

        # Burn the freshly-cached proxy so the next unlock actually reaches
        # the (now failing again) backend instead of serving from cache.
        assert client.delete("/v1/credential", headers=_AUTH).status_code == 204

        client.app.state.x509_provider.backends = [_FakeFailingBackend()]
        # If the counter hadn't reset, this single failure would trip the
        # limit (only one more was needed before the successful unlock).
        assert _unlock(client).status_code == 422
        assert _unlock(client).status_code == 422
        resp = _unlock(client)
        assert resp.status_code == 429, resp.text


def test_rate_limit_returns_429_with_retry_after(
    app_client_factory: Callable[..., object], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CREDENTIAL_UNLOCK_MAX_FAILURES", "2")
    monkeypatch.setenv("CREDENTIAL_UNLOCK_WINDOW_SECONDS", "60")

    with app_client_factory() as (client, _state):
        client.app.state.x509_provider.backends = [_FakeFailingBackend()]
        for _ in range(2):
            assert _unlock(client).status_code == 422
        resp = _unlock(client)

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
        client.app.state.x509_provider.backends = [_FakeFailingBackend()]
        assert _unlock(client).status_code == 422
        resp = _unlock(client)

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
