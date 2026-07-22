"""Tests for POST/GET/DELETE /v1/tokens — manual bearer bootstrap (issue #24).

These exercise the real app through ``app_client``/``app_client_factory``
(see conftest.py); the Keycloak token-exchange and revoke calls are faked via
monkeypatching ``af_mcp_broker.api.tokens.get_http_client`` so no network call
ever happens. Every test that mints a token sets TOKEN_MINT_CLIENT_ID/SECRET
so the endpoint doesn't short-circuit with 503.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any

import jwt
import pytest

from af_mcp_broker.api import tokens as tokens_module

if TYPE_CHECKING:
    from collections.abc import Callable

    from fastapi.testclient import TestClient

_AUTH = {"Authorization": "Bearer test"}


def _make_kc_access_token(*, ttl_seconds: int = 3600, jti: str | None = None) -> str:
    """Build an unsigned-for-test-purposes JWT shaped like a Keycloak access token.

    tokens.py decodes the returned token with signature verification disabled
    (it trusts the transport, not the token itself, since Keycloak handed it
    back directly) — so any signing key works here.
    """
    now = int(time.time())
    claims: dict[str, Any] = {"iat": now, "exp": now + ttl_seconds}
    if jti is not None:
        claims["jti"] = jti
    return jwt.encode(
        claims, "test-signing-key-that-is-long-enough-for-hs256", algorithm="HS256"
    )


class _FakeResponse:
    def __init__(self, status_code: int, payload: dict[str, Any]) -> None:
        self.status_code = status_code
        self._payload = payload

    def json(self) -> dict[str, Any]:
        return self._payload


class _FakeKeycloakClient:
    """Fakes both the token-exchange and revoke POSTs tokens.py makes."""

    def __init__(self, *, mint_status: int = 200, ttl_seconds: int = 3600) -> None:
        self.mint_status = mint_status
        self.ttl_seconds = ttl_seconds
        self.revoke_calls: list[dict[str, Any]] = []
        self.mint_calls: list[dict[str, Any]] = []

    async def post(
        self, url: str, *, data: dict[str, Any], **kwargs: Any
    ) -> _FakeResponse:
        if data.get("grant_type") == "urn:ietf:params:oauth:grant-type:token-exchange":
            self.mint_calls.append(data)
            if self.mint_status >= 400:
                return _FakeResponse(self.mint_status, {})
            token = _make_kc_access_token(ttl_seconds=self.ttl_seconds)
            return _FakeResponse(200, {"access_token": token})
        # Revocation call (RFC 7009)
        self.revoke_calls.append(data)
        return _FakeResponse(200, {})


@pytest.fixture
def fake_keycloak(monkeypatch: pytest.MonkeyPatch) -> _FakeKeycloakClient:
    """Install a fake Keycloak client and the client-credential env vars."""
    fake = _FakeKeycloakClient()
    monkeypatch.setattr(tokens_module, "get_http_client", lambda: fake)
    monkeypatch.setenv("TOKEN_MINT_CLIENT_ID", "test-mint-client")
    monkeypatch.setenv("TOKEN_MINT_CLIENT_SECRET", "test-mint-secret")
    return fake


def _mint(
    client: TestClient, *, ttl_seconds: int = 3600, note: str | None = "claude-desktop"
):
    body: dict[str, Any] = {"ttl_seconds": ttl_seconds}
    if note is not None:
        body["note"] = note
    return client.post("/v1/tokens", json=body, headers=_AUTH)


def test_mint_happy_path(
    app_client: tuple[TestClient, dict], fake_keycloak: _FakeKeycloakClient
) -> None:
    client, _ = app_client
    resp = _mint(client, ttl_seconds=3600, note="claude-desktop")

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert isinstance(body["token"], str)
    assert body["token"]
    assert isinstance(body["jti"], str)
    assert body["jti"]
    assert body["note"] == "claude-desktop"
    assert "issued_at" in body
    assert "expires_at" in body


def test_mint_without_client_credentials_configured_returns_503(
    app_client: tuple[TestClient, dict], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("TOKEN_MINT_CLIENT_ID", raising=False)
    monkeypatch.delenv("TOKEN_MINT_CLIENT_SECRET", raising=False)
    client, _ = app_client
    resp = _mint(client)
    assert resp.status_code == 503, resp.text


def test_mint_rejects_ttl_above_max(
    app_client: tuple[TestClient, dict], fake_keycloak: _FakeKeycloakClient
) -> None:
    client, _ = app_client
    resp = _mint(client, ttl_seconds=86401)
    assert resp.status_code == 422, resp.text


def test_mint_rate_limit_11th_call_429(
    app_client: tuple[TestClient, dict], fake_keycloak: _FakeKeycloakClient
) -> None:
    client, _ = app_client
    for i in range(10):
        resp = _mint(client, note=f"token-{i}")
        assert resp.status_code == 200, resp.text

    resp = _mint(client, note="eleventh")
    assert resp.status_code == 429, resp.text


def test_list_returns_own_tokens_only(
    app_client: tuple[TestClient, dict],
    fake_keycloak: _FakeKeycloakClient,
    make_principal: Callable[..., object],
) -> None:
    client, state = app_client
    mint_resp = _mint(client, note="mine")
    assert mint_resp.status_code == 200, mint_resp.text

    listed = client.get("/v1/tokens", headers=_AUTH)
    assert listed.status_code == 200, listed.text
    rows = listed.json()
    assert len(rows) == 1
    assert rows[0]["note"] == "mine"
    assert rows[0]["source"] == "manual"
    assert "token" not in rows[0]  # never re-exposed

    # A different uid must never see the first user's tokens.
    state["principal"] = make_principal(uid=99999, groups=["atlas"])
    listed_other = client.get("/v1/tokens", headers=_AUTH)
    assert listed_other.status_code == 200, listed_other.text
    assert listed_other.json() == []


def test_revoke_success_then_list_omits_row(
    app_client: tuple[TestClient, dict], fake_keycloak: _FakeKeycloakClient
) -> None:
    client, _ = app_client
    mint_resp = _mint(client, note="to-revoke")
    jti = mint_resp.json()["jti"]

    revoke_resp = client.delete(f"/v1/tokens/{jti}", headers=_AUTH)
    assert revoke_resp.status_code == 200, revoke_resp.text
    assert revoke_resp.json()["jti"] == jti

    listed = client.get("/v1/tokens", headers=_AUTH)
    assert listed.status_code == 200, listed.text
    assert listed.json() == []


def test_revoke_non_owned_jti_403(
    app_client: tuple[TestClient, dict],
    fake_keycloak: _FakeKeycloakClient,
    make_principal: Callable[..., object],
) -> None:
    client, state = app_client
    mint_resp = _mint(client, note="owned-by-first-user")
    jti = mint_resp.json()["jti"]

    state["principal"] = make_principal(uid=99999, groups=["atlas"])
    revoke_resp = client.delete(f"/v1/tokens/{jti}", headers=_AUTH)
    assert revoke_resp.status_code == 403, revoke_resp.text


def test_revoke_unknown_jti_404(
    app_client: tuple[TestClient, dict], fake_keycloak: _FakeKeycloakClient
) -> None:
    client, _ = app_client
    resp = client.delete("/v1/tokens/does-not-exist", headers=_AUTH)
    assert resp.status_code == 404, resp.text


def test_mint_falls_back_to_synthetic_jti_when_keycloak_omits_one(
    app_client: tuple[TestClient, dict], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Keycloak access tokens are not guaranteed to carry a `jti` claim; the
    broker must still hand back something list/revoke can key on."""
    fake = _FakeKeycloakClient()
    monkeypatch.setattr(tokens_module, "get_http_client", lambda: fake)
    monkeypatch.setenv("TOKEN_MINT_CLIENT_ID", "test-mint-client")
    monkeypatch.setenv("TOKEN_MINT_CLIENT_SECRET", "test-mint-secret")

    client, _ = app_client
    resp = _mint(client)
    assert resp.status_code == 200, resp.text
    assert resp.json()["jti"]
