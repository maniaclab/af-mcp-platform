"""Tests for POST/GET/DELETE /v1/tokens — manual bearer bootstrap (issue #24)
and its Vault-backed registry + enforced revocation (issue #115).

These exercise the real app through ``app_client``/``app_client_factory``
(see conftest.py); the Keycloak token-exchange call is faked via
monkeypatching ``af_mcp_broker.api.tokens.get_http_client`` so no network call
ever happens. Every test that mints a token sets TOKEN_MINT_CLIENT_ID/SECRET
so the endpoint doesn't short-circuit with 503.
"""

from __future__ import annotations

import re
import time
from typing import TYPE_CHECKING, Any

import jwt
import pytest

from af_mcp_broker.api import tokens as tokens_module

if TYPE_CHECKING:
    from collections.abc import Callable

    from fastapi.testclient import TestClient

_AUTH = {"Authorization": "Bearer test"}

# A JWT looks like three base64url segments joined by dots. Used to assert
# list/detail payloads never carry a token-shaped string anywhere (issue #115
# requirement 1) -- not just that the "token" key is absent.
_JWT_SHAPED = re.compile(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")


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
    """Fakes the token-exchange POST tokens.py makes."""

    def __init__(self, *, mint_status: int = 200, ttl_seconds: int = 3600) -> None:
        self.mint_status = mint_status
        self.ttl_seconds = ttl_seconds
        self.mint_calls: list[dict[str, Any]] = []

    async def post(
        self, url: str, *, data: dict[str, Any], **kwargs: Any
    ) -> _FakeResponse:
        assert (
            data.get("grant_type") == "urn:ietf:params:oauth:grant-type:token-exchange"
        )
        self.mint_calls.append(data)
        if self.mint_status >= 400:
            return _FakeResponse(self.mint_status, {})
        token = _make_kc_access_token(ttl_seconds=self.ttl_seconds)
        return _FakeResponse(200, {"access_token": token})


@pytest.fixture
def fake_keycloak(monkeypatch: pytest.MonkeyPatch) -> _FakeKeycloakClient:
    """Install a fake Keycloak client and the client-credential env vars."""
    fake = _FakeKeycloakClient()
    monkeypatch.setattr(tokens_module, "get_http_client", lambda: fake)
    monkeypatch.setenv("TOKEN_MINT_CLIENT_ID", "test-mint-client")
    monkeypatch.setenv("TOKEN_MINT_CLIENT_SECRET", "test-mint-secret")
    return fake


def _mint(
    client: TestClient, *, ttl_seconds: int = 3600, name: str | None = "claude-desktop"
):
    body: dict[str, Any] = {"ttl_seconds": ttl_seconds}
    if name is not None:
        body["name"] = name
    return client.post("/v1/tokens", json=body, headers=_AUTH)


def test_mint_happy_path(
    app_client: tuple[TestClient, dict], fake_keycloak: _FakeKeycloakClient
) -> None:
    client, _ = app_client
    resp = _mint(client, ttl_seconds=3600, name="claude-desktop")

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert isinstance(body["token"], str)
    assert body["token"]
    assert isinstance(body["jti"], str)
    assert body["jti"]
    assert body["name"] == "claude-desktop"
    assert "issued_at" in body
    assert "expires_at" in body


def test_mint_without_name_generates_a_default(
    app_client: tuple[TestClient, dict], fake_keycloak: _FakeKeycloakClient
) -> None:
    client, _ = app_client
    resp = _mint(client, name=None)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["name"].startswith("mcp-")
    assert body["jti"][:8] in body["name"]


def test_mint_rejects_name_above_max_length(
    app_client: tuple[TestClient, dict], fake_keycloak: _FakeKeycloakClient
) -> None:
    client, _ = app_client
    resp = _mint(client, name="x" * 201)
    assert resp.status_code == 422, resp.text


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
        resp = _mint(client, name=f"token-{i}")
        assert resp.status_code == 200, resp.text

    resp = _mint(client, name="eleventh")
    assert resp.status_code == 429, resp.text


def test_list_returns_own_tokens_only(
    app_client: tuple[TestClient, dict],
    fake_keycloak: _FakeKeycloakClient,
    make_principal: Callable[..., object],
) -> None:
    client, state = app_client
    mint_resp = _mint(client, name="mine")
    assert mint_resp.status_code == 200, mint_resp.text

    listed = client.get("/v1/tokens", headers=_AUTH)
    assert listed.status_code == 200, listed.text
    rows = listed.json()
    assert len(rows) == 1
    assert rows[0]["name"] == "mine"
    assert rows[0]["source"] == "manual"
    assert "token" not in rows[0]  # never re-exposed

    # A different uid must never see the first user's tokens.
    state["principal"] = make_principal(uid=99999, groups=["atlas"])
    listed_other = client.get("/v1/tokens", headers=_AUTH)
    assert listed_other.status_code == 200, listed_other.text
    assert listed_other.json() == []


def test_list_and_mint_responses_never_leak_a_jwt_shaped_string(
    app_client: tuple[TestClient, dict], fake_keycloak: _FakeKeycloakClient
) -> None:
    """issue #115 requirement 1: the registry never re-exposes anything a
    token could be reconstructed from. Scan the *raw* response bodies (not
    just specific keys) so a renamed or newly-added field can't silently
    smuggle a token value back out."""
    client, _ = app_client
    mint_resp = _mint(client, name="scan-me")
    assert mint_resp.status_code == 200, mint_resp.text
    minted_token = mint_resp.json()["token"]
    assert _JWT_SHAPED.search(minted_token)  # sanity: our fake token IS jwt-shaped

    listed = client.get("/v1/tokens", headers=_AUTH)
    assert listed.status_code == 200, listed.text
    assert not _JWT_SHAPED.search(listed.text)

    jti = mint_resp.json()["jti"]
    revoke_resp = client.delete(f"/v1/tokens/{jti}", headers=_AUTH)
    assert not _JWT_SHAPED.search(revoke_resp.text)


def test_revoke_success_then_list_shows_revoked_row(
    app_client: tuple[TestClient, dict], fake_keycloak: _FakeKeycloakClient
) -> None:
    """issue #115 changes revoke from "remove the row" (PR #28) to "mark it
    revoked" -- the portal now needs to show a revoked/active/expired status,
    which requires the row to still be listed."""
    client, _ = app_client
    mint_resp = _mint(client, name="to-revoke")
    jti = mint_resp.json()["jti"]

    revoke_resp = client.delete(f"/v1/tokens/{jti}", headers=_AUTH)
    assert revoke_resp.status_code == 200, revoke_resp.text
    assert revoke_resp.json()["jti"] == jti
    assert revoke_resp.json()["revoked"] is True

    listed = client.get("/v1/tokens", headers=_AUTH)
    assert listed.status_code == 200, listed.text
    rows = listed.json()
    assert len(rows) == 1
    assert rows[0]["jti"] == jti
    assert rows[0]["revoked_at"] is not None


def test_revoke_non_owned_jti_403(
    app_client: tuple[TestClient, dict],
    fake_keycloak: _FakeKeycloakClient,
    make_principal: Callable[..., object],
) -> None:
    client, state = app_client
    mint_resp = _mint(client, name="owned-by-first-user")
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


def test_mint_upstream_unreachable_returns_502(
    app_client: tuple[TestClient, dict], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression: a connection failure to Keycloak must surface as a clean
    502, not an unhandled 500 (caught this via manual smoke testing against
    a broker with no Keycloak listening)."""

    class _UnreachableClient:
        async def post(self, *args: object, **kwargs: object) -> None:
            raise ConnectionError("all connection attempts failed")

    monkeypatch.setattr(tokens_module, "get_http_client", _UnreachableClient)
    monkeypatch.setenv("TOKEN_MINT_CLIENT_ID", "test-mint-client")
    monkeypatch.setenv("TOKEN_MINT_CLIENT_SECRET", "test-mint-secret")

    client, _ = app_client
    resp = _mint(client)
    assert resp.status_code == 502, resp.text


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


def test_revoke_marks_jti_in_the_apps_revoked_registry(
    app_client: tuple[TestClient, dict], fake_keycloak: _FakeKeycloakClient
) -> None:
    """Confirms DELETE /v1/tokens/{jti} actually reaches the same
    token_registry app.state wires into identity's revocation check --
    end-to-end enforcement itself (a revoked jti rejecting a real Bearer) is
    covered directly against get_principal/IdentityMiddleware in
    test_identity.py and test_mcp_middleware_identity.py, which control a
    real RSA-signed JWT + primed JWKS the way this fixture's dependency
    override does not."""
    from af_mcp_broker.app import app

    client, _ = app_client
    mint_resp = _mint(client, name="to-be-revoked")
    jti = mint_resp.json()["jti"]

    client.delete(f"/v1/tokens/{jti}", headers=_AUTH)

    import asyncio

    revoked = asyncio.run(app.state.token_registry._backend.list_revoked_jtis())
    assert jti in revoked
