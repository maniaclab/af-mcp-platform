"""Tests for GET /v1/identities' ``providers`` list.

``providers`` reflects whatever ``identity_providers`` entries are
configured, in config order, uniform across both linking mechanisms:
Keycloak's stored-broker-token pattern (``OIDCProvider``) and the broker's
own direct OAuth 2.1 client (``OAuth21Provider``). These tests exercise
building that list: probing ``is_linked()`` so the response reflects reality
rather than a JWT claim that may be absent, ``link_url`` shape for both
provider types (always null for keycloak-brokered — issue #66 PR4), and
config-order preservation.
"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING
from urllib.parse import parse_qs, urlparse

import pytest
from cryptography.fernet import Fernet
from pydantic import SecretStr

if TYPE_CHECKING:
    from collections.abc import Callable

    from fastapi.testclient import TestClient

_AUTH = {"Authorization": "Bearer test"}

# Matches conftest.py's app_client_factory default `identity_providers` entry.
DEFAULT_KEYCLOAK_ALIAS = "atlas-oidc"

ALIAS = "rucio-mcp-atlas"
AUTHORIZATION_ENDPOINT = "https://backend-as.example/authorize"
TOKEN_ENDPOINT = "https://backend-as.example/token"
PROVIDER_ISSUER = "https://backend-as.example"


def _configure_oauth21_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BROKER_STATE_KEY", Fernet.generate_key().decode())
    monkeypatch.setenv("OAUTH21_CLIENT_ID", "https://mcp.example.com/.well-known/cimd")
    monkeypatch.setenv(
        "IDENTITY_PROVIDERS",
        json.dumps(
            [
                {
                    "type": "oauth21-direct",
                    "alias": ALIAS,
                    "targets": [ALIAS],
                    "authorization_endpoint": AUTHORIZATION_ENDPOINT,
                    "token_endpoint": TOKEN_ENDPOINT,
                    "issuer": PROVIDER_ISSUER,
                    "display_name": "Rucio (ATLAS)",
                    "enables": "ATLAS Rucio operations via rucio-mcp",
                }
            ]
        ),
    )


def _by_id(body: dict) -> dict[str, dict]:
    return {p["id"]: p for p in body["providers"]}


# ---------------------------------------------------------------------------
# keycloak-brokered providers
# ---------------------------------------------------------------------------


def test_keycloak_brokered_provider_reflects_is_linked_true(
    app_client: tuple[TestClient, dict], monkeypatch: pytest.MonkeyPatch
) -> None:
    from af_mcp_broker.credentials.oidc import OIDCProvider

    async def _linked(self, principal) -> bool:
        return True

    monkeypatch.setattr(OIDCProvider, "is_linked", _linked)

    client, _ = app_client
    resp = client.get("/v1/identities", headers=_AUTH)

    assert resp.status_code == 200, resp.text
    entry = _by_id(resp.json())[DEFAULT_KEYCLOAK_ALIAS]
    assert entry["type"] == "keycloak-brokered"
    assert entry["linked"] is True


def test_keycloak_brokered_provider_reflects_is_linked_false(
    app_client: tuple[TestClient, dict], monkeypatch: pytest.MonkeyPatch
) -> None:
    from af_mcp_broker.credentials.oidc import OIDCProvider

    async def _not_linked(self, principal) -> bool:
        return False

    monkeypatch.setattr(OIDCProvider, "is_linked", _not_linked)

    client, _ = app_client
    resp = client.get("/v1/identities", headers=_AUTH)

    assert resp.status_code == 200, resp.text
    entry = _by_id(resp.json())[DEFAULT_KEYCLOAK_ALIAS]
    assert entry["linked"] is False


def test_keycloak_brokered_provider_probes_not_jwt_claims(
    app_client_factory: Callable[..., object], make_principal: Callable[..., object]
) -> None:
    """A principal has no JWT-derived sub claim to carry any more (the fields
    were removed from Principal entirely) — the linked flag must still be
    accurate, built purely from the is_linked() probe."""
    from af_mcp_broker.credentials.oidc import OIDCProvider

    async def _linked(self, principal) -> bool:
        return True

    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr(OIDCProvider, "is_linked", _linked)
        with app_client_factory() as (client, state):
            state["principal"] = make_principal(groups=[])
            resp = client.get("/v1/identities", headers=_AUTH)

    assert resp.status_code == 200, resp.text
    entry = _by_id(resp.json())[DEFAULT_KEYCLOAK_ALIAS]
    assert entry["linked"] is True


def test_keycloak_brokered_link_url_always_null(
    app_client: tuple[TestClient, dict],
) -> None:
    """Per issue #66 PR4, keycloak-brokered link_urls are unconditionally
    null — the portal re-runs its own client-side startIdpLink() flow for
    these instead of navigating to a broker-built URL."""
    client, _ = app_client
    resp = client.get("/v1/identities", headers=_AUTH)

    assert resp.status_code == 200, resp.text
    entry = _by_id(resp.json())[DEFAULT_KEYCLOAK_ALIAS]
    assert entry["link_url"] is None


# ---------------------------------------------------------------------------
# OAuth 2.1-direct providers
# ---------------------------------------------------------------------------


def test_oauth21_provider_absent_when_not_configured(
    app_client: tuple[TestClient, dict],
) -> None:
    client, _ = app_client
    resp = client.get("/v1/identities", headers=_AUTH)

    assert resp.status_code == 200, resp.text
    types = {p["type"] for p in resp.json()["providers"]}
    assert "oauth21-direct" not in types


def test_oauth21_provider_present_with_metadata_and_link_url(
    monkeypatch: pytest.MonkeyPatch, app_client_factory: Callable[..., object]
) -> None:
    _configure_oauth21_env(monkeypatch)

    with app_client_factory() as (client, _state):
        resp = client.get("/v1/identities", headers=_AUTH)

    assert resp.status_code == 200, resp.text
    entry = _by_id(resp.json())[ALIAS]
    assert entry["type"] == "oauth21-direct"
    assert entry["display_name"] == "Rucio (ATLAS)"
    assert entry["enables"] == "ATLAS Rucio operations via rucio-mcp"
    assert entry["linked"] is False

    parsed = urlparse(entry["link_url"])
    assert parsed.path == f"/v1/oauth/authorize/{ALIAS}"
    assert parse_qs(parsed.query)["return"] == ["/identities/"]
    # Full URL, not a bare path — the portal is served from a different
    # origin than the broker.
    assert parsed.scheme
    assert parsed.netloc


def test_oauth21_provider_linked_reflects_token_store_state(
    monkeypatch: pytest.MonkeyPatch, app_client_factory: Callable[..., object]
) -> None:
    from af_mcp_broker.app import app as broker_app
    from af_mcp_broker.credentials.oauth21 import StoredOAuthCredential

    _configure_oauth21_env(monkeypatch)

    with app_client_factory() as (client, state):
        subject = state["principal"].subject
        store = broker_app.state.oauth21_token_store
        cred = StoredOAuthCredential(
            alias=ALIAS,
            subject=subject,
            access_token=SecretStr("access-token"),
            refresh_token=SecretStr("refresh-token"),
            expires_at=datetime.now(UTC) + timedelta(hours=1),
            refresh_expires_at=datetime.now(UTC) + timedelta(days=30),
            scope=["openid"],
            issuer=PROVIDER_ISSUER,
            token_endpoint=TOKEN_ENDPOINT,
        )
        asyncio.run(store.write_cas(subject, ALIAS, cred, expected_version=None))

        resp = client.get("/v1/identities", headers=_AUTH)

    assert resp.status_code == 200, resp.text
    entry = _by_id(resp.json())[ALIAS]
    assert entry["linked"] is True


# ---------------------------------------------------------------------------
# Config-order preservation
# ---------------------------------------------------------------------------


def test_providers_order_matches_identity_providers_config_order(
    monkeypatch: pytest.MonkeyPatch, app_client_factory: Callable[..., object]
) -> None:
    """The response's providers list must reflect identity_providers' config
    order, not grouped by type — Python dicts preserve insertion order, and
    app.py's lifespan populates app.state.identity_providers by iterating
    identity_providers in order, so this is structural rather than an
    explicit sort."""
    monkeypatch.setenv("BROKER_STATE_KEY", Fernet.generate_key().decode())
    monkeypatch.setenv("OAUTH21_CLIENT_ID", "https://mcp.example.com/.well-known/cimd")
    monkeypatch.setenv(
        "IDENTITY_PROVIDERS",
        json.dumps(
            [
                {
                    "type": "oauth21-direct",
                    "alias": "z-oauth21-provider",
                    "targets": ["z-oauth21-provider"],
                    "authorization_endpoint": AUTHORIZATION_ENDPOINT,
                    "token_endpoint": TOKEN_ENDPOINT,
                    "issuer": PROVIDER_ISSUER,
                },
                {
                    "type": "keycloak-brokered",
                    "alias": "a-keycloak-provider",
                    "targets": ["a-keycloak-provider"],
                },
            ]
        ),
    )

    with app_client_factory() as (client, _state):
        resp = client.get("/v1/identities", headers=_AUTH)

    assert resp.status_code == 200, resp.text
    ids = [p["id"] for p in resp.json()["providers"]]
    assert ids == ["z-oauth21-provider", "a-keycloak-provider"]


# ---------------------------------------------------------------------------
# DELETE /v1/identities/link/{provider}
# ---------------------------------------------------------------------------


def test_unlink_unknown_provider_returns_422(
    app_client: tuple[TestClient, dict],
) -> None:
    client, _ = app_client
    resp = client.delete("/v1/identities/link/not-a-real-provider", headers=_AUTH)
    assert resp.status_code == 422


def test_unlink_known_keycloak_provider_returns_501(
    app_client: tuple[TestClient, dict],
) -> None:
    client, _ = app_client
    resp = client.delete(f"/v1/identities/link/{DEFAULT_KEYCLOAK_ALIAS}", headers=_AUTH)
    assert resp.status_code == 501


def test_unlink_known_oauth21_alias_returns_501(
    monkeypatch: pytest.MonkeyPatch, app_client_factory: Callable[..., object]
) -> None:
    _configure_oauth21_env(monkeypatch)

    with app_client_factory() as (client, _state):
        resp = client.delete(f"/v1/identities/link/{ALIAS}", headers=_AUTH)

    assert resp.status_code == 501
