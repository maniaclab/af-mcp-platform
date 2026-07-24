"""Tests for GET /v1/identities' ``providers`` list.

``providers`` flattens the old ``linked_accounts``/``available_providers``
split into one list, uniform across both linking mechanisms: Keycloak's
stored-broker-token pattern (``OIDCProvider``) and the broker's own direct
OAuth 2.1 client (``OAuth21Provider``). These tests exercise
building that list: probing ``is_linked()`` so the response reflects reality
rather than a JWT claim that may be absent, ``link_url`` shape for both
provider types, and the degraded-config cases where ``link_url`` is null.
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

ALIAS = "rucio-mcp-atlas"
AUTHORIZATION_ENDPOINT = "https://backend-as.example/authorize"
TOKEN_ENDPOINT = "https://backend-as.example/token"
PROVIDER_ISSUER = "https://backend-as.example"


def _configure_oauth21_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BROKER_STATE_KEY", Fernet.generate_key().decode())
    monkeypatch.setenv("OAUTH21_CLIENT_ID", "https://mcp.example.com/.well-known/cimd")
    monkeypatch.setenv("CIMD_IDP_ALIASES", json.dumps([ALIAS]))
    monkeypatch.setenv(
        "OAUTH21_PROVIDERS",
        json.dumps(
            [
                {
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


def _keycloak_entries(body: dict) -> dict[str, dict]:
    return {p["id"]: p for p in body["providers"] if p["type"] == "keycloak-brokered"}


def _oauth21_entries(body: dict) -> dict[str, dict]:
    return {p["id"]: p for p in body["providers"] if p["type"] == "oauth21-direct"}


# ---------------------------------------------------------------------------
# Keycloak-brokered providers
# ---------------------------------------------------------------------------


def test_providers_reflects_is_linked_true(
    app_client: tuple[TestClient, dict], monkeypatch: pytest.MonkeyPatch
) -> None:
    from af_mcp_broker.credentials.oidc import OIDCProvider

    async def _linked(self, principal) -> bool:
        return True

    monkeypatch.setattr(OIDCProvider, "is_linked", _linked)

    client, _ = app_client
    resp = client.get("/v1/identities", headers=_AUTH)

    assert resp.status_code == 200, resp.text
    body = resp.json()
    kc = _keycloak_entries(body)
    assert kc["atlas-iam"]["linked"] is True
    assert kc["cern"]["linked"] is False


def test_providers_empty_when_not_linked(
    app_client: tuple[TestClient, dict], monkeypatch: pytest.MonkeyPatch
) -> None:
    from af_mcp_broker.credentials.oidc import OIDCProvider

    async def _not_linked(self, principal) -> bool:
        return False

    monkeypatch.setattr(OIDCProvider, "is_linked", _not_linked)

    client, _ = app_client
    resp = client.get("/v1/identities", headers=_AUTH)

    assert resp.status_code == 200, resp.text
    body = resp.json()
    kc = _keycloak_entries(body)
    assert kc["atlas-iam"]["linked"] is False
    assert kc["cern"]["linked"] is False


def test_providers_probes_not_jwt_claims(
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
    body = resp.json()
    kc = _keycloak_entries(body)
    assert kc["atlas-iam"]["linked"] is True
    assert kc["cern"]["linked"] is False


def test_atlas_iam_link_url_null_when_client_id_unset(
    app_client: tuple[TestClient, dict],
) -> None:
    # identities_link_client_id defaults to "" — app_client_factory doesn't
    # set IDENTITIES_LINK_CLIENT_ID.
    client, _ = app_client
    resp = client.get("/v1/identities", headers=_AUTH)

    assert resp.status_code == 200, resp.text
    kc = _keycloak_entries(resp.json())
    assert kc["atlas-iam"]["link_url"] is None


def test_atlas_iam_link_url_set_when_client_id_configured(
    monkeypatch: pytest.MonkeyPatch, app_client_factory: Callable[..., object]
) -> None:
    monkeypatch.setenv("IDENTITIES_LINK_CLIENT_ID", "mcp-portal")

    with app_client_factory() as (client, _state):
        resp = client.get("/v1/identities", headers=_AUTH)

    assert resp.status_code == 200, resp.text
    kc = _keycloak_entries(resp.json())
    link_url = kc["atlas-iam"]["link_url"]
    assert link_url is not None
    parsed = urlparse(link_url)
    assert parsed.path.endswith("/protocol/openid-connect/auth")
    query = parse_qs(parsed.query)
    assert query["client_id"] == ["mcp-portal"]
    assert query["kc_action"] == ["LINK_IDP"]
    assert query["provider_id"] == ["atlas-oidc"]
    assert query["redirect_uri"] == ["https://mcp-portal.af.uchicago.edu/callback"]


def test_cern_link_url_always_null_even_when_client_id_configured(
    monkeypatch: pytest.MonkeyPatch, app_client_factory: Callable[..., object]
) -> None:
    """cern has no real backing IdP — it's a placeholder, no link possible."""
    monkeypatch.setenv("IDENTITIES_LINK_CLIENT_ID", "mcp-portal")

    with app_client_factory() as (client, _state):
        resp = client.get("/v1/identities", headers=_AUTH)

    assert resp.status_code == 200, resp.text
    kc = _keycloak_entries(resp.json())
    assert kc["cern"]["link_url"] is None


# ---------------------------------------------------------------------------
# OAuth 2.1-direct providers
# ---------------------------------------------------------------------------


def test_oauth21_provider_absent_when_not_configured(
    app_client: tuple[TestClient, dict],
) -> None:
    client, _ = app_client
    resp = client.get("/v1/identities", headers=_AUTH)

    assert resp.status_code == 200, resp.text
    assert _oauth21_entries(resp.json()) == {}


def test_oauth21_provider_present_with_metadata_and_link_url(
    monkeypatch: pytest.MonkeyPatch, app_client_factory: Callable[..., object]
) -> None:
    _configure_oauth21_env(monkeypatch)

    with app_client_factory() as (client, _state):
        resp = client.get("/v1/identities", headers=_AUTH)

    assert resp.status_code == 200, resp.text
    entries = _oauth21_entries(resp.json())
    entry = entries[ALIAS]
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
    entries = _oauth21_entries(resp.json())
    assert entries[ALIAS]["linked"] is True


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
    resp = client.delete("/v1/identities/link/atlas-iam", headers=_AUTH)
    assert resp.status_code == 501


def test_unlink_known_oauth21_alias_returns_501(
    monkeypatch: pytest.MonkeyPatch, app_client_factory: Callable[..., object]
) -> None:
    _configure_oauth21_env(monkeypatch)

    with app_client_factory() as (client, _state):
        resp = client.delete(f"/v1/identities/link/{ALIAS}", headers=_AUTH)

    assert resp.status_code == 501
