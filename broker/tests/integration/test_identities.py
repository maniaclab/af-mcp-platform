"""Tests for GET /v1/identities' ``providers`` list.

``providers`` reflects whatever ``identity_providers`` entries are
configured, in config order, uniform across both linking mechanisms:
Keycloak's stored-broker-token pattern (``OIDCProvider``) and the broker's
own direct OAuth 2.1 client (``OAuth21Provider``). x509 is an ordinary entry
too: every backend wired with ``auth_type: x509`` must be covered by an
explicit entry (app.py's lifespan refuses to start otherwise — there is no
synthesized fallback), so the x509 row is always registry-sourced like every
other. conftest.py's ``app_client``/``app_client_factory`` default supplies
a minimal entry (alias "x509", targets ["ami"]) covering the
shipped services.yaml's x509 backend, which is what the x509-specific tests
below exercise. These tests cover building that list: probing
``is_linked()`` so the response reflects reality rather than a JWT claim
that may be absent, ``link_url`` shape for both provider types (always null
for keycloak-brokered — issue #66 PR4), ``link_mechanism`` per type, and
config-order preservation.
"""

from __future__ import annotations

import asyncio
import json
import time
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING
from urllib.parse import parse_qs, urlparse

import httpx2
import pytest
from cryptography.fernet import Fernet
from pydantic import SecretStr
from x509_fakes import FakeX509Store

from af_mcp_broker.app import app as broker_app
from af_mcp_broker.credentials.cache import ProxyMeta
from af_mcp_broker.credentials.oauth21 import StoredOAuthCredential
from af_mcp_broker.credentials.oidc import OIDCLinkStatus, OIDCProvider

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

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
    monkeypatch.setenv("BROKER_PUBLIC_ORIGIN", "https://mcp-portal.example.com")
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
                },
                # This override replaces conftest's default entirely, but
                # the shipped services.yaml's "ami" (auth_type: x509) still
                # needs an explicit entry or the broker refuses to start.
                {
                    "type": "x509",
                    "voms": "atlas",
                    "service_url": "http://voms-token-service.invalid:8000",
                    "alias": "x509",
                    "targets": ["ami"],
                },
            ]
        ),
    )


def _by_id(body: dict) -> dict[str, dict]:
    return {p["id"]: p for p in body["providers"]}


# ---------------------------------------------------------------------------
# POSIX identity is optional (issue #148)
# ---------------------------------------------------------------------------


def test_get_identities_succeeds_with_no_posix_identity(
    app_client: tuple[TestClient, dict], make_principal: Callable[..., object]
) -> None:
    """A principal with no POSIX identity (e.g. a bearer-only user once the
    operator drops the JWT `posix` claim) must still get a working GET
    /v1/identities response, with uid/gid/unixname simply null."""
    client, state = app_client
    state["principal"] = make_principal(
        groups=["atlas"], uid=None, gid=None, unixname=None
    )

    resp = client.get("/v1/identities", headers=_AUTH)

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["uid"] is None
    assert body["gid"] is None
    assert body["unixname"] is None


# ---------------------------------------------------------------------------
# is_admin
# ---------------------------------------------------------------------------


def test_is_admin_true_for_admin_group_member(
    monkeypatch: pytest.MonkeyPatch,
    app_client_factory: Callable[..., object],
    make_principal: Callable[..., object],
) -> None:
    monkeypatch.setenv("ADMIN_GROUP", "af-admins")

    with app_client_factory() as (client, state):
        state["principal"] = make_principal(groups=["atlas", "af-admins"])
        resp = client.get("/v1/identities", headers=_AUTH)

    assert resp.status_code == 200, resp.text
    assert resp.json()["is_admin"] is True


def test_is_admin_false_for_non_admin_group_member(
    monkeypatch: pytest.MonkeyPatch,
    app_client_factory: Callable[..., object],
    make_principal: Callable[..., object],
) -> None:
    monkeypatch.setenv("ADMIN_GROUP", "af-admins")

    with app_client_factory() as (client, state):
        state["principal"] = make_principal(groups=["atlas"])
        resp = client.get("/v1/identities", headers=_AUTH)

    assert resp.status_code == 200, resp.text
    assert resp.json()["is_admin"] is False


# ---------------------------------------------------------------------------
# keycloak-brokered providers
# ---------------------------------------------------------------------------


def test_keycloak_brokered_provider_reflects_is_linked_true(
    app_client: tuple[TestClient, dict], monkeypatch: pytest.MonkeyPatch
) -> None:

    async def _linked(self, principal) -> OIDCLinkStatus:
        return OIDCLinkStatus(linked=True, permission_denied=False)

    monkeypatch.setattr(OIDCProvider, "link_status", _linked)

    client, _ = app_client
    resp = client.get("/v1/identities", headers=_AUTH)

    assert resp.status_code == 200, resp.text
    entry = _by_id(resp.json())[DEFAULT_KEYCLOAK_ALIAS]
    assert entry["type"] == "keycloak-brokered"
    assert entry["linked"] is True
    assert entry["link_permission_denied"] is False


def test_keycloak_brokered_provider_reflects_is_linked_false(
    app_client: tuple[TestClient, dict], monkeypatch: pytest.MonkeyPatch
) -> None:

    async def _not_linked(self, principal) -> OIDCLinkStatus:
        return OIDCLinkStatus(linked=False, permission_denied=False)

    monkeypatch.setattr(OIDCProvider, "link_status", _not_linked)

    client, _ = app_client
    resp = client.get("/v1/identities", headers=_AUTH)

    assert resp.status_code == 200, resp.text
    entry = _by_id(resp.json())[DEFAULT_KEYCLOAK_ALIAS]
    assert entry["linked"] is False
    assert entry["link_permission_denied"] is False


def test_keycloak_brokered_provider_reflects_permission_denied(
    app_client: tuple[TestClient, dict], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A 403 from Keycloak's broker endpoint (caller lacks `read-token`)
    surfaces as link_permission_denied=True, distinct from an ordinary
    not-yet-linked False — so the portal can tell the user why, instead of
    an indistinguishable "not linked" for someone who may have already
    completed the IdP linking flow."""

    async def _permission_denied(self, principal) -> OIDCLinkStatus:
        return OIDCLinkStatus(linked=False, permission_denied=True)

    monkeypatch.setattr(OIDCProvider, "link_status", _permission_denied)

    client, _ = app_client
    resp = client.get("/v1/identities", headers=_AUTH)

    assert resp.status_code == 200, resp.text
    entry = _by_id(resp.json())[DEFAULT_KEYCLOAK_ALIAS]
    assert entry["linked"] is False
    assert entry["link_permission_denied"] is True


def test_keycloak_brokered_provider_probes_not_jwt_claims(
    app_client_factory: Callable[..., object], make_principal: Callable[..., object]
) -> None:
    """A principal carries no JWT-derived sub claim (Principal has no such
    field) — the linked flag must still be
    accurate, built purely from the link_status() probe."""

    async def _linked(self, principal) -> OIDCLinkStatus:
        return OIDCLinkStatus(linked=True, permission_denied=False)

    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr(OIDCProvider, "link_status", _linked)
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

    _configure_oauth21_env(monkeypatch)

    with app_client_factory() as (client, state):
        subject = state["principal"].subject
        store = broker_app.state.broker.oauth21_token_store
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


def test_oauth21_provider_rejected_credential_is_unlinked_and_flagged_rejected(
    monkeypatch: pytest.MonkeyPatch, app_client_factory: Callable[..., object]
) -> None:
    """A credential a backend rejected is stored but unusable: ``linked``
    stays false (its meaning is unchanged) and ``rejected`` says why."""

    _configure_oauth21_env(monkeypatch)

    with app_client_factory() as (client, state):
        subject = state["principal"].subject
        store = broker_app.state.broker.oauth21_token_store
        cred = StoredOAuthCredential(
            alias=ALIAS,
            subject=subject,
            access_token=SecretStr("access-token"),
            refresh_token=None,
            expires_at=datetime.now(UTC) + timedelta(hours=1),
            refresh_expires_at=None,
            scope=["openid"],
            issuer=PROVIDER_ISSUER,
            token_endpoint=TOKEN_ENDPOINT,
            rejected_at=datetime.now(UTC),
        )
        asyncio.run(store.write_cas(subject, ALIAS, cred, expected_version=None))

        resp = client.get("/v1/identities", headers=_AUTH)

    assert resp.status_code == 200, resp.text
    by_id = _by_id(resp.json())
    assert by_id[ALIAS]["linked"] is False
    assert by_id[ALIAS]["rejected"] is True
    # A provider that tracks no rejection is never flagged.
    assert by_id["x509"]["rejected"] is False


def test_oauth21_provider_with_nothing_stored_is_not_rejected(
    monkeypatch: pytest.MonkeyPatch, app_client_factory: Callable[..., object]
) -> None:
    _configure_oauth21_env(monkeypatch)

    with app_client_factory() as (client, _state):
        resp = client.get("/v1/identities", headers=_AUTH)

    entry = _by_id(resp.json())[ALIAS]
    assert entry["linked"] is False
    assert entry["rejected"] is False


# ---------------------------------------------------------------------------
# Config-order preservation
# ---------------------------------------------------------------------------


def test_providers_order_matches_identity_providers_config_order(
    monkeypatch: pytest.MonkeyPatch, app_client_factory: Callable[..., object]
) -> None:
    """The response's providers list must reflect identity_providers' config
    order, not grouped by type — Python dicts preserve insertion order, and
    app.py's lifespan populates app.state.broker.identity_providers by iterating
    identity_providers in order, so this is structural rather than an
    explicit sort."""
    monkeypatch.setenv("BROKER_STATE_KEY", Fernet.generate_key().decode())
    monkeypatch.setenv("OAUTH21_CLIENT_ID", "https://mcp.example.com/.well-known/cimd")
    monkeypatch.setenv("BROKER_PUBLIC_ORIGIN", "https://mcp-portal.example.com")
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
                # The shipped services.yaml wires "ami" with auth_type: x509,
                # so this override (replacing conftest's default entirely)
                # must still cover it or the broker refuses to start.
                {
                    "type": "x509",
                    "voms": "atlas",
                    "service_url": "http://voms-token-service.invalid:8000",
                    "alias": "x509",
                    "targets": ["ami"],
                },
            ]
        ),
    )

    with app_client_factory() as (client, _state):
        resp = client.get("/v1/identities", headers=_AUTH)

    assert resp.status_code == 200, resp.text
    ids = [p["id"] for p in resp.json()["providers"]]
    # config order is preserved -- the x509 entry trails here only because
    # it was declared last above, not because of any special-casing.
    assert ids == ["z-oauth21-provider", "a-keycloak-provider", "x509"]


# ---------------------------------------------------------------------------
# link_mechanism — how the portal starts a linking flow for each entry
# ---------------------------------------------------------------------------


def test_keycloak_brokered_link_mechanism_is_redirect(
    app_client: tuple[TestClient, dict],
) -> None:
    client, _ = app_client
    resp = client.get("/v1/identities", headers=_AUTH)

    assert resp.status_code == 200, resp.text
    entry = _by_id(resp.json())[DEFAULT_KEYCLOAK_ALIAS]
    assert entry["link_mechanism"] == "redirect"


def test_oauth21_link_mechanism_is_redirect(
    monkeypatch: pytest.MonkeyPatch, app_client_factory: Callable[..., object]
) -> None:
    _configure_oauth21_env(monkeypatch)

    with app_client_factory() as (client, _state):
        resp = client.get("/v1/identities", headers=_AUTH)

    assert resp.status_code == 200, resp.text
    entry = _by_id(resp.json())[ALIAS]
    assert entry["link_mechanism"] == "redirect"


def test_broker_issued_link_mechanism_is_none(
    monkeypatch: pytest.MonkeyPatch,
    app_client_factory: Callable[..., object],
    tmp_path,
    broker_signing_key_file: Path,
) -> None:
    """AF-native entries have no linking step at all — the broker is
    authoritative, so there is no portal action to start."""
    monkeypatch.setenv("BROKER_SIGNING_KEY_FILE", str(broker_signing_key_file))
    monkeypatch.setenv("BROKER_PUBLIC_ORIGIN", "https://mcp.example.com")
    monkeypatch.setenv(
        "IDENTITY_PROVIDERS",
        json.dumps(
            [
                {
                    "type": "broker-issued",
                    "alias": "af-native",
                    "targets": ["af-internal"],
                },
                # This override replaces conftest's default entirely, but
                # the shipped services.yaml's "ami" (auth_type: x509) still
                # needs an explicit entry or the broker refuses to start.
                {
                    "type": "x509",
                    "voms": "atlas",
                    "service_url": "http://voms-token-service.invalid:8000",
                    "alias": "x509",
                    "targets": ["ami"],
                },
            ]
        ),
    )

    with app_client_factory() as (client, _state):
        resp = client.get("/v1/identities", headers=_AUTH)

    assert resp.status_code == 200, resp.text
    entry = _by_id(resp.json())["af-native"]
    assert entry["link_mechanism"] == "none"


# ---------------------------------------------------------------------------
# The x509 entry — registry-sourced like every other row: conftest.py's
# app_client_factory default supplies a minimal entry (alias
# "x509", targets ["ami"]) covering the shipped services.yaml's auth_type:
# x509 backend, since the broker refuses to start otherwise (there is no
# synthesized fallback) — id "x509" matching the credential_provider alias
# /v1/catalog reports (wiring/checks.py's build_target_to_alias), which the portal
# joins on.
# ---------------------------------------------------------------------------

_NO_X509_SERVICES_YAML = """
services:
  - name: docs
    prefix: docs
    url: "http://docs-mcp.af.svc.cluster.local/mcp"
    transport: http
    required_permission: __none__
    display_name: Docs
    description: Search and browse Analysis Facility documentation.
    auth_type: none
"""


def test_x509_entry_present_with_x509_backend(
    app_client: tuple[TestClient, dict],
) -> None:
    """The shipped services.yaml wires "ami" with auth_type: x509, and
    conftest's default identity_providers covers it -- the default app must
    list the entry with the passphrase mechanism and no link_url (x509
    links via an in-portal passphrase form, not a redirect)."""
    client, _ = app_client
    resp = client.get("/v1/identities", headers=_AUTH)

    assert resp.status_code == 200, resp.text
    entry = _by_id(resp.json())["x509"]
    assert entry["type"] == "x509"
    assert entry["link_mechanism"] == "passphrase"
    assert entry["link_url"] is None
    assert entry["display_name"]
    assert entry["enables"]


def test_x509_entry_absent_without_x509_backends(
    monkeypatch: pytest.MonkeyPatch,
    app_client_factory: Callable[..., object],
    tmp_path,
) -> None:
    """With no ``auth_type: x509`` backend at all, an x509 entry is neither
    required nor rendered -- override IDENTITY_PROVIDERS too, dropping
    conftest's default x509 entry (which targets "ami", absent from this
    services.yaml), since a dangling entry would fail the broker's coverage
    check the other way (an x509 entry targeting a non-x509 backend)."""
    services_file = tmp_path / "services.yaml"
    services_file.write_text(_NO_X509_SERVICES_YAML)
    monkeypatch.setenv("SERVICES_FILE", str(services_file))
    monkeypatch.setenv(
        "IDENTITY_PROVIDERS",
        json.dumps(
            [
                {
                    "type": "keycloak-brokered",
                    "alias": DEFAULT_KEYCLOAK_ALIAS,
                    "targets": ["rucio", "opendata", "af-internal"],
                }
            ]
        ),
    )

    with app_client_factory() as (client, _state):
        resp = client.get("/v1/identities", headers=_AUTH)

    assert resp.status_code == 200, resp.text
    assert "x509" not in _by_id(resp.json())


def test_x509_entry_appended_after_configured_providers(
    app_client: tuple[TestClient, dict],
) -> None:
    """conftest's default entry order (keycloak-brokered, then x509) is
    reflected as-is -- config order, not any special-casing."""
    client, _ = app_client
    resp = client.get("/v1/identities", headers=_AUTH)

    assert resp.status_code == 200, resp.text
    ids = [p["id"] for p in resp.json()["providers"]]
    assert ids == [DEFAULT_KEYCLOAK_ALIAS, "x509"]


def test_explicit_x509_entry_renders_from_its_config(
    monkeypatch: pytest.MonkeyPatch,
    app_client_factory: Callable[..., object],
    tmp_path,
    broker_signing_key_file: Path,
) -> None:
    """An operator-written x509 entry is an ordinary registry row: its own
    alias/display_name/enables, the passphrase mechanism, no link_url (here
    the entry still needs the signing key, which this test mounts -- see
    app.py's lifespan)."""
    monkeypatch.setenv("BROKER_SIGNING_KEY_FILE", str(broker_signing_key_file))
    monkeypatch.setenv("BROKER_PUBLIC_ORIGIN", "https://mcp.example.com")
    monkeypatch.setenv(
        "IDENTITY_PROVIDERS",
        json.dumps(
            [
                {
                    "type": "x509",
                    "voms": "atlas",
                    "service_url": "http://voms-token-service.invalid:8000",
                    "alias": "grid-cert-atlas",
                    "display_name": "ATLAS grid certificate",
                    "enables": "VOMS proxies for AMI",
                    "targets": ["ami"],
                }
            ]
        ),
    )

    with app_client_factory() as (client, _state):
        resp = client.get("/v1/identities", headers=_AUTH)

    assert resp.status_code == 200, resp.text
    by_id = _by_id(resp.json())
    assert "x509" not in by_id  # no synthesized entry alongside the real one
    entry = by_id["grid-cert-atlas"]
    assert entry["type"] == "x509"
    assert entry["display_name"] == "ATLAS grid certificate"
    assert entry["enables"] == "VOMS proxies for AMI"
    assert entry["link_mechanism"] == "passphrase"
    assert entry["link_url"] is None
    # Nothing is stored in Vault for the default principal yet.
    assert entry["linked"] is False


def test_x509_linked_reflects_vault_link_in_service_mode(
    app_client: tuple[TestClient, dict],
) -> None:
    """linked comes from the Vault link record, never the filesystem, and
    storing a link must flip the flag."""

    client, state = app_client
    store = client.app.state.broker.x509_provider.vault_store

    resp = client.get("/v1/identities", headers=_AUTH)
    assert resp.status_code == 200, resp.text
    assert _by_id(resp.json())["x509"]["linked"] is False

    subject = state["principal"].subject
    asyncio.run(
        store.store_link(
            subject,
            passphrase=SecretStr("hunter2"),
            unixname="tuser",
            uid=1000,
            gid=1000,
        )
    )

    resp = client.get("/v1/identities", headers=_AUTH)
    assert resp.status_code == 200, resp.text
    assert _by_id(resp.json())["x509"]["linked"] is True


def test_x509_proxy_expires_at_null_when_nothing_cached(
    app_client: tuple[TestClient, dict],
) -> None:
    client, _ = app_client
    resp = client.get("/v1/identities", headers=_AUTH)

    assert resp.status_code == 200, resp.text
    assert _by_id(resp.json())["x509"]["proxy_expires_at"] is None


def test_x509_proxy_expires_at_reflects_cached_proxy(
    app_client: tuple[TestClient, dict],
) -> None:
    """proxy_expires_at comes from the Vault-stored proxy."""

    client, state = app_client
    subject = state["principal"].subject
    not_after = _seed_service_record(
        client.app.state.broker.x509_provider.vault_store,
        subject,
        passphrase="hunter2",
        proxy_remaining=3600.0,
    )

    resp = client.get("/v1/identities", headers=_AUTH)

    assert resp.status_code == 200, resp.text
    expires_at = _by_id(resp.json())["x509"]["proxy_expires_at"]
    assert expires_at is not None
    parsed = datetime.fromisoformat(expires_at)
    assert parsed.timestamp() == pytest.approx(not_after, abs=1.0)


def test_x509_proxy_expires_at_ignores_a_stale_in_memory_meta(
    app_client: tuple[TestClient, dict],
) -> None:
    """Vault is authoritative: a leftover in-memory ProxyMeta on this replica
    must not report a proxy Vault does not hold."""

    client, state = app_client
    subject = state["principal"].subject
    meta = ProxyMeta(
        dn="/DC=ch/DC=cern/CN=Test User",
        voms_attributes=["/atlas"],
        not_after=time.time() + 3600.0,
    )
    asyncio.run(
        client.app.state.broker.credential_cache.put(
            subject, "ami", {"proxy_handle": subject}, proxy_meta=meta
        )
    )

    resp = client.get("/v1/identities", headers=_AUTH)

    assert resp.status_code == 200, resp.text
    assert _by_id(resp.json())["x509"]["proxy_expires_at"] is None


def test_non_x509_entries_have_null_proxy_expires_at(
    app_client: tuple[TestClient, dict],
) -> None:
    client, _ = app_client
    resp = client.get("/v1/identities", headers=_AUTH)

    assert resp.status_code == 200, resp.text
    entry = _by_id(resp.json())[DEFAULT_KEYCLOAK_ALIAS]
    assert entry["proxy_expires_at"] is None


# ---------------------------------------------------------------------------
# x509_link_mode: custody mode surfaced per entry (consent toggle follow-up)
# ---------------------------------------------------------------------------


def _x509_store(client: TestClient) -> FakeX509Store:
    """The in-memory x509 link/proxy store conftest wires into the app."""
    store = client.app.state.broker.x509_provider.vault_store
    assert isinstance(store, FakeX509Store)
    return store


def _seed_service_record(
    store,
    subject: str,
    *,
    passphrase: str | None,
    proxy_remaining: float | None,
) -> float | None:
    asyncio.run(
        store.store_link(
            subject,
            passphrase=SecretStr(passphrase) if passphrase is not None else None,
            unixname="tuser",
            uid=1000,
            gid=1000,
        )
    )
    if proxy_remaining is None:
        return None
    not_after = time.time() + proxy_remaining
    asyncio.run(
        store.store_proxy(
            subject,
            pem="FAKE PEM",
            dn="/DC=ch/DC=cern/CN=Test User",
            voms_attributes=["/atlas"],
            not_after=not_after,
        )
    )
    return not_after


class TestX509LinkMode:
    def test_null_when_not_linked(self, app_client: tuple[TestClient, dict]) -> None:
        client, _ = app_client
        resp = client.get("/v1/identities", headers=_AUTH)

        assert resp.status_code == 200, resp.text
        entry = _by_id(resp.json())["x509"]
        assert entry["linked"] is False
        assert entry["x509_link_mode"] is None

    def test_null_on_non_x509_entries(
        self, app_client: tuple[TestClient, dict]
    ) -> None:
        client, _ = app_client
        resp = client.get("/v1/identities", headers=_AUTH)

        assert resp.status_code == 200, resp.text
        assert _by_id(resp.json())[DEFAULT_KEYCLOAK_ALIAS]["x509_link_mode"] is None

    def test_auto_renew_with_valid_proxy(
        self, app_client: tuple[TestClient, dict]
    ) -> None:
        client, state = app_client
        store = _x509_store(client)
        not_after = _seed_service_record(
            store,
            state["principal"].subject,
            passphrase="hunter2",
            proxy_remaining=3600,
        )

        resp = client.get("/v1/identities", headers=_AUTH)

        assert resp.status_code == 200, resp.text
        entry = _by_id(resp.json())["x509"]
        assert entry["linked"] is True
        assert entry["x509_link_mode"] == "auto-renew"
        # Vault is authoritative for the expiry — the in-memory ProxyMeta
        # cache is empty here, and that must not matter.
        assert entry["proxy_expires_at"] is not None
        parsed = datetime.fromisoformat(entry["proxy_expires_at"])
        assert parsed.timestamp() == pytest.approx(not_after, abs=1.0)

    def test_auto_renew_survives_proxy_expiry(
        self, app_client: tuple[TestClient, dict]
    ) -> None:
        """linked-with-renewal must read as linked even with no valid proxy
        — the next issue() renews hands-free."""
        client, state = app_client
        store = _x509_store(client)
        _seed_service_record(
            store, state["principal"].subject, passphrase="hunter2", proxy_remaining=-10
        )

        resp = client.get("/v1/identities", headers=_AUTH)

        assert resp.status_code == 200, resp.text
        entry = _by_id(resp.json())["x509"]
        assert entry["linked"] is True
        assert entry["x509_link_mode"] == "auto-renew"
        assert entry["proxy_expires_at"] is None

    def test_until_expiry_with_valid_proxy(
        self, app_client: tuple[TestClient, dict]
    ) -> None:
        client, state = app_client
        store = _x509_store(client)
        not_after = _seed_service_record(
            store, state["principal"].subject, passphrase=None, proxy_remaining=3600
        )

        resp = client.get("/v1/identities", headers=_AUTH)

        assert resp.status_code == 200, resp.text
        entry = _by_id(resp.json())["x509"]
        assert entry["linked"] is True
        assert entry["x509_link_mode"] == "until-expiry"
        parsed = datetime.fromisoformat(entry["proxy_expires_at"])
        assert parsed.timestamp() == pytest.approx(not_after, abs=1.0)

    def test_until_expiry_reads_unlinked_after_expiry(
        self, app_client: tuple[TestClient, dict]
    ) -> None:
        """The bounded consequence of remember=false: after the proxy
        lapses the entry reads as not linked, prompting a re-link."""
        client, state = app_client
        store = _x509_store(client)
        _seed_service_record(
            store, state["principal"].subject, passphrase=None, proxy_remaining=-10
        )

        resp = client.get("/v1/identities", headers=_AUTH)

        assert resp.status_code == 200, resp.text
        entry = _by_id(resp.json())["x509"]
        assert entry["linked"] is False
        assert entry["x509_link_mode"] is None
        assert entry["proxy_expires_at"] is None


# ---------------------------------------------------------------------------
# DELETE /v1/identities/link/<provider>
# ---------------------------------------------------------------------------


def test_unlink_unknown_provider_returns_422(
    app_client: tuple[TestClient, dict],
) -> None:
    client, _ = app_client
    resp = client.delete("/v1/identities/link/not-a-real-provider", headers=_AUTH)
    assert resp.status_code == 422
    assert resp.json()["detail"] == "Unknown provider 'not-a-real-provider'"


def test_unlink_known_keycloak_provider_returns_501(
    app_client: tuple[TestClient, dict],
) -> None:
    client, _ = app_client
    resp = client.delete(f"/v1/identities/link/{DEFAULT_KEYCLOAK_ALIAS}", headers=_AUTH)
    assert resp.status_code == 501
    assert "not yet implemented" in resp.json()["detail"]


def test_unlink_known_oauth21_alias_returns_204_and_deletes_stored_token(
    monkeypatch: pytest.MonkeyPatch, app_client_factory: Callable[..., object]
) -> None:

    _configure_oauth21_env(monkeypatch)

    with app_client_factory() as (client, state):
        subject = state["principal"].subject
        store = broker_app.state.broker.oauth21_token_store
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

        resp = client.delete(f"/v1/identities/link/{ALIAS}", headers=_AUTH)

        assert resp.status_code == 204, resp.text
        assert asyncio.run(store.get(subject, ALIAS)) is None


def test_unlink_known_oauth21_alias_purges_credential_cache(
    monkeypatch: pytest.MonkeyPatch, app_client_factory: Callable[..., object]
) -> None:
    """The alias's targets must have their in-process cached credentials
    purged too, not just the stored TokenStore entry -- otherwise a still-
    cached credential would keep being handed out until it naturally
    expires."""

    _configure_oauth21_env(monkeypatch)

    with app_client_factory() as (client, state):
        subject = state["principal"].subject
        cache = broker_app.state.broker.credential_cache
        asyncio.run(cache.put(subject, ALIAS, "fake-cached-credential"))
        assert asyncio.run(cache.get(subject, ALIAS)) is not None

        resp = client.delete(f"/v1/identities/link/{ALIAS}", headers=_AUTH)

        assert resp.status_code == 204, resp.text
        # get() itself would raise on a rate-limited miss -- read the entry
        # dict directly to assert absence without tripping that.
        assert (subject, ALIAS) not in cache._entries


def test_unlink_oauth21_alias_returns_204_even_when_nothing_was_stored(
    monkeypatch: pytest.MonkeyPatch, app_client_factory: Callable[..., object]
) -> None:
    """Unlinking an alias that was never actually linked must still succeed
    -- there's nothing to revoke, but that's not an error."""
    _configure_oauth21_env(monkeypatch)

    with app_client_factory() as (client, _state):
        resp = client.delete(f"/v1/identities/link/{ALIAS}", headers=_AUTH)
    assert resp.status_code == 204, resp.text
    assert resp.content == b""


def test_unlink_oauth21_alias_204_even_when_revocation_endpoint_fails(
    monkeypatch: pytest.MonkeyPatch, app_client_factory: Callable[..., object]
) -> None:
    """A rejecting/unreachable revocation_endpoint must not turn into a
    failed unlink -- OAuth21Provider.revoke() is best-effort upstream."""

    monkeypatch.setenv("BROKER_STATE_KEY", Fernet.generate_key().decode())
    monkeypatch.setenv("OAUTH21_CLIENT_ID", "https://mcp.example.com/.well-known/cimd")
    monkeypatch.setenv("BROKER_PUBLIC_ORIGIN", "https://mcp-portal.example.com")
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
                    "revocation_endpoint": "https://backend-as.example/revoke",
                },
                # This override replaces conftest's default entirely, but
                # the shipped services.yaml's "ami" (auth_type: x509) still
                # needs an explicit entry or the broker refuses to start.
                {
                    "type": "x509",
                    "voms": "atlas",
                    "service_url": "http://voms-token-service.invalid:8000",
                    "alias": "x509",
                    "targets": ["ami"],
                },
            ]
        ),
    )

    class _RejectingClient:
        async def post(self, *args, **kwargs):

            return httpx2.Response(500, request=httpx2.Request("POST", args[0]))

    monkeypatch.setattr(
        "af_mcp_broker.app.build_http_client", lambda _stack: _RejectingClient()
    )

    with app_client_factory() as (client, state):
        subject = state["principal"].subject
        store = broker_app.state.broker.oauth21_token_store
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

        resp = client.delete(f"/v1/identities/link/{ALIAS}", headers=_AUTH)

        assert resp.status_code == 204, resp.text
        assert asyncio.run(store.get(subject, ALIAS)) is None
