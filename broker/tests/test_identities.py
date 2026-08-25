"""Tests for GET /v1/identities' ``providers`` list.

``providers`` reflects whatever ``identity_providers`` entries are
configured, in config order, uniform across both linking mechanisms:
Keycloak's stored-broker-token pattern (``OIDCProvider``) and the broker's
own direct OAuth 2.1 client (``OAuth21Provider``). x509 is an ordinary entry
too: every backend wired with ``auth_type: x509`` must be covered by an
explicit entry (app.py's lifespan refuses to start otherwise — there is no
synthesized fallback), so the x509 row is always registry-sourced like every
other. conftest.py's ``app_client``/``app_client_factory`` default supplies
a minimal legacy-mode entry (alias "x509", targets ["ami"]) covering the
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
) -> None:
    """AF-native entries have no linking step at all — the broker is
    authoritative, so there is no portal action to start."""
    from test_broker_issued import _make_rsa_key, _private_pem

    key_file = tmp_path / "signing-key.pem"
    key_file.write_bytes(_private_pem(_make_rsa_key()))
    monkeypatch.setenv("BROKER_SIGNING_KEY_FILE", str(key_file))
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
# app_client_factory default supplies a minimal legacy-mode entry (alias
# "x509", targets ["ami"]) covering the shipped services.yaml's auth_type:
# x509 backend, since the broker refuses to start otherwise (there is no
# synthesized fallback) — id "x509" matching the credential_provider alias
# /v1/catalog reports (app.py's _build_target_to_alias), which the portal
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
) -> None:
    """An operator-written x509 entry is an ordinary registry row: its own
    alias/display_name/enables, the passphrase mechanism, no link_url (here
    a legacy-mode entry, service_url omitted, so no Vault/voms-token-service
    deployment is needed to boot). The signing key is mounted anyway in this
    test even though a keyless legacy entry only warns rather than failing
    -- see app.py's lifespan."""
    from test_broker_issued import _make_rsa_key, _private_pem

    key_file = tmp_path / "signing-key.pem"
    key_file.write_bytes(_private_pem(_make_rsa_key()))
    monkeypatch.setenv("BROKER_SIGNING_KEY_FILE", str(key_file))
    monkeypatch.setenv("BROKER_PUBLIC_ORIGIN", "https://mcp.example.com")
    monkeypatch.setenv(
        "IDENTITY_PROVIDERS",
        json.dumps(
            [
                {
                    "type": "x509",
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
    # The ~/.globus pair app_client_factory pre-creates makes the default
    # principal linked in legacy mode — same probe as the alias "x509" case.
    assert entry["linked"] is True


def test_x509_linked_true_legacy_mode(
    app_client: tuple[TestClient, dict],
) -> None:
    """Legacy (no voms-token-service) mode: linked reflects the ~/.globus
    cert-pair heuristic — the app_client fixture pre-creates the pair for
    the default principal's unixname."""
    client, _ = app_client
    resp = client.get("/v1/identities", headers=_AUTH)

    assert resp.status_code == 200, resp.text
    assert _by_id(resp.json())["x509"]["linked"] is True


def test_x509_linked_false_legacy_mode_without_cert_pair(
    app_client: tuple[TestClient, dict], make_principal: Callable[..., object]
) -> None:
    client, state = app_client
    state["principal"] = make_principal(groups=["atlas"], unixname="no-globus-here")

    resp = client.get("/v1/identities", headers=_AUTH)

    assert resp.status_code == 200, resp.text
    assert _by_id(resp.json())["x509"]["linked"] is False


def test_x509_linked_reflects_vault_link_in_service_mode(
    app_client: tuple[TestClient, dict],
) -> None:
    """voms-token-service mode: linked comes from the Vault link record, not
    the filesystem — the pre-created ~/.globus pair must NOT count, and
    storing a link must flip the flag."""
    from test_x509_service_mode import FakeVomsClient, FakeX509Store

    client, state = app_client
    store = FakeX509Store()
    provider = client.app.state.x509_provider
    provider._vault_store = store
    provider._voms_client = FakeVomsClient()
    assert provider.uses_voms_service is True

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
    """proxy_expires_at comes from the same in-memory ProxyMeta the
    GET /v1/x509/proxy/status endpoint serves — cheap, no Vault round trip."""
    from af_mcp_broker.credentials.cache import ProxyMeta

    client, state = app_client
    subject = state["principal"].subject
    not_after = time.time() + 3600.0
    meta = ProxyMeta(
        dn="/DC=ch/DC=cern/CN=Test User",
        voms_attributes=["/atlas"],
        not_after=not_after,
    )
    asyncio.run(
        client.app.state.credential_cache.put(
            subject, "ami", {"proxy_handle": subject}, proxy_meta=meta
        )
    )

    resp = client.get("/v1/identities", headers=_AUTH)

    assert resp.status_code == 200, resp.text
    expires_at = _by_id(resp.json())["x509"]["proxy_expires_at"]
    assert expires_at is not None
    parsed = datetime.fromisoformat(expires_at)
    assert parsed.timestamp() == pytest.approx(not_after, abs=1.0)


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


def _flip_to_service_mode(client: TestClient):
    """Flip the app's default legacy x509 provider into service mode with the in-memory fakes (same pattern as the service-mode linked test above)."""
    from test_x509_service_mode import FakeVomsClient, FakeX509Store

    store = FakeX509Store()
    provider = client.app.state.x509_provider
    provider._vault_store = store
    provider._voms_client = FakeVomsClient()
    assert provider.uses_voms_service is True
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
    def test_null_in_legacy_mode(self, app_client: tuple[TestClient, dict]) -> None:
        """Legacy (filesystem) linkage has no custody concept."""
        client, _ = app_client
        resp = client.get("/v1/identities", headers=_AUTH)

        assert resp.status_code == 200, resp.text
        entry = _by_id(resp.json())["x509"]
        assert entry["linked"] is True  # conftest pre-creates the cert pair
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
        store = _flip_to_service_mode(client)
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
        # Vault is authoritative for the expiry in service mode — the
        # in-memory ProxyMeta cache is empty here, and that must not matter.
        assert entry["proxy_expires_at"] is not None
        parsed = datetime.fromisoformat(entry["proxy_expires_at"])
        assert parsed.timestamp() == pytest.approx(not_after, abs=1.0)

    def test_auto_renew_survives_proxy_expiry(
        self, app_client: tuple[TestClient, dict]
    ) -> None:
        """linked-with-renewal must read as linked even with no valid proxy
        — the next issue() renews hands-free."""
        client, state = app_client
        store = _flip_to_service_mode(client)
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
        store = _flip_to_service_mode(client)
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
        store = _flip_to_service_mode(client)
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


def test_unlink_known_oauth21_alias_returns_204_and_deletes_stored_token(
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
    from af_mcp_broker.app import app as broker_app

    _configure_oauth21_env(monkeypatch)

    with app_client_factory() as (client, state):
        subject = state["principal"].subject
        cache = broker_app.state.credential_cache
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


def test_unlink_oauth21_alias_204_even_when_revocation_endpoint_fails(
    monkeypatch: pytest.MonkeyPatch, app_client_factory: Callable[..., object]
) -> None:
    """A rejecting/unreachable revocation_endpoint must not turn into a
    failed unlink -- OAuth21Provider.revoke() is best-effort upstream."""
    from af_mcp_broker.app import app as broker_app
    from af_mcp_broker.credentials.oauth21 import StoredOAuthCredential

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
                    "alias": "x509",
                    "targets": ["ami"],
                },
            ]
        ),
    )

    class _RejectingClient:
        async def post(self, *args, **kwargs):
            import httpx

            return httpx.Response(500, request=httpx.Request("POST", args[0]))

    monkeypatch.setattr(
        "af_mcp_broker.credentials.oauth21.get_http_client",
        _RejectingClient,
    )

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

        resp = client.delete(f"/v1/identities/link/{ALIAS}", headers=_AUTH)

        assert resp.status_code == 204, resp.text
        assert asyncio.run(store.get(subject, ALIAS)) is None
