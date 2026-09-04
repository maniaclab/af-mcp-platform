"""Tests for the backend-facing krb5 ticket redeem endpoint (issue #274 follow-up).

POST /v1/credentials/krb5/redeem is authenticated by an AF Broker Identity
Token (NOT a Keycloak token) -- mirrors POST /v1/credentials/x509/redeem
(see test_x509_redeem.py) exactly: the broker verifies its own signature,
requires ``aud`` to be a configured krb5 target, and returns whatever ticket
is already cached or Vault-stored for the caller. Deliberately read-only --
this endpoint must NEVER mint or renew a ticket, since a synchronous
backend-to-backend call has no way to prompt a user for a CERN password.
"""

from __future__ import annotations

import asyncio
import json
import time
from typing import TYPE_CHECKING

import pytest
from pydantic import SecretStr
from test_broker_issued import _make_rsa_key, _private_pem
from test_krb5_token import FakeKrb5VaultStore

from af_mcp_broker.api import credentials as credentials_api
from af_mcp_broker.credentials import (
    CredentialKind,
    ExecutionModel,
    IssuedCredential,
)
from af_mcp_broker.vault_kv import VaultKV

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from fastapi.testclient import TestClient

    from af_mcp_broker.audit import AuditRecord

_REDEEM = "/v1/credentials/krb5/redeem"
_TARGET = "krb5-backend"

# krb5-backend is a krb5 backend (auth_type: krb5): that flag is what
# app.py's krb5_audiences map is built from (Task 1 of this plan). An
# explicit identity_providers entry covering it is required too (the
# fixture below supplies one; the broker refuses to start otherwise --
# see app.py's krb5-token signing-key check).
_BACKENDS_YAML = (
    "services:\n"
    "  - name: krb5-backend\n"
    "    prefix: krb5b\n"
    "    url: http://krb5-backend.invalid/mcp\n"
    "    auth_type: krb5\n"
    "    required_permission: read_data\n"
)

# A krb5 service whose registry name and token audience diverge (issue #257,
# same split as x509's _DIVERGENT_YAML in test_x509_redeem.py): the broker
# mints aud=krb5-backend-mcp (effective_audience) for the target
# krb5_backend_service.
_DIVERGENT_YAML = (
    "services:\n"
    "  - name: krb5_backend_service\n"
    "    prefix: krb5b\n"
    "    url: http://krb5-backend.invalid/mcp\n"
    "    auth_type: krb5\n"
    "    audience: krb5-backend-mcp\n"
    "    required_permission: read_data\n"
)


@pytest.fixture
def captured_audits(monkeypatch: pytest.MonkeyPatch) -> list[AuditRecord]:
    """Capture every ``write_audit`` call made from api/credentials.py.

    Same pattern as test_mcp_middleware_authorization.py's fixture of the
    same name: monkeypatch the name as imported into the module under test
    (``write_audit`` is imported by name into af_mcp_broker.api.credentials),
    rather than the audit logger itself.
    """
    records: list[AuditRecord] = []

    async def _fake_write_audit(record: AuditRecord) -> None:
        records.append(record)

    monkeypatch.setattr(credentials_api, "write_audit", _fake_write_audit)
    return records


async def _fake_authenticate(self: VaultKV) -> str:
    return "vault-test-token"


@pytest.fixture
def krb5_redeem_env(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> Callable[..., None]:
    """Configure a krb5-token identity provider for target 'krb5-backend' with a real signing key and a stubbed Vault."""

    def _apply(
        services_yaml: str = _BACKENDS_YAML,
        krb5_targets: list[str] | None = None,
    ) -> None:
        services_file = tmp_path / "services.yaml"
        services_file.write_text(services_yaml)
        monkeypatch.setenv("SERVICES_FILE", str(services_file))
        monkeypatch.setenv("BROKER_PUBLIC_ORIGIN", "https://mcp.example.com")
        monkeypatch.setenv(
            "IDENTITY_PROVIDERS",
            json.dumps(
                [
                    {
                        "type": "krb5-token",
                        "alias": "krb5",
                        "display_name": "CERN Kerberos ticket",
                        "targets": krb5_targets or [_TARGET],
                        "service_url": "http://krb5-token-service.invalid",
                    }
                ]
            ),
        )
        key_file = tmp_path / "signing-key.pem"
        key_file.write_bytes(_private_pem(_make_rsa_key()))
        monkeypatch.setenv("BROKER_SIGNING_KEY_FILE", str(key_file))
        # A krb5-token entry always requires Vault (config.py's
        # _validate_vault_config); stub the trial auth the same way
        # test_krb5_ticket_endpoint.py's krb5_app fixture does.
        monkeypatch.setattr(VaultKV, "_authenticate", _fake_authenticate)
        monkeypatch.setenv("VAULT_ADDR", "https://vault.invalid")
        monkeypatch.setenv("VAULT_AUTH_ROLE", "af-mcp-broker")

    return _apply


def _fake_vault_store(client: TestClient, target: str = _TARGET) -> FakeKrb5VaultStore:
    """Resolve *target*'s KrbTokenProvider and swap in a FakeKrb5VaultStore, returning it.

    Same "swap the concrete store attribute post-boot" pattern
    test_krb5_ticket_endpoint.py's krb5_app fixture uses -- with a real
    Krb5VaultStore wired in, any Vault-tier read would hit the (stubbed but
    otherwise real) VaultKV client.
    """
    provider = asyncio.run(client.app.state.credential_registry.resolve(target))
    store = FakeKrb5VaultStore()
    provider._vault_store = store
    return store


def _mint(
    client: TestClient, *, subject: str = "sub-abc", audience: str = _TARGET
) -> str:
    token, _ = client.app.state.broker_token_issuer.mint(subject, audience)
    return str(token)


def _seed_cache_ticket(
    client: TestClient,
    *,
    subject: str,
    target: str = _TARGET,
    remaining: float = 3600.0,
    renewable: bool = True,
) -> IssuedCredential:
    """Store a fake ticket for *subject* against krb5 *target* directly in the shared CredentialCache."""
    not_after = time.time() + remaining
    renew_until = not_after + 3600.0 if renewable else None
    cred = IssuedCredential(
        cred_class="krb5_ticket",
        target=target,
        kind=CredentialKind.KRB5_CCACHE,
        expires_at=not_after,
        payload={
            "ccache_b64": "ZmFrZS1jY2FjaGU=",
            "principal": "tuser@CERN.CH",
            "realm": "CERN.CH",
            "renew_until": renew_until,
        },
        audit_id="test-audit-id",
        source="test",
        execution_model=ExecutionModel.DELEGATED,
    )
    asyncio.run(
        client.app.state.credential_cache.put(
            subject, target, cred, expires_at=not_after
        )
    )
    return cred


class TestRedeemAuth:
    def test_missing_authorization_is_401(
        self, krb5_redeem_env, app_client_factory
    ) -> None:
        krb5_redeem_env()
        with app_client_factory() as (client, _):
            resp = client.post(_REDEEM, json={})
        assert resp.status_code == 401

    def test_garbage_token_is_401(self, krb5_redeem_env, app_client_factory) -> None:
        krb5_redeem_env()
        with app_client_factory() as (client, _):
            resp = client.post(
                _REDEEM, json={}, headers={"Authorization": "Bearer nonsense"}
            )
        assert resp.status_code == 401

    def test_non_krb5_audience_is_403(
        self, krb5_redeem_env, app_client_factory
    ) -> None:
        krb5_redeem_env()
        with app_client_factory() as (client, _):
            token = _mint(client, audience="condor-token-service")
            resp = client.post(
                _REDEEM, json={}, headers={"Authorization": f"Bearer {token}"}
            )
        assert resp.status_code == 403
        assert "not a configured krb5 target" in resp.json()["detail"]

    def test_non_krb5_audience_denial_is_audited(
        self, krb5_redeem_env, app_client_factory, captured_audits
    ) -> None:
        """Security-relevant: since krb5_audiences is empty until a real
        services.yaml consumer is configured, this 403 is the ONLY outcome
        this route reaches in any real deployment today -- it must not be
        audit-silent. Mirrors x509's audience-not-mapped audit record
        (credentials.py's inline AuditRecord at the top of
        redeem_x509_proxy) shape-for-shape, action renamed for krb5."""
        krb5_redeem_env()
        with app_client_factory() as (client, _):
            token = _mint(client, audience="condor-token-service")
            resp = client.post(
                _REDEEM, json={}, headers={"Authorization": f"Bearer {token}"}
            )
        assert resp.status_code == 403
        assert len(captured_audits) == 1
        record = captured_audits[0]
        assert record.action == "krb5_ticket_release"
        assert record.outcome == "denied"
        assert record.target == "condor-token-service"
        assert record.principal_sub == "sub-abc"
        assert "not a configured krb5 target" in (record.error or "")

    def test_redeem_maps_audience_to_target_when_name_differs(
        self, krb5_redeem_env, app_client_factory
    ) -> None:
        """issue #257 regression (krb5 side): for a krb5 service whose name
        and audience diverge (name=krb5_backend_service,
        audience=krb5-backend-mcp), the broker mints tokens with
        aud=krb5-backend-mcp. The redeem endpoint must map that audience back
        to the krb5 target ('krb5_backend_service') and serve the ticket
        cached under it -- NOT 403 because 'krb5-backend-mcp' isn't a target
        name. Mirrors test_x509_redeem.py's
        test_redeem_maps_audience_to_target_when_name_differs."""
        krb5_redeem_env(
            services_yaml=_DIVERGENT_YAML, krb5_targets=["krb5_backend_service"]
        )
        with app_client_factory() as (client, _):
            _fake_vault_store(client, target="krb5_backend_service")
            cred = _seed_cache_ticket(
                client, subject="sub-abc", target="krb5_backend_service"
            )
            token = _mint(client, audience="krb5-backend-mcp")
            resp = client.post(
                _REDEEM, json={}, headers={"Authorization": f"Bearer {token}"}
            )
        assert resp.status_code == 200, resp.text
        assert resp.json()["ccache_b64"] == cred.payload["ccache_b64"]


class TestRedeem:
    def test_no_ticket_anywhere_is_404_with_actionable_detail(
        self, krb5_redeem_env, app_client_factory
    ) -> None:
        krb5_redeem_env()
        with app_client_factory() as (client, _):
            _fake_vault_store(client)
            token = _mint(client)
            resp = client.post(
                _REDEEM, json={}, headers={"Authorization": f"Bearer {token}"}
            )
        assert resp.status_code == 404
        assert "/v1/krb5/ticket" in resp.json()["detail"]

    def test_cache_hit_returns_ticket(
        self, krb5_redeem_env, app_client_factory
    ) -> None:
        krb5_redeem_env()
        with app_client_factory() as (client, _):
            _fake_vault_store(client)
            cred = _seed_cache_ticket(client, subject="sub-abc")
            token = _mint(client)
            resp = client.post(
                _REDEEM, json={}, headers={"Authorization": f"Bearer {token}"}
            )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        # Assert on the actual wire keys -- the response must carry ONLY the
        # documented fields, never raw cache/Vault internals.
        assert set(body) == {
            "ccache_b64",
            "principal",
            "realm",
            "expires_at",
            "remaining_seconds",
            "renew_until",
        }
        assert body["ccache_b64"] == cred.payload["ccache_b64"]
        assert body["principal"] == cred.payload["principal"]
        assert body["realm"] == cred.payload["realm"]
        assert body["renew_until"]
        assert 3500 < body["remaining_seconds"] <= 3600
        assert body["expires_at"]

    def test_cache_hit_null_renew_until_for_non_renewable_ticket(
        self, krb5_redeem_env, app_client_factory
    ) -> None:
        krb5_redeem_env()
        with app_client_factory() as (client, _):
            _fake_vault_store(client)
            _seed_cache_ticket(client, subject="sub-abc", renewable=False)
            token = _mint(client)
            resp = client.post(
                _REDEEM, json={}, headers={"Authorization": f"Bearer {token}"}
            )
        assert resp.status_code == 200, resp.text
        assert resp.json()["renew_until"] is None

    def test_vault_only_hit_returns_ticket(
        self, krb5_redeem_env, app_client_factory
    ) -> None:
        """Cache empty, Vault holds a fresh ticket -- simulates a broker
        restart (KrbTokenProvider.issue()'s tier 2, reused read-only by
        peek_ticket())."""
        krb5_redeem_env()
        with app_client_factory() as (client, _):
            store = _fake_vault_store(client)
            not_after = time.time() + 3600.0
            asyncio.run(
                store.store_ticket(
                    "sub-abc",
                    ccache_b64=SecretStr("dmF1bHQtY2NhY2hl"),
                    principal="tuser@CERN.CH",
                    realm="CERN.CH",
                    not_after=not_after,
                    renew_until=not_after + 3600.0,
                )
            )
            token = _mint(client)
            resp = client.post(
                _REDEEM, json={}, headers={"Authorization": f"Bearer {token}"}
            )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["ccache_b64"] == "dmF1bHQtY2NhY2hl"
        assert body["principal"] == "tuser@CERN.CH"
        assert body["realm"] == "CERN.CH"
        assert 3500 < body["remaining_seconds"] <= 3600

    def test_expired_cached_ticket_falls_through_to_vault_miss_404(
        self, krb5_redeem_env, app_client_factory
    ) -> None:
        krb5_redeem_env()
        with app_client_factory() as (client, _):
            _fake_vault_store(client)
            _seed_cache_ticket(client, subject="sub-abc", remaining=-10.0)
            token = _mint(client)
            resp = client.post(
                _REDEEM, json={}, headers={"Authorization": f"Bearer {token}"}
            )
        assert resp.status_code == 404

    def test_ticket_is_per_subject(self, krb5_redeem_env, app_client_factory) -> None:
        krb5_redeem_env()
        with app_client_factory() as (client, _):
            _fake_vault_store(client)
            _seed_cache_ticket(client, subject="someone-else")
            token = _mint(client, subject="sub-abc")
            resp = client.post(
                _REDEEM, json={}, headers={"Authorization": f"Bearer {token}"}
            )
        assert resp.status_code == 404

    def test_redeem_never_calls_keycloak(
        self, krb5_redeem_env, app_client_factory
    ) -> None:
        """Regression guard mirroring test_x509_redeem.py's equivalent: this
        endpoint must authenticate purely via BrokerTokenIssuer.verify(),
        never via keycloak_dependency (which app_client_factory overrides
        for every other test in this module -- see credentials.py's
        backend_router module comment for why redeem lives off the
        maintenance-mode-gated router)."""
        from af_mcp_broker.identity import keycloak_dependency

        krb5_redeem_env()
        with app_client_factory() as (client, _):
            client.app.dependency_overrides.pop(keycloak_dependency, None)
            _fake_vault_store(client)
            cred = _seed_cache_ticket(client, subject="sub-abc")
            token = _mint(client)
            resp = client.post(
                _REDEEM, json={}, headers={"Authorization": f"Bearer {token}"}
            )
        assert resp.status_code == 200
        assert resp.json()["ccache_b64"] == cred.payload["ccache_b64"]

    def test_successful_redeem_is_audited(
        self, krb5_redeem_env, app_client_factory, captured_audits
    ) -> None:
        """Mirrors x509's success-path audit (_release_audit's
        outcome="success" record on redeem_x509_proxy's legacy path): the
        ccache material itself must never appear in the record, only
        subject/target/outcome and the resolved principal metadata."""
        krb5_redeem_env()
        with app_client_factory() as (client, _):
            _fake_vault_store(client)
            cred = _seed_cache_ticket(client, subject="sub-abc")
            token = _mint(client)
            resp = client.post(
                _REDEEM, json={}, headers={"Authorization": f"Bearer {token}"}
            )
        assert resp.status_code == 200
        assert len(captured_audits) == 1
        record = captured_audits[0]
        assert record.action == "krb5_ticket_release"
        assert record.outcome == "success"
        assert record.target == _TARGET
        assert record.principal_sub == "sub-abc"
        assert cred.payload["ccache_b64"] not in record.args_summary


class TestKeylessBoot:
    def test_krb5_backend_without_signing_key_boots_and_503s_redeem(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path, app_client_factory
    ) -> None:
        """Mirrors test_x509_redeem.py's
        test_x509_backend_without_signing_key_boots_and_503s_redeem, adapted
        for krb5: unlike x509 there is no legacy/service-mode split -- ANY
        krb5-token identity_providers entry always implies the signing key
        requirement (app.py's fail-closed check groups krb5-token in with
        broker-issued/condor-token), so the only way to reach a booted app
        with issuer=None and a krb5 target configured is to have an
        auth_type: krb5 service in services.yaml with NO covering
        krb5-token identity_providers entry at all (there is no drift check
        for that the way _validate_x509_provider_targets enforces for x509 --
        see app.py's krb5_targets comment). The redeem endpoint still answers
        503 until a signing key is mounted -- enforcement at point of use."""
        services_file = tmp_path / "services.yaml"
        services_file.write_text(_BACKENDS_YAML)
        monkeypatch.setenv("SERVICES_FILE", str(services_file))
        monkeypatch.setenv("IDENTITY_PROVIDERS", json.dumps([]))
        monkeypatch.delenv("BROKER_SIGNING_KEY_FILE", raising=False)

        with app_client_factory() as (client, _):
            resp = client.post(
                _REDEEM, json={}, headers={"Authorization": "Bearer whatever"}
            )
        assert resp.status_code == 503
