"""Tests for the backend-facing ServiceX access-token redeem endpoint (issue #295).

POST /v1/credentials/servicex/redeem is authenticated by an AF Broker
Identity Token (NOT a Keycloak token) -- mirrors POST /v1/credentials/
x509/redeem and POST /v1/credentials/krb5/redeem (see test_x509_redeem.py/
test_krb5_redeem.py): the broker verifies its own signature, requires
``aud`` to be a configured servicex target, and returns whatever access
token is already Vault-stored (or hands-free redeemed from the stored
refresh token) for the caller.
"""

from __future__ import annotations

import asyncio
import json
import time
from typing import TYPE_CHECKING, Any

import pytest
from pydantic import SecretStr
from test_broker_issued import _make_rsa_key, _private_pem
from test_servicex import FakeServiceXClient, FakeServiceXStore, _redeemed

from af_mcp_broker.api import credentials as credentials_api
from af_mcp_broker.credentials.servicex_service import (
    ServiceXBadRefreshTokenError,
    ServiceXServiceMintError,
)
from af_mcp_broker.vault_kv import VaultKV

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from fastapi.testclient import TestClient

    from af_mcp_broker.audit import AuditRecord

_REDEEM = "/v1/credentials/servicex/redeem"
_TARGET = "servicex-backend"

# servicex-backend is a servicex backend (auth_type: servicex): that flag is
# what app.py's servicex_audiences map is built from. An explicit
# identity_providers entry covering it is required too (the fixture below
# supplies one; the broker refuses to start otherwise -- see app.py's
# servicex-token signing-key check).
_BACKENDS_YAML = (
    "services:\n"
    "  - name: servicex-backend\n"
    "    prefix: servicexb\n"
    "    url: http://servicex-backend.invalid/mcp\n"
    "    auth_type: servicex\n"
    "    required_permission: read_data\n"
)

# A servicex service whose registry name and token audience diverge (issue
# #257, same split as x509's/krb5's divergent-audience regression tests):
# the broker mints aud=servicex-backend-mcp (effective_audience) for the
# target servicex_backend_service.
_DIVERGENT_YAML = (
    "services:\n"
    "  - name: servicex_backend_service\n"
    "    prefix: servicexb\n"
    "    url: http://servicex-backend.invalid/mcp\n"
    "    auth_type: servicex\n"
    "    audience: servicex-backend-mcp\n"
    "    required_permission: read_data\n"
)


@pytest.fixture
def captured_audits(monkeypatch: pytest.MonkeyPatch) -> list[AuditRecord]:
    """Capture every ``write_audit`` call made from api/credentials.py."""
    records: list[AuditRecord] = []

    async def _fake_write_audit(record: AuditRecord) -> None:
        records.append(record)

    monkeypatch.setattr(credentials_api, "write_audit", _fake_write_audit)
    return records


async def _fake_authenticate(self: VaultKV) -> str:
    return "vault-test-token"


@pytest.fixture
def servicex_redeem_env(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> Callable[..., None]:
    """Configure a servicex-token identity provider for target 'servicex-backend' with a real signing key and a stubbed Vault."""

    def _apply(
        services_yaml: str = _BACKENDS_YAML,
        servicex_targets: list[str] | None = None,
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
                        "type": "servicex-token",
                        "alias": "servicex",
                        "display_name": "ServiceX access token",
                        "targets": servicex_targets or [_TARGET],
                        "service_url": "http://servicex-token-service.invalid",
                    }
                ]
            ),
        )
        key_file = tmp_path / "signing-key.pem"
        key_file.write_bytes(_private_pem(_make_rsa_key()))
        monkeypatch.setenv("BROKER_SIGNING_KEY_FILE", str(key_file))
        # A servicex-token entry always requires Vault (config.py's
        # _validate_vault_config); stub the trial auth the same way
        # test_krb5_redeem.py's krb5_redeem_env does.
        monkeypatch.setattr(VaultKV, "_authenticate", _fake_authenticate)
        monkeypatch.setenv("VAULT_ADDR", "https://vault.invalid")
        monkeypatch.setenv("VAULT_AUTH_ROLE", "af-mcp-broker")

    return _apply


def _fake_vault_store(client: TestClient, target: str = _TARGET) -> FakeServiceXStore:
    """Resolve *target*'s ServiceXProvider and swap in a FakeServiceXStore, returning it."""
    provider = asyncio.run(client.app.state.credential_registry.resolve(target))
    store = FakeServiceXStore()
    provider._vault_store = store
    return store


def _fake_service_client(
    client: TestClient, target: str = _TARGET, **kwargs: Any
) -> FakeServiceXClient:
    """Resolve *target*'s ServiceXProvider and swap in a scriptable fake service client."""
    provider = asyncio.run(client.app.state.credential_registry.resolve(target))
    fake_client = FakeServiceXClient(**kwargs)
    provider._servicex_client = fake_client
    return fake_client


def _mint(
    client: TestClient, *, subject: str = "sub-abc", audience: str = _TARGET
) -> str:
    token, _ = client.app.state.broker_token_issuer.mint(subject, audience)
    return str(token)


class TestRedeemAuth:
    def test_missing_authorization_is_401(
        self, servicex_redeem_env, app_client_factory
    ) -> None:
        servicex_redeem_env()
        with app_client_factory() as (client, _):
            resp = client.post(_REDEEM, json={})
        assert resp.status_code == 401

    def test_garbage_token_is_401(
        self, servicex_redeem_env, app_client_factory
    ) -> None:
        servicex_redeem_env()
        with app_client_factory() as (client, _):
            resp = client.post(
                _REDEEM, json={}, headers={"Authorization": "Bearer nonsense"}
            )
        assert resp.status_code == 401

    def test_non_servicex_audience_is_403(
        self, servicex_redeem_env, app_client_factory
    ) -> None:
        servicex_redeem_env()
        with app_client_factory() as (client, _):
            token = _mint(client, audience="condor-token-service")
            resp = client.post(
                _REDEEM, json={}, headers={"Authorization": f"Bearer {token}"}
            )
        assert resp.status_code == 403
        assert "not a configured servicex target" in resp.json()["detail"]

    def test_non_servicex_audience_denial_is_audited(
        self, servicex_redeem_env, app_client_factory, captured_audits
    ) -> None:
        servicex_redeem_env()
        with app_client_factory() as (client, _):
            token = _mint(client, audience="condor-token-service")
            resp = client.post(
                _REDEEM, json={}, headers={"Authorization": f"Bearer {token}"}
            )
        assert resp.status_code == 403
        assert len(captured_audits) == 1
        record = captured_audits[0]
        assert record.action == "servicex_token_release"
        assert record.outcome == "denied"
        assert record.target == "condor-token-service"
        assert record.principal_sub == "sub-abc"
        assert "not a configured servicex target" in (record.error or "")

    def test_redeem_maps_audience_to_target_when_name_differs(
        self, servicex_redeem_env, app_client_factory
    ) -> None:
        """issue #257 regression (servicex side): for a servicex service
        whose name and audience diverge (name=servicex_backend_service,
        audience=servicex-backend-mcp), the broker mints tokens with
        aud=servicex-backend-mcp. The redeem endpoint must map that audience
        back to the servicex target ('servicex_backend_service') and serve
        the token stored under it."""
        servicex_redeem_env(
            services_yaml=_DIVERGENT_YAML,
            servicex_targets=["servicex_backend_service"],
        )
        with app_client_factory() as (client, _):
            store = _fake_vault_store(client, target="servicex_backend_service")
            asyncio.run(
                store.store_link(
                    "sub-abc",
                    refresh_token=SecretStr("rt"),
                )
            )
            asyncio.run(
                store.store_token(
                    "sub-abc",
                    access_token="cached-access-token",
                    expires_at=time.time() + 3600,
                )
            )
            token = _mint(client, audience="servicex-backend-mcp")
            resp = client.post(
                _REDEEM, json={}, headers={"Authorization": f"Bearer {token}"}
            )
        assert resp.status_code == 200, resp.text
        assert resp.json()["access_token"] == "cached-access-token"


class TestRedeem:
    def test_no_link_anywhere_is_404_with_actionable_detail(
        self, servicex_redeem_env, app_client_factory
    ) -> None:
        servicex_redeem_env()
        with app_client_factory() as (client, _):
            _fake_vault_store(client)
            token = _mint(client)
            resp = client.post(
                _REDEEM, json={}, headers={"Authorization": f"Bearer {token}"}
            )
        assert resp.status_code == 404
        assert "/v1/servicex/link" in resp.json()["detail"]

    def test_stored_token_is_served_without_calling_the_service(
        self, servicex_redeem_env, app_client_factory
    ) -> None:
        servicex_redeem_env()
        with app_client_factory() as (client, _):
            store = _fake_vault_store(client)
            fake_client = _fake_service_client(client)
            asyncio.run(
                store.store_link(
                    "sub-abc",
                    refresh_token=SecretStr("rt"),
                )
            )
            asyncio.run(
                store.store_token(
                    "sub-abc",
                    access_token="cached-access-token",
                    expires_at=time.time() + 3600,
                )
            )
            token = _mint(client)
            resp = client.post(
                _REDEEM, json={}, headers={"Authorization": f"Bearer {token}"}
            )
        assert resp.status_code == 200, resp.text
        assert resp.json()["access_token"] == "cached-access-token"
        assert fake_client.calls == []

    def test_no_stored_token_but_linked_redeems_hands_free(
        self, servicex_redeem_env, app_client_factory
    ) -> None:
        servicex_redeem_env()
        with app_client_factory() as (client, _):
            store = _fake_vault_store(client)
            fake_client = _fake_service_client(client, outcome=_redeemed())
            asyncio.run(
                store.store_link(
                    "sub-abc",
                    refresh_token=SecretStr("rt"),
                )
            )
            token = _mint(client)
            resp = client.post(
                _REDEEM, json={}, headers={"Authorization": f"Bearer {token}"}
            )
        assert resp.status_code == 200, resp.text
        assert len(fake_client.calls) == 1

    def test_rejected_refresh_token_unlinks_and_returns_404(
        self, servicex_redeem_env, app_client_factory
    ) -> None:
        servicex_redeem_env()
        with app_client_factory() as (client, _):
            store = _fake_vault_store(client)
            _fake_service_client(client, outcome=ServiceXBadRefreshTokenError())
            asyncio.run(
                store.store_link(
                    "sub-abc",
                    refresh_token=SecretStr("rt"),
                )
            )
            token = _mint(client)
            resp = client.post(
                _REDEEM, json={}, headers={"Authorization": f"Bearer {token}"}
            )
        assert resp.status_code == 404
        assert "unlinked" in resp.json()["detail"] or "Re-link" in resp.json()["detail"]

    def test_infra_failure_returns_502(
        self, servicex_redeem_env, app_client_factory
    ) -> None:
        servicex_redeem_env()
        with app_client_factory() as (client, _):
            store = _fake_vault_store(client)
            _fake_service_client(client, outcome=ServiceXServiceMintError("down"))
            asyncio.run(
                store.store_link(
                    "sub-abc",
                    refresh_token=SecretStr("rt"),
                )
            )
            token = _mint(client)
            resp = client.post(
                _REDEEM, json={}, headers={"Authorization": f"Bearer {token}"}
            )
        assert resp.status_code == 502
