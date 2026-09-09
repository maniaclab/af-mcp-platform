"""Tests for the portal-facing ServiceX link endpoint (issue #295).

POST /v1/servicex/link is authenticated by a Keycloak token (via
``keycloak_dependency``, same as POST /v1/x509/proxy) -- the user pastes
their ServiceX personal refresh token here. ``ServiceXProvider.link``
verifies it with one redeem before persisting anything, so a bad token
never gets silently stored (mirrors POST /v1/x509/proxy's bad-passphrase
handling, see test_x509_identity_provider.py).
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest
from test_broker_issued import _make_rsa_key, _private_pem
from test_servicex import FakeServiceXClient, FakeServiceXStore

from af_mcp_broker.credentials.servicex_service import (
    ServiceXBadRefreshTokenError,
    ServiceXServiceMintError,
)
from af_mcp_broker.vault_kv import VaultKV

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from fastapi.testclient import TestClient

_LINK = "/v1/servicex/link"
_TARGET = "servicex-target"

_BACKENDS_YAML = (
    "services:\n"
    "  - name: servicex-target\n"
    "    prefix: servicex\n"
    "    url: http://servicex-target.invalid/mcp\n"
    "    auth_type: bearer\n"
    "    required_permission: read_data\n"
)


async def _fake_authenticate(self: VaultKV) -> str:
    return "vault-test-token"


@pytest.fixture
def servicex_link_env(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> Callable[..., None]:
    def _apply() -> None:
        services_file = tmp_path / "services.yaml"
        services_file.write_text(_BACKENDS_YAML)
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
                        "targets": [_TARGET],
                        "service_url": "http://servicex-token-service.invalid",
                    }
                ]
            ),
        )
        key_file = tmp_path / "signing-key.pem"
        key_file.write_bytes(_private_pem(_make_rsa_key()))
        monkeypatch.setenv("BROKER_SIGNING_KEY_FILE", str(key_file))
        monkeypatch.setattr(VaultKV, "_authenticate", _fake_authenticate)
        monkeypatch.setenv("VAULT_ADDR", "https://vault.invalid")
        monkeypatch.setenv("VAULT_AUTH_ROLE", "af-mcp-broker")

    return _apply


def _fake_provider(client: TestClient, **kwargs: object) -> FakeServiceXClient:
    """Swap in a fake Vault store and a scriptable fake service client for the 'servicex' entry.

    A real VaultServiceXStore would otherwise make a genuine HTTP call to
    the stubbed-auth-only VaultKV's unreachable https://vault.invalid on
    any successful link -- the same reason test_servicex_redeem.py's
    _fake_vault_store swaps the store out entirely.
    """
    provider = client.app.state.identity_providers["servicex"]
    provider._vault_store = FakeServiceXStore()
    fake_client = FakeServiceXClient(**kwargs)
    provider._servicex_client = fake_client
    return fake_client


class TestLink:
    def test_valid_refresh_token_links_and_returns_metadata(
        self, servicex_link_env, app_client_factory
    ) -> None:
        servicex_link_env()
        with app_client_factory() as (client, _):
            _fake_provider(client)
            resp = client.post(_LINK, json={"refresh_token": "a-refresh-token"})

        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["target"] == _TARGET
        assert body["remaining_seconds"] > 0
        assert "access_token" not in body

    def test_bad_refresh_token_is_400_and_stores_nothing(
        self, servicex_link_env, app_client_factory
    ) -> None:
        servicex_link_env()
        with app_client_factory() as (client, _):
            _fake_provider(client, outcome=ServiceXBadRefreshTokenError())
            resp = client.post(_LINK, json={"refresh_token": "bad-token"})

        assert resp.status_code == 400

    def test_infra_failure_is_502(self, servicex_link_env, app_client_factory) -> None:
        servicex_link_env()
        with app_client_factory() as (client, _):
            _fake_provider(client, outcome=ServiceXServiceMintError("down"))
            resp = client.post(_LINK, json={"refresh_token": "a-token"})

        assert resp.status_code == 502

    def test_explicit_target_selects_that_entry(
        self, servicex_link_env, app_client_factory
    ) -> None:
        servicex_link_env()
        with app_client_factory() as (client, _):
            _fake_provider(client)
            resp = client.post(
                _LINK,
                json={"refresh_token": "a-refresh-token", "target": _TARGET},
            )

        assert resp.status_code == 201, resp.text
        assert resp.json()["target"] == _TARGET

    def test_unknown_target_is_404(self, servicex_link_env, app_client_factory) -> None:
        servicex_link_env()
        with app_client_factory() as (client, _):
            resp = client.post(
                _LINK,
                json={"refresh_token": "a-refresh-token", "target": "nope"},
            )

        assert resp.status_code == 404
