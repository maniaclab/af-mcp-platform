"""App-level wiring for ServiceXProvider (issue #295).

Covers: provider registration from an ``identity_providers`` servicex-token
entry, the startup fail-closed checks (a servicex-token entry with no
broker signing key, or with no Vault connection configured, must both
refuse to boot -- the provider composes the same ``BrokerTokenIssuer`` as
condor-token/krb5-token, and its refresh token persists in Vault with no
in-memory fallback), and /v1/identities listing the provider's is_linked()
state. The provider unit tests (HTTP boundary stubbed) live in
test_servicex.py.
"""

from __future__ import annotations

import asyncio
import json
from typing import TYPE_CHECKING, Any

import pytest
from test_broker_issued import _make_rsa_key, _private_pem
from test_servicex import FakeServiceXStore

from af_mcp_broker.credentials import ServiceXProvider
from af_mcp_broker.credentials.servicex_vault import VaultServiceXStore
from af_mcp_broker.vault_kv import VaultKV

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

_SERVICEX_TOKEN_PROVIDERS = [
    {
        "type": "servicex-token",
        "alias": "servicex",
        "display_name": "ServiceX access token",
        "targets": ["servicex-target"],
        "service_url": "http://servicex-token-service.invalid",
    }
]

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
def servicex_token_env(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> Callable[..., None]:
    """Point the app at a servicex-token identity provider and (optionally) a real signing key on disk and a stubbed Vault connection.

    A servicex-token entry always requires Vault to be configured -- unlike
    x509 there is no legacy/service-mode split (service_url is mandatory on
    every entry), same reasoning as krb5-token
    (config.py's _validate_vault_config). Vault is therefore stubbed by
    default here the same way test_krb5_token_app.py's krb5_token_env stubs
    it: VaultKV's startup trial auth is faked out rather than requiring a
    real Vault.
    """

    def _apply(*, with_signing_key: bool = True, with_vault: bool = True) -> None:
        services_file = tmp_path / "services.yaml"
        services_file.write_text(_BACKENDS_YAML)
        monkeypatch.setenv("SERVICES_FILE", str(services_file))
        monkeypatch.setenv("IDENTITY_PROVIDERS", json.dumps(_SERVICEX_TOKEN_PROVIDERS))
        monkeypatch.setenv("BROKER_PUBLIC_ORIGIN", "https://mcp.example.com")
        if with_signing_key:
            key_file = tmp_path / "signing-key.pem"
            key_file.write_bytes(_private_pem(_make_rsa_key()))
            monkeypatch.setenv("BROKER_SIGNING_KEY_FILE", str(key_file))
        if with_vault:
            monkeypatch.setattr(VaultKV, "_authenticate", _fake_authenticate)
            monkeypatch.setenv("VAULT_ADDR", "https://vault.invalid")
            monkeypatch.setenv("VAULT_AUTH_ROLE", "af-mcp-broker")

    return _apply


def test_servicex_token_provider_registered_from_config(
    servicex_token_env, app_client_factory
) -> None:
    servicex_token_env()

    with app_client_factory() as (client, _):
        state = client.app.state
        assert state.broker_token_issuer is not None
        assert isinstance(state.identity_providers["servicex"], ServiceXProvider)
        provider = asyncio.run(state.credential_registry.resolve("servicex-target"))
        assert isinstance(provider, ServiceXProvider)
        # issue #90's catalog join: the target maps to the configured alias.
        assert state.target_to_alias["servicex-target"] == "servicex"


def test_servicex_vault_store_constructed_and_exposed_on_state(
    servicex_token_env, app_client_factory
) -> None:
    """Happy-path counterpart to the fail-closed tests below: a
    servicex-token entry with Vault configured must actually construct the
    shared VaultServiceXStore and expose it on app.state, not just refuse
    to boot without one."""
    servicex_token_env()

    with app_client_factory() as (client, _):
        state = client.app.state
        assert isinstance(state.servicex_vault_store, VaultServiceXStore)


def test_servicex_provider_wired_to_shared_vault_store(
    servicex_token_env, app_client_factory
) -> None:
    """The registered ServiceXProvider must be constructed with the same
    shared VaultServiceXStore instance exposed on app.state."""
    servicex_token_env()

    with app_client_factory() as (client, _):
        state = client.app.state
        provider = state.identity_providers["servicex"]
        assert isinstance(provider, ServiceXProvider)
        assert provider._vault_store is state.servicex_vault_store


def test_servicex_token_entry_without_signing_key_refuses_to_start(
    servicex_token_env, app_client_factory
) -> None:
    """Fail-closed, same as krb5-token/condor-token: ServiceXProvider mints
    its broker identity token through the shared BrokerTokenIssuer, so a
    servicex-token entry with no signing key configured must refuse to boot
    rather than fail at first request."""
    servicex_token_env(with_signing_key=False)

    with pytest.raises(RuntimeError, match="BROKER_SIGNING_KEY_FILE"):  # noqa: SIM117
        with app_client_factory():
            pass


def test_servicex_token_entry_without_vault_refuses_to_start(
    servicex_token_env, app_client_factory
) -> None:
    """Fail-closed, same reasoning as krb5-token: a servicex-token entry's
    refresh token persists in Vault with no in-memory fallback, so an entry
    with no Vault connection configured must refuse to boot rather than
    fail at first request."""
    servicex_token_env(with_vault=False)

    with pytest.raises(ValueError, match="vault_addr"):  # noqa: SIM117
        with app_client_factory():
            pass


def test_identities_lists_servicex_token_provider_as_linked(
    servicex_token_env, app_client_factory
) -> None:
    servicex_token_env()

    with app_client_factory() as (client, _):
        # is_linked() asks the vault store -- swap in the in-memory fake
        # (test_servicex.py's FakeServiceXStore) so this assertion doesn't
        # require a live Vault connection.
        client.app.state.identity_providers[
            "servicex"
        ]._vault_store = FakeServiceXStore()
        resp = client.get("/v1/identities")

    assert resp.status_code == 200, resp.text
    rows: list[dict[str, Any]] = resp.json()["providers"]
    (row,) = [r for r in rows if r["id"] == "servicex"]
    assert row["type"] == "servicex-token"
    assert row["linked"] is False
    assert row["link_url"] is None
    # A single-field paste (refresh token), same shape as x509's passphrase
    # -- distinct from krb5-token's two-field "credential" mechanism.
    assert row["link_mechanism"] == "passphrase"
