"""App-level wiring for KrbTokenProvider (issue #274).

Covers: provider registration from an ``identity_providers`` krb5-token
entry, the startup fail-closed checks (a krb5-token entry with no broker
signing key, or with no Vault connection configured, must both refuse to
boot -- the provider composes the same ``BrokerTokenIssuer`` as
broker-issued/condor-token, and its optional "remember" feature persists in
Vault with no in-memory fallback), and /v1/identities listing the
provider's is_linked() state. The provider unit tests (HTTP boundary
stubbed) live in test_krb5_token.py.
"""

from __future__ import annotations

import asyncio
import json
from typing import TYPE_CHECKING, Any

import pytest
from test_broker_issued import _make_rsa_key, _private_pem

from af_mcp_broker.credentials import KrbTokenProvider
from af_mcp_broker.credentials.krb5_vault import Krb5VaultStore
from af_mcp_broker.vault_kv import VaultKV

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

_KRB5_TOKEN_PROVIDERS = [
    {
        "type": "krb5-token",
        "alias": "krb5",
        "display_name": "CERN Kerberos ticket",
        "targets": ["krb5-target"],
        "service_url": "http://krb5-token-service.invalid",
    }
]

_BACKENDS_YAML = (
    "services:\n"
    "  - name: krb5-target\n"
    "    prefix: krb5\n"
    "    url: http://krb5-target.invalid/mcp\n"
    "    auth_type: bearer\n"
    "    required_permission: read_data\n"
)


async def _fake_authenticate(self: VaultKV) -> str:
    return "vault-test-token"


@pytest.fixture
def krb5_token_env(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> Callable[..., None]:
    """Point the app at a krb5-token identity provider and (optionally) a real signing key on disk and a stubbed Vault connection.

    A krb5-token entry always requires Vault to be configured -- unlike
    x509 there is no legacy/service-mode split (service_url is mandatory on
    every entry), and a given entry can't declare ahead of time whether any
    caller will ever check "remember" (config.py's _validate_vault_config).
    Vault is therefore stubbed by default here the same way
    test_x509_service_mode.py's ``voms_service_env`` stubs it: VaultKV's
    startup trial auth is faked out rather than requiring a real Vault.
    """

    def _apply(*, with_signing_key: bool = True, with_vault: bool = True) -> None:
        services_file = tmp_path / "services.yaml"
        services_file.write_text(_BACKENDS_YAML)
        monkeypatch.setenv("SERVICES_FILE", str(services_file))
        monkeypatch.setenv("IDENTITY_PROVIDERS", json.dumps(_KRB5_TOKEN_PROVIDERS))
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


def test_krb5_token_provider_registered_from_config(
    krb5_token_env, app_client_factory
) -> None:
    krb5_token_env()

    with app_client_factory() as (client, _):
        state = client.app.state
        assert state.broker_token_issuer is not None
        assert isinstance(state.identity_providers["krb5"], KrbTokenProvider)
        provider = asyncio.run(state.credential_registry.resolve("krb5-target"))
        assert isinstance(provider, KrbTokenProvider)
        # issue #90's catalog join: the target maps to the configured alias.
        assert state.target_to_alias["krb5-target"] == "krb5"


def test_krb5_vault_store_constructed_and_exposed_on_state(
    krb5_token_env, app_client_factory
) -> None:
    """Happy-path counterpart to the fail-closed tests below: a krb5-token
    entry with Vault configured must actually construct the shared
    Krb5VaultStore and expose it on app.state, not just refuse to boot
    without one."""
    krb5_token_env()

    with app_client_factory() as (client, _):
        state = client.app.state
        assert isinstance(state.krb5_vault_store, Krb5VaultStore)


def test_krb5_token_entry_without_signing_key_refuses_to_start(
    krb5_token_env, app_client_factory
) -> None:
    """Fail-closed, same as broker-issued/condor-token: KrbTokenProvider mints
    its broker identity token through the shared BrokerTokenIssuer, so a
    krb5-token entry with no signing key configured must refuse to boot
    rather than fail at first request."""
    krb5_token_env(with_signing_key=False)

    with pytest.raises(RuntimeError, match="BROKER_SIGNING_KEY_FILE"):  # noqa: SIM117
        with app_client_factory():
            pass


def test_krb5_token_entry_without_vault_refuses_to_start(
    krb5_token_env, app_client_factory
) -> None:
    """Fail-closed, same reasoning as voms-token-service mode: krb5-token's
    optional "remember" feature persists in Vault with no in-memory
    fallback, and a krb5-token entry can't declare ahead of time whether any
    caller will ever check "remember" -- so a krb5-token entry with no Vault
    connection configured must refuse to boot rather than fail at first
    request. (test_config.py's test_vault_config_required_by_krb5_token_entry
    covers the same check directly at the Settings level.)"""
    krb5_token_env(with_vault=False)

    with pytest.raises(ValueError, match="vault_addr"):  # noqa: SIM117
        with app_client_factory():
            pass


def test_identities_lists_krb5_token_provider_as_linked(
    krb5_token_env, app_client_factory
) -> None:
    krb5_token_env()

    with app_client_factory() as (client, _):
        resp = client.get("/v1/identities")

    assert resp.status_code == 200, resp.text
    rows: list[dict[str, Any]] = resp.json()["providers"]
    (row,) = [r for r in rows if r["id"] == "krb5"]
    assert row["type"] == "krb5-token"
    # Unlike CondorTokenProvider's unconditional True, KrbTokenProvider's
    # is_linked() reflects live cache state (see credentials/krb5.py's
    # module docstring) -- a freshly-started app with nothing minted yet
    # has no cached ticket for any of the entry's targets.
    assert row["linked"] is False
    assert row["link_url"] is None
    # krb5-token needs username + password, two fields, not one -- distinct
    # from x509's "passphrase" (see identities.py's _LINK_MECHANISM_BY_TYPE).
    assert row["link_mechanism"] == "credential"
