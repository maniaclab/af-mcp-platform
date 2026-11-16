"""Every Vault KV prefix is derived from the one ``vault_kv_root`` setting."""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from af_mcp_broker.config import Settings, VaultKvPaths

# The KV prefixes brokers used when each store had its own prefix setting. The
# derived paths must equal them so no Vault record migrates.
#
# A second, narrower broker (condor only) never set the maintenance-mode,
# x509, krb5, servicex and credmon prefixes: it ran on the broker defaults
# (mcp/...), but used Postgres for maintenance mode and had no
# x509/krb5/servicex identity provider and credmon disabled, so those five
# stores are never built and nothing is stored under them. They are asserted
# at the root's own subtree.
_PRODUCTION_PLATFORM = {
    "tokens": "mcp/tokens",
    "token_registry": "mcp/token-registry",
    "principal_cache": "mcp/principal-cache",
    "maintenance_mode": "mcp/maintenance-mode",
    "x509": "mcp/x509",
    "krb5": "mcp/krb5",
    "servicex": "mcp/servicex",
    "credmon_state": "mcp/credmon",
}
_NARROW_BROKER_LIVE_STORES = {
    "tokens": "example-ops/tokens",
    "token_registry": "example-ops/token-registry",
    "principal_cache": "example-ops/principal-cache",
}


def _derived(root: str) -> dict[str, str]:
    paths = VaultKvPaths(root=root)
    return {name: getattr(paths, name) for name in _PRODUCTION_PLATFORM}


def test_platform_root_derives_production_prefixes() -> None:
    assert _derived("mcp") == _PRODUCTION_PLATFORM


def test_narrow_broker_root_derives_prefixes_of_its_live_stores() -> None:
    derived = _derived("example-ops")
    for name, prefix in _NARROW_BROKER_LIVE_STORES.items():
        assert derived[name] == prefix


def test_narrow_broker_root_keeps_every_store_under_its_own_subtree() -> None:
    assert all(p.startswith("example-ops/") for p in _derived("example-ops").values())


def test_derived_prefixes_are_distinct() -> None:
    derived = list(_derived("mcp").values())
    assert len(set(derived)) == len(derived)


@pytest.mark.parametrize("root", ["mcp/", "/mcp", "/mcp/"])
def test_root_slashes_are_stripped(root: str) -> None:
    assert _derived(root) == _PRODUCTION_PLATFORM


@pytest.mark.parametrize("root", ["", "/", "//"])
def test_empty_root_is_refused(root: str) -> None:
    with pytest.raises(ValidationError):
        VaultKvPaths(root=root)


_VAULT_CONNECTION: dict[str, Any] = {
    "vault_addr": "https://vault.example.com",
    "vault_auth_role": "r",
}


def test_settings_derive_paths_from_vault_kv_root() -> None:
    settings = Settings(
        _env_file=None,
        token_store_backend="vault",
        vault_kv_root="example-ops",
        **_VAULT_CONNECTION,
    )
    assert settings.vault_kv_paths.tokens == "example-ops/tokens"


@pytest.mark.parametrize(
    "backend",
    [
        "token_store_backend",
        "token_registry_backend",
        "principal_cache_backend",
        "maintenance_mode_backend",
    ],
)
def test_vault_without_root_fails_boot(backend: str) -> None:
    with pytest.raises(ValidationError, match="vault_kv_root"):
        Settings(_env_file=None, **{backend: "vault"}, **_VAULT_CONNECTION)


def test_vault_identity_provider_without_root_fails_boot() -> None:
    entry = {
        "type": "servicex-token",
        "alias": "servicex",
        "targets": ["servicex"],
        "service_url": "http://servicex-token-service.invalid",
    }
    with pytest.raises(ValidationError, match="vault_kv_root"):
        Settings(_env_file=None, identity_providers=[entry], **_VAULT_CONNECTION)


def test_root_is_not_required_without_vault() -> None:
    assert Settings(_env_file=None).vault is None


@pytest.mark.parametrize("name", sorted(_PRODUCTION_PLATFORM))
def test_individual_prefix_settings_are_gone(name: str) -> None:
    removed = {
        "tokens": "vault_kv_path_prefix",
        "token_registry": "token_registry_kv_path_prefix",
        "principal_cache": "principal_cache_kv_path_prefix",
        "maintenance_mode": "maintenance_mode_kv_path_prefix",
        "x509": "x509_kv_path_prefix",
        "krb5": "krb5_kv_path_prefix",
        "servicex": "servicex_kv_path_prefix",
        "credmon_state": "credmon_state_kv_path_prefix",
    }[name]
    assert removed not in Settings.model_fields
