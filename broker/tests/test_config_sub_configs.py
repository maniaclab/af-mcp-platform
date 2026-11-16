"""The typed sub-configs ``Settings`` derives from its flat env-shaped fields."""

from __future__ import annotations

import pytest

from af_mcp_broker.config import (
    CredmonApiConfig,
    InMemoryMaintenanceStoreConfig,
    InMemoryUsageStoreConfig,
    PostgresMaintenanceStoreConfig,
    PostgresUsageStoreConfig,
    Settings,
    VaultConfig,
    VaultMaintenanceStoreConfig,
)

_VAULT = {
    "vault_addr": "https://vault.example",
    "vault_auth_role": "af-mcp-broker",
    "vault_kv_root": "mcp",
}


class TestVaultConfig:
    def test_absent_when_no_subsystem_uses_vault(self) -> None:
        assert Settings(_env_file=None).vault is None

    def test_carries_the_connection_settings_when_a_backend_selects_vault(self) -> None:
        settings = Settings(
            _env_file=None,
            token_registry_backend="vault",
            vault_auth_mount="k8s",
            vault_kv_mount="kv",
            vault_sa_token_path="/sa/token",
            **_VAULT,
        )

        assert settings.vault == VaultConfig(
            addr="https://vault.example",
            auth_mount="k8s",
            auth_role="af-mcp-broker",
            kv_mount="kv",
            sa_token_path="/sa/token",
        )


class TestCredmonApiConfig:
    def test_absent_when_credmon_is_disabled(self) -> None:
        assert Settings(_env_file=None).credmon_api is None

    def test_carries_the_api_settings_when_credmon_is_enabled(self) -> None:
        settings = Settings(
            _env_file=None,
            credmon_enabled=True,
            credmon_htcondor_api_url="https://htcondor-api.example",
            credmon_htcondor_api_token_file="/token",
            credmon_user_domain="af.example.org",
            token_store_backend="vault",
            **_VAULT,
        )

        api = settings.credmon_api
        assert isinstance(api, CredmonApiConfig)
        assert str(api.url) == "https://htcondor-api.example/"
        assert api.token_file == "/token"
        assert api.user_domain == "af.example.org"


class TestUsageStoreConfig:
    def test_in_memory_by_default(self) -> None:
        assert isinstance(
            Settings(_env_file=None).usage_store, InMemoryUsageStoreConfig
        )

    def test_postgres_carries_its_dsn(self) -> None:
        settings = Settings(
            _env_file=None,
            usage_store_backend="postgres",
            usage_postgres_dsn="postgresql://u:p@h/db",
        )

        store = settings.usage_store
        assert isinstance(store, PostgresUsageStoreConfig)
        assert store.dsn.get_secret_value() == "postgresql://u:p@h/db"


class TestMaintenanceStoreConfig:
    def test_in_memory_by_default(self) -> None:
        assert isinstance(
            Settings(_env_file=None).maintenance_store, InMemoryMaintenanceStoreConfig
        )

    def test_vault_carries_the_vault_connection(self) -> None:
        settings = Settings(_env_file=None, maintenance_mode_backend="vault", **_VAULT)

        store = settings.maintenance_store
        assert isinstance(store, VaultMaintenanceStoreConfig)
        assert store.vault == settings.vault

    def test_postgres_carries_its_own_dsn(self) -> None:
        settings = Settings(
            _env_file=None,
            maintenance_mode_backend="postgres",
            maintenance_mode_postgres_dsn="postgresql://m/db",
            usage_postgres_dsn="postgresql://u/db",
        )

        store = settings.maintenance_store
        assert isinstance(store, PostgresMaintenanceStoreConfig)
        assert store.dsn.get_secret_value() == "postgresql://m/db"

    def test_postgres_falls_back_to_the_usage_dsn(self) -> None:
        settings = Settings(
            _env_file=None,
            maintenance_mode_backend="postgres",
            usage_postgres_dsn="postgresql://u/db",
        )

        store = settings.maintenance_store
        assert isinstance(store, PostgresMaintenanceStoreConfig)
        assert store.dsn.get_secret_value() == "postgresql://u/db"


@pytest.mark.parametrize(
    "kwargs",
    [
        {"usage_store_backend": "postgres"},
        {"maintenance_mode_backend": "postgres"},
        {"credmon_enabled": True},
    ],
)
def test_a_selected_feature_without_its_settings_is_refused_at_construction(
    kwargs: dict[str, object],
) -> None:
    with pytest.raises(ValueError, match="must be set"):
        Settings(_env_file=None, **kwargs)
