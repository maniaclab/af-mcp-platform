"""Unit tests for the config-Literal backend selectors.

Every ``*_backend`` setting is a ``Literal``; each selector is a ``match`` that
``assert_never`` makes exhaustive for mypy. These tests parametrize over the
Literal's own values (``typing.get_args``) so a value added to config.py with
no selector branch fails here at runtime too.
"""

from __future__ import annotations

from typing import Any, get_args, get_type_hints

import pytest

from af_mcp_broker.config import Settings
from af_mcp_broker.credentials import InMemoryTokenStore, VaultTokenStore
from af_mcp_broker.credentials.stores import build_token_store
from af_mcp_broker.errors import require
from af_mcp_broker.maintenance import (
    CachingMaintenanceModeStore,
    InMemoryMaintenanceModeStore,
    PostgresMaintenanceModeStore,
    VaultMaintenanceModeStore,
    build_maintenance_store,
)
from af_mcp_broker.metering import InProcessMeteringBackend, build_metering_backend
from af_mcp_broker.principal_cache import (
    InMemoryPrincipalCacheBackend,
    VaultPrincipalCacheBackend,
    build_principal_cache_backend,
)
from af_mcp_broker.token_registry import (
    InMemoryTokenRegistryBackend,
    VaultTokenRegistryBackend,
    build_token_registry_backend,
)
from af_mcp_broker.usage import (
    InMemoryUsageStore,
    PostgresUsageStore,
    build_usage_store,
)
from af_mcp_broker.vault_kv import VaultKV

_DSN = "postgresql://u:p@localhost/db"


def _literal_values(field: str) -> tuple[str, ...]:
    hint = get_type_hints(Settings)[field]
    assert get_args(hint), field
    return get_args(hint)


@pytest.fixture
def vault_kv() -> VaultKV:
    return VaultKV(
        addr="https://vault.invalid",
        auth_mount="kubernetes",
        auth_role="r",
        kv_mount="secret",
        sa_token_path="/nonexistent",
    )


def _settings(**overrides: Any) -> Settings:
    return Settings(
        oidc_issuer="https://kc.invalid/realms/x",
        vault_addr="https://vault.invalid",
        vault_auth_role="r",
        maintenance_mode_postgres_dsn=_DSN,
        usage_postgres_dsn=_DSN,
        **overrides,
    )


def test_require_returns_a_present_value() -> None:
    assert require(3, "never raised") == 3


def test_require_raises_with_the_message_for_none() -> None:
    with pytest.raises(RuntimeError, match="the invariant"):
        require(None, "the invariant")


@pytest.mark.parametrize("backend", _literal_values("token_store_backend"))
def test_token_store_covers_every_backend(backend: str, vault_kv: VaultKV) -> None:
    store = build_token_store(_settings(token_store_backend=backend), vault_kv)
    expected = {"in_memory": InMemoryTokenStore, "vault": VaultTokenStore}[backend]
    assert isinstance(store, expected)


@pytest.mark.parametrize("backend", _literal_values("token_registry_backend"))
def test_token_registry_covers_every_backend(backend: str, vault_kv: VaultKV) -> None:
    built = build_token_registry_backend(
        _settings(token_registry_backend=backend), vault_kv
    )
    expected = {
        "in_memory": InMemoryTokenRegistryBackend,
        "vault": VaultTokenRegistryBackend,
    }[backend]
    assert isinstance(built, expected)


@pytest.mark.parametrize("backend", _literal_values("principal_cache_backend"))
def test_principal_cache_backend_covers_every_backend(
    backend: str, vault_kv: VaultKV
) -> None:
    built = build_principal_cache_backend(
        _settings(principal_cache_backend=backend), vault_kv
    )
    expected = {
        "in_memory": InMemoryPrincipalCacheBackend,
        "vault": VaultPrincipalCacheBackend,
    }[backend]
    assert isinstance(built, expected)


@pytest.mark.parametrize("backend", _literal_values("maintenance_mode_backend"))
def test_maintenance_store_covers_every_backend(
    backend: str, vault_kv: VaultKV
) -> None:
    built = build_maintenance_store(
        _settings(maintenance_mode_backend=backend), vault_kv
    )
    expected = {
        "in_memory": InMemoryMaintenanceModeStore,
        # Network-backed stores sit behind the TTL cache by default.
        "vault": CachingMaintenanceModeStore,
        "postgres": CachingMaintenanceModeStore,
    }[backend]
    assert isinstance(built, expected)


@pytest.mark.parametrize(
    ("backend", "inner"),
    [("vault", VaultMaintenanceModeStore), ("postgres", PostgresMaintenanceModeStore)],
)
def test_maintenance_store_is_unwrapped_when_the_cache_ttl_is_zero(
    backend: str, inner: type, vault_kv: VaultKV
) -> None:
    built = build_maintenance_store(
        _settings(
            maintenance_mode_backend=backend, maintenance_mode_cache_ttl_seconds=0
        ),
        vault_kv,
    )
    assert isinstance(built, inner)


@pytest.mark.parametrize("backend", _literal_values("usage_store_backend"))
def test_usage_store_covers_every_backend(backend: str) -> None:
    built = build_usage_store(_settings(usage_store_backend=backend))
    expected = {"in_memory": InMemoryUsageStore, "postgres": PostgresUsageStore}[
        backend
    ]
    assert isinstance(built, expected)


@pytest.mark.parametrize("backend", _literal_values("metering_backend"))
def test_metering_backend_covers_every_backend(backend: str) -> None:
    built = build_metering_backend(_settings(metering_backend=backend))
    assert isinstance(built, {"in_process": InProcessMeteringBackend}[backend])
