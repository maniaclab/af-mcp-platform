"""Unit tests for the identity-side builders (``wiring/identity.py``) and the Vault client builder (``wiring/vault.py``)."""

from __future__ import annotations

import json
from typing import Any

import httpx2
import pytest
from cryptography.fernet import Fernet

from af_mcp_broker.config import KeycloakBrokeredProviderConfig, Settings
from af_mcp_broker.mcp_auth_codes import McpAuthCodeStore
from af_mcp_broker.principal_cache import (
    InMemoryPrincipalCacheBackend,
    PrincipalCache,
    VaultPrincipalCacheBackend,
)
from af_mcp_broker.shared_state import InMemorySharedState
from af_mcp_broker.token_registry import (
    InMemoryTokenRegistryBackend,
    TokenRegistry,
    VaultTokenRegistryBackend,
)
from af_mcp_broker.vault_kv import VaultConnections, VaultKV
from af_mcp_broker.wiring.identity import (
    build_dev_bypass_principal,
    build_mcp_auth_code_store,
    build_principal_cache,
    build_token_registry,
)
from af_mcp_broker.wiring.vault import build_vault_connections

_DEV_PRINCIPAL = json.dumps(
    {
        "uid": 1000,
        "gid": 1000,
        "unixname": "devuser",
        "email": "dev@localhost",
        "groups": ["af-users"],
    }
)


def _settings(**overrides: Any) -> Settings:
    overrides.setdefault("oidc_issuer", "https://kc.invalid/realms/x")
    return Settings(
        vault_addr="https://vault.invalid",
        vault_kv_root="mcp",
        vault_auth_role="r",
        **overrides,
    )


@pytest.fixture
def vaults() -> VaultConnections:
    return VaultConnections(httpx2.AsyncClient())


class TestBuildDevBypassPrincipal:
    def test_is_none_when_the_bypass_is_off(self) -> None:
        assert build_dev_bypass_principal(_settings()) is None

    def test_parses_the_principal_for_a_local_issuer(self) -> None:
        settings = _settings(
            oidc_issuer="http://localhost:8081/realms/dev",
            BROKER_DEV_INSECURE_PRINCIPAL=_DEV_PRINCIPAL,
        )

        principal = build_dev_bypass_principal(settings)

        assert principal is not None
        assert principal.unixname == "devuser"

    def test_refuses_a_non_local_issuer(self) -> None:
        settings = _settings(BROKER_DEV_INSECURE_PRINCIPAL=_DEV_PRINCIPAL)

        with pytest.raises(RuntimeError, match="does not look like a local"):
            build_dev_bypass_principal(settings)

    @pytest.mark.parametrize(
        "issuer",
        [
            "http://[::1/realms/dev",  # urlparse raises ValueError
            "http:///realms/dev",  # no hostname
            "not-a-url",
            "https://localhost.example.org/realms/dev",
        ],
    )
    def test_refuses_an_issuer_it_cannot_prove_local(self, issuer: str) -> None:
        settings = _settings(
            oidc_issuer=issuer, BROKER_DEV_INSECURE_PRINCIPAL=_DEV_PRINCIPAL
        )

        with pytest.raises(RuntimeError, match="Refusing to start"):
            build_dev_bypass_principal(settings)

    def test_does_not_parse_the_payload_before_the_issuer_check(self) -> None:
        settings = _settings(BROKER_DEV_INSECURE_PRINCIPAL="{not json")

        with pytest.raises(RuntimeError, match="does not look like a local"):
            build_dev_bypass_principal(settings)


class TestBuildPrincipalCache:
    def test_builds_a_cache_when_the_admin_account_is_configured(self) -> None:
        settings = _settings(
            keycloak_admin_client_id="admin", keycloak_admin_client_secret="s"
        )

        cache = build_principal_cache(
            settings,
            VaultConnections(httpx2.AsyncClient()),
            httpx2.AsyncClient(),
            dev_bypass_active=False,
        )

        assert isinstance(cache, PrincipalCache)
        assert isinstance(cache._backend, InMemoryPrincipalCacheBackend)

    def test_uses_the_vault_backend_when_selected(
        self, vaults: VaultConnections
    ) -> None:
        settings = _settings(
            keycloak_admin_client_id="admin",
            keycloak_admin_client_secret="s",
            principal_cache_backend="vault",
        )

        cache = build_principal_cache(
            settings, vaults, httpx2.AsyncClient(), dev_bypass_active=False
        )

        assert cache is not None
        assert isinstance(cache._backend, VaultPrincipalCacheBackend)

    def test_is_none_under_the_dev_bypass_without_an_admin_account(self) -> None:
        assert (
            build_principal_cache(
                _settings(),
                VaultConnections(httpx2.AsyncClient()),
                httpx2.AsyncClient(),
                dev_bypass_active=True,
            )
            is None
        )

    def test_refuses_to_boot_without_an_admin_account_or_the_bypass(self) -> None:
        with pytest.raises(
            RuntimeError, match="KEYCLOAK_ADMIN_CLIENT_ID/KEYCLOAK_ADMIN_CLIENT_SECRET"
        ):
            build_principal_cache(
                _settings(),
                VaultConnections(httpx2.AsyncClient()),
                httpx2.AsyncClient(),
                dev_bypass_active=False,
            )


class TestBuildTokenRegistry:
    def test_wraps_the_in_memory_backend_by_default(self) -> None:
        built = build_token_registry(
            _settings(), VaultConnections(httpx2.AsyncClient()), InMemorySharedState()
        )

        assert isinstance(built.backend, InMemoryTokenRegistryBackend)
        assert isinstance(built.registry, TokenRegistry)

    def test_wraps_the_vault_backend_when_selected(
        self, vaults: VaultConnections
    ) -> None:
        settings = _settings(token_registry_backend="vault")

        built = build_token_registry(settings, vaults, InMemorySharedState())

        assert isinstance(built.backend, VaultTokenRegistryBackend)


class TestBuildMcpAuthCodeStore:
    def test_is_none_without_a_state_cipher(self) -> None:
        assert (
            build_mcp_auth_code_store(_settings(), None, InMemorySharedState()) is None
        )

    def test_is_built_over_the_cipher(self) -> None:
        store = build_mcp_auth_code_store(
            _settings(), Fernet(Fernet.generate_key()), InMemorySharedState()
        )

        assert isinstance(store, McpAuthCodeStore)


class TestBuildVaultConnections:
    async def test_authenticates_nothing_when_no_subsystem_uses_vault(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        calls: list[VaultKV] = []

        async def _authenticate(self: VaultKV) -> str:
            calls.append(self)
            return "token"

        monkeypatch.setattr(VaultKV, "_authenticate", _authenticate)

        await build_vault_connections(_settings(), httpx2.AsyncClient())

        assert calls == []

    async def test_authenticates_once_at_startup_when_a_subsystem_uses_vault(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        calls: list[VaultKV] = []

        async def _authenticate(self: VaultKV) -> str:
            calls.append(self)
            return "token"

        monkeypatch.setattr(VaultKV, "_authenticate", _authenticate)

        settings = _settings(maintenance_mode_backend="vault")
        built = await build_vault_connections(settings, httpx2.AsyncClient())

        assert settings.vault is not None
        assert calls == [built.connect(settings.vault)]

    async def test_a_failed_trial_authentication_refuses_to_boot(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async def _authenticate(self: VaultKV) -> str:
            raise OSError("SA token unreadable")

        monkeypatch.setattr(VaultKV, "_authenticate", _authenticate)

        with pytest.raises(
            RuntimeError, match="Vault K8s auth failed at startup: SA token unreadable"
        ):
            await build_vault_connections(
                _settings(token_registry_backend="vault"), httpx2.AsyncClient()
            )

    def test_an_identity_entry_that_persists_in_vault_counts_as_using_vault(
        self,
    ) -> None:
        settings = _settings(
            identity_providers=[KeycloakBrokeredProviderConfig(alias="o", targets=[])]
        )

        assert settings.uses_vault is False
        assert _settings(principal_cache_backend="vault").uses_vault is True
