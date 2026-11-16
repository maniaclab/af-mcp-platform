"""Unit tests for the credential-subsystem builders (``wiring/credentials.py``)."""

from __future__ import annotations

import asyncio
from contextlib import AsyncExitStack
from typing import TYPE_CHECKING, Any

import httpx2
import pytest
from cryptography.fernet import Fernet

from af_mcp_broker.config import (
    BrokerIssuedProviderConfig,
    KeycloakBrokeredProviderConfig,
    OAuth21DirectProviderConfig,
    Settings,
    X509ProviderConfig,
)
from af_mcp_broker.credentials import (
    BrokerIssuedProvider,
    CredentialCache,
    CredentialRegistry,
    InMemoryTokenStore,
    OAuth21Provider,
    OIDCProvider,
    VaultTokenStore,
    X509Provider,
)
from af_mcp_broker.credentials.stores import VaultLinkStores
from af_mcp_broker.credentials.x509_vault import VaultX509Store
from af_mcp_broker.service_registry import ServiceRegistry
from af_mcp_broker.shared_state import InMemorySharedState
from af_mcp_broker.vault_kv import VaultConnections
from af_mcp_broker.wiring.credentials import (
    build_broker_token_issuer,
    build_credential_cache,
    build_credential_providers,
    build_list_cache_invalidator,
    build_state_cipher,
    resolve_x509_provider,
)

if TYPE_CHECKING:
    from pathlib import Path

_ORIGIN = "https://mcp.example.com"


def _oauth21_entry() -> OAuth21DirectProviderConfig:
    return OAuth21DirectProviderConfig(
        alias="backend-as",
        targets=["backend"],
        authorization_endpoint="https://as.invalid/authorize",
        token_endpoint="https://as.invalid/token",
        issuer="https://as.invalid",
    )


def _settings(**overrides: Any) -> Settings:
    return Settings(
        oidc_issuer="https://kc.invalid/realms/x",
        vault_addr="https://vault.invalid",
        vault_kv_root="mcp",
        vault_auth_role="r",
        broker_public_origin=_ORIGIN,
        broker_state_key=Fernet.generate_key().decode(),
        oauth21_client_id=f"{_ORIGIN}/.well-known/cimd",
        **overrides,
    )


@pytest.fixture
def vaults() -> VaultConnections:
    return VaultConnections(httpx2.AsyncClient())


class TestBuildStateCipher:
    def test_is_none_when_no_flow_needs_it(self) -> None:
        assert build_state_cipher(_settings()) is None

    def test_exists_for_an_oauth21_direct_entry(self) -> None:
        cipher = build_state_cipher(_settings(identity_providers=[_oauth21_entry()]))

        assert isinstance(cipher, Fernet)

    def test_exists_for_the_mcp_oauth_bootstrap(self) -> None:
        cipher = build_state_cipher(
            _settings(
                TOKEN_MINT_CLIENT_ID="login-client",
                TOKEN_MINT_CLIENT_SECRET="s",
            )
        )

        assert isinstance(cipher, Fernet)


class TestBuildBrokerTokenIssuer:
    def test_is_none_without_a_key_and_without_entries_that_need_one(self) -> None:
        settings = _settings(
            identity_providers=[
                KeycloakBrokeredProviderConfig(alias="oidc", targets=["rucio"])
            ]
        )

        assert build_broker_token_issuer(settings) is None

    def test_loads_the_issuer_when_a_key_is_configured(
        self, broker_signing_key_file: Path
    ) -> None:
        settings = _settings(broker_signing_key_file=str(broker_signing_key_file))

        assert build_broker_token_issuer(settings) is not None

    def test_refuses_an_entry_that_needs_a_key_when_none_is_configured(self) -> None:
        settings = _settings(
            identity_providers=[
                BrokerIssuedProviderConfig(alias="broker", targets=["docs", "other"])
            ]
        )

        with pytest.raises(
            RuntimeError,
            match=r"BROKER_SIGNING_KEY_FILE is not set\. Affected services: "
            r"docs, other \(broker-issued entry 'broker'\)",
        ):
            build_broker_token_issuer(settings)


class TestStartedResourcesCloseWithTheStack:
    async def test_invalidator_and_cache_janitor_stop_when_the_stack_closes(
        self,
    ) -> None:
        settings = _settings()
        shared_state = InMemorySharedState()
        async with AsyncExitStack() as stack:
            invalidator = build_list_cache_invalidator(
                shared_state, backend_providers=_NoProviders(), stack=stack
            )
            cache = build_credential_cache(settings, shared_state, invalidator, stack)
            await asyncio.sleep(0)
            assert cache._janitor_task is not None
            assert not cache._janitor_task.done()
            janitor = cache._janitor_task

        assert janitor.done()


class _NoProviders:
    """A ``BackendProviders`` with nothing registered."""

    def items(self) -> list[tuple[str, Any]]:
        return []

    def values(self) -> list[Any]:
        return []


class TestBuildCredentialProviders:
    def _build(
        self,
        settings: Settings,
        *,
        issuer: Any = None,
    ):
        registry = ServiceRegistry()
        cache = build_credential_cache_for_tests(settings)
        return build_credential_providers(
            settings,
            service_registry=registry,
            cache=cache,
            issuer=issuer,
            vaults=VaultConnections(httpx2.AsyncClient()),
            http_client=httpx2.AsyncClient(),
        )

    def test_builds_one_provider_per_entry_in_config_order_and_registers_targets(
        self,
    ) -> None:
        settings = _settings(
            identity_providers=[
                KeycloakBrokeredProviderConfig(alias="oidc", targets=["rucio", "ami"]),
                _oauth21_entry(),
            ]
        )

        built = self._build(settings)

        assert list(built.providers) == ["oidc", "backend-as"]
        assert isinstance(built.providers["oidc"], OIDCProvider)
        assert isinstance(built.providers["backend-as"], OAuth21Provider)
        assert list(built.configs) == ["oidc", "backend-as"]
        assert isinstance(built.registry, CredentialRegistry)
        for target, alias in [
            ("rucio", "oidc"),
            ("ami", "oidc"),
            ("backend", "backend-as"),
        ]:
            assert asyncio.run(built.registry.resolve(target)) is built.providers[alias]

    def test_a_broker_issued_entry_needs_the_issuer(
        self, broker_signing_key_file: Path
    ) -> None:
        settings = _settings(
            identity_providers=[
                BrokerIssuedProviderConfig(alias="b", targets=["docs"])
            ],
            broker_signing_key_file=str(broker_signing_key_file),
        )
        issuer = build_broker_token_issuer(settings)

        built = self._build(settings, issuer=issuer)

        assert isinstance(built.providers["b"], BrokerIssuedProvider)

    def test_an_issuer_less_broker_token_entry_is_an_invariant_error(self) -> None:
        settings = _settings(
            identity_providers=[BrokerIssuedProviderConfig(alias="b", targets=["docs"])]
        )

        with pytest.raises(RuntimeError, match="no signing key is configured"):
            self._build(settings)

    def test_an_x509_entry_builds_the_x509_store_it_shares_with_its_provider(
        self, broker_signing_key_file: Path
    ) -> None:
        settings = _settings(
            identity_providers=[
                X509ProviderConfig(
                    voms="atlas",
                    alias="x509",
                    targets=["ami"],
                    service_url="http://v.invalid",
                )
            ],
            broker_signing_key_file=str(broker_signing_key_file),
        )

        built = self._build(settings, issuer=build_broker_token_issuer(settings))

        provider = built.providers["x509"]
        assert isinstance(provider, X509Provider)
        assert isinstance(built.link_stores.x509, VaultX509Store)
        assert provider.vault_store is built.link_stores.x509
        assert built.link_stores.krb5 is None
        assert built.link_stores.servicex is None

    def test_no_link_store_is_built_without_an_entry_that_needs_one(self) -> None:
        built = self._build(_settings())

        assert built.link_stores == VaultLinkStores()

    def test_no_token_store_is_built_without_an_oauth21_entry(self) -> None:
        assert self._build(_settings()).oauth21_token_store is None

    @pytest.mark.parametrize(
        ("backend", "expected"),
        [("in_memory", InMemoryTokenStore), ("vault", VaultTokenStore)],
    )
    def test_an_oauth21_entry_builds_the_token_store_its_backend_selects(
        self, backend: str, expected: type
    ) -> None:
        settings = _settings(
            identity_providers=[_oauth21_entry()], token_store_backend=backend
        )

        built = self._build(settings)

        assert isinstance(built.oauth21_token_store, expected)


def build_credential_cache_for_tests(settings: Settings) -> Any:
    return CredentialCache(
        max_failed_unlocks=settings.credential_unlock_max_failures,
        unlock_window_seconds=settings.credential_unlock_window_seconds,
        shared_state=InMemorySharedState(),
    )


class TestResolveX509Provider:
    async def test_is_none_without_x509_targets(self) -> None:
        assert await resolve_x509_provider(CredentialRegistry(), []) is None

    async def test_returns_the_provider_of_the_first_target(
        self, broker_signing_key_file: Path
    ) -> None:
        settings = _settings(
            identity_providers=[
                X509ProviderConfig(
                    voms="atlas",
                    alias="x509",
                    targets=["ami", "ami2"],
                    service_url="http://v.invalid",
                )
            ],
            broker_signing_key_file=str(broker_signing_key_file),
        )
        built = build_credential_providers(
            settings,
            service_registry=ServiceRegistry(),
            cache=build_credential_cache_for_tests(settings),
            issuer=build_broker_token_issuer(settings),
            vaults=VaultConnections(httpx2.AsyncClient()),
            http_client=httpx2.AsyncClient(),
        )

        resolved = await resolve_x509_provider(built.registry, ["ami", "ami2"])

        assert resolved is built.providers["x509"]

    async def test_a_non_x509_provider_for_an_x509_target_is_a_type_error(self) -> None:
        settings = _settings(
            identity_providers=[
                KeycloakBrokeredProviderConfig(alias="oidc", targets=["ami"])
            ]
        )
        built = build_credential_providers(
            settings,
            service_registry=ServiceRegistry(),
            cache=build_credential_cache_for_tests(settings),
            issuer=None,
            vaults=VaultConnections(httpx2.AsyncClient()),
            http_client=httpx2.AsyncClient(),
        )

        with pytest.raises(TypeError, match="not X509Provider"):
            await resolve_x509_provider(built.registry, ["ami"])
