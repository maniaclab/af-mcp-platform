"""The built subsystems, and their publication onto ``app.state``."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cryptography.fernet import Fernet
    from starlette.datastructures import State

    from af_mcp_broker.api.tokens import TokenRegistry
    from af_mcp_broker.config import Settings
    from af_mcp_broker.credentials import (
        BrokerTokenIssuer,
        CredentialCache,
        InMemoryTokenStore,
        VaultTokenStore,
        X509Provider,
    )
    from af_mcp_broker.credentials.stores import VaultLinkStores
    from af_mcp_broker.credmon.sync import CredmonSyncService
    from af_mcp_broker.lint_observations import LintObservationStore
    from af_mcp_broker.maintenance import MaintenanceModeStore
    from af_mcp_broker.mcp_auth_codes import McpAuthCodeStore
    from af_mcp_broker.principal_cache import PrincipalCache
    from af_mcp_broker.shared_state import SharedState
    from af_mcp_broker.usage import UsageStore
    from af_mcp_broker.wiring.credentials import CredentialProviders
    from af_mcp_broker.wiring.services import IdentityTargets, ServiceCatalog


@dataclass(frozen=True)
class BrokerState:
    """Every subsystem the request path reads off ``app.state``, as built by the lifespan."""

    settings: Settings
    catalog: ServiceCatalog
    targets: IdentityTargets
    credential_cache: CredentialCache
    providers: CredentialProviders
    x509_provider: X509Provider | None
    oauth21_token_store: InMemoryTokenStore | VaultTokenStore | None
    oauth21_state_cipher: Fernet | None
    token_registry: TokenRegistry
    principal_cache: PrincipalCache | None
    mcp_auth_code_store: McpAuthCodeStore | None
    broker_token_issuer: BrokerTokenIssuer | None
    usage_store: UsageStore
    maintenance_mode_store: MaintenanceModeStore
    lint_observations: LintObservationStore
    shared_state: SharedState
    link_stores: VaultLinkStores
    credmon_sync: CredmonSyncService | None

    def publish(self, state: State) -> None:
        """Assign each subsystem to the ``app.state`` attribute the routes and middleware read it from."""
        state.settings = self.settings
        state.entitlement_policy = self.catalog.entitlement_policy
        state.service_registry = self.catalog.service_registry
        state.services = self.catalog.services
        state.services_loaded = self.catalog.services_loaded
        state.credential_cache = self.credential_cache
        state.credential_registry = self.providers.registry
        state.x509_provider = self.x509_provider
        state.x509_targets = self.targets.x509_targets
        state.x509_audiences = self.targets.x509_audiences
        state.krb5_audiences = self.targets.krb5_audiences
        state.krb5_targets = self.targets.krb5_targets
        state.servicex_audiences = self.targets.servicex_audiences
        state.servicex_targets = self.targets.servicex_targets
        state.identity_providers = self.providers.providers
        state.identity_provider_configs = self.providers.configs
        state.target_to_alias = self.targets.target_to_alias
        state.oauth21_token_store = self.oauth21_token_store
        state.oauth21_state_cipher = self.oauth21_state_cipher
        state.token_registry = self.token_registry
        state.principal_cache = self.principal_cache
        state.mcp_auth_code_store = self.mcp_auth_code_store
        state.broker_token_issuer = self.broker_token_issuer
        state.usage_store = self.usage_store
        state.maintenance_mode_store = self.maintenance_mode_store
        state.lint_observations = self.lint_observations
        state.shared_state = self.shared_state
        # Also passed to KrbTokenProvider (remember/renew support, issue
        # #274); exposed on state so it exists in one place alongside every
        # other subsystem here.
        state.krb5_vault_store = self.link_stores.krb5
        state.servicex_vault_store = self.link_stores.servicex
        # Set unconditionally so a disabled deployment reads None rather than
        # whatever a previous app instance left behind.
        state.credmon_sync = self.credmon_sync
