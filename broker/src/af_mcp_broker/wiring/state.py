"""Assembly of the built subsystems into the ``BrokerState`` the request path reads."""

from __future__ import annotations

from typing import TYPE_CHECKING

from af_mcp_broker.backend_client import ToolListingCache
from af_mcp_broker.broker_state import BrokerState

if TYPE_CHECKING:
    from cryptography.fernet import Fernet
    from fastmcp import FastMCP
    from starlette.types import ASGIApp

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
    from af_mcp_broker.principal import Principal
    from af_mcp_broker.principal_cache import PrincipalCache
    from af_mcp_broker.shared_state import SharedState
    from af_mcp_broker.token_registry import TokenRegistry
    from af_mcp_broker.usage import UsageStore
    from af_mcp_broker.wiring.credentials import CredentialProviders
    from af_mcp_broker.wiring.services import IdentityTargets, ServiceCatalog


def build_broker_state(
    settings: Settings,
    *,
    catalog: ServiceCatalog,
    targets: IdentityTargets,
    providers: CredentialProviders,
    credential_cache: CredentialCache,
    x509_provider: X509Provider | None,
    oauth21_token_store: InMemoryTokenStore | VaultTokenStore | None,
    oauth21_state_cipher: Fernet | None,
    token_registry: TokenRegistry,
    principal_cache: PrincipalCache | None,
    mcp_auth_code_store: McpAuthCodeStore | None,
    broker_token_issuer: BrokerTokenIssuer | None,
    usage_store: UsageStore,
    maintenance_mode_store: MaintenanceModeStore,
    lint_observations: LintObservationStore,
    shared_state: SharedState,
    link_stores: VaultLinkStores,
    credmon_sync: CredmonSyncService | None,
    mcp_aggregator: FastMCP,
    mcp_app: ASGIApp,
    dev_bypass_principal: Principal | None,
    metrics_port: int | None,
) -> BrokerState:
    """Flatten the lifespan's built subsystems (and the groups they come in) into one ``BrokerState``, with a cold tool-listing cache."""
    return BrokerState(
        settings=settings,
        entitlement_policy=catalog.entitlement_policy,
        service_registry=catalog.service_registry,
        services=catalog.services,
        services_loaded=catalog.services_loaded,
        credential_cache=credential_cache,
        credential_registry=providers.registry,
        x509_provider=x509_provider,
        x509_targets=targets.x509_targets,
        krb5_targets=targets.krb5_targets,
        servicex_targets=targets.servicex_targets,
        x509_audiences=targets.x509_audiences,
        krb5_audiences=targets.krb5_audiences,
        servicex_audiences=targets.servicex_audiences,
        target_to_alias=targets.target_to_alias,
        identity_providers=providers.providers,
        identity_provider_configs=providers.configs,
        oauth21_token_store=oauth21_token_store,
        oauth21_state_cipher=oauth21_state_cipher,
        token_registry=token_registry,
        principal_cache=principal_cache,
        mcp_auth_code_store=mcp_auth_code_store,
        broker_token_issuer=broker_token_issuer,
        usage_store=usage_store,
        maintenance_mode_store=maintenance_mode_store,
        lint_observations=lint_observations,
        shared_state=shared_state,
        krb5_vault_store=link_stores.krb5,
        servicex_vault_store=link_stores.servicex,
        credmon_sync=credmon_sync,
        tool_listing_cache=ToolListingCache(),
        mcp_aggregator=mcp_aggregator,
        mcp_app=mcp_app,
        dev_bypass_principal=dev_bypass_principal,
        metrics_port=metrics_port,
    )
