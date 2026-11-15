"""The built subsystems the request path reads, as one typed object stored on ``app.state.broker``.

The lifespan (``app.py``) builds every subsystem, assembles them into a
``BrokerState`` and stores it once; ``/v1`` routes and the ``/mcp`` ASGI
middleware read it back through ``get_broker_state``/``broker_state_of``.
A component that a deployment may legitimately lack is an explicit
``X | None`` field and each consumer decides what absence means; every other
field is required, so a missing one is a construction error, never a silent
default at request time.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from fastapi import (
    Request,  # noqa: TC002 -- FastAPI resolves the dependency's annotations at runtime
)

if TYPE_CHECKING:
    from cryptography.fernet import Fernet
    from fastmcp import FastMCP
    from starlette.applications import Starlette

    from af_mcp_broker.authorization import EntitlementPolicy
    from af_mcp_broker.backend_client import ToolListingCache
    from af_mcp_broker.config import IdentityProviderConfig, Settings
    from af_mcp_broker.credentials import (
        BrokerTokenIssuer,
        CredentialCache,
        CredentialProvider,
        CredentialRegistry,
        InMemoryTokenStore,
        VaultServiceXStore,
        VaultTokenStore,
        X509Provider,
    )
    from af_mcp_broker.credentials.krb5_vault import Krb5VaultStore
    from af_mcp_broker.credmon.sync import CredmonSyncService
    from af_mcp_broker.lint_observations import LintObservationStore
    from af_mcp_broker.maintenance import MaintenanceModeStore
    from af_mcp_broker.mcp_auth_codes import McpAuthCodeStore
    from af_mcp_broker.principal import Principal
    from af_mcp_broker.principal_cache import PrincipalCache
    from af_mcp_broker.service_registry import ServiceRegistry, ServiceSpec
    from af_mcp_broker.shared_state import SharedState
    from af_mcp_broker.token_registry import TokenRegistry
    from af_mcp_broker.usage import UsageStore


@dataclass(frozen=True)
class BrokerState:
    """Every subsystem the request path reads, as built by the lifespan.

    *services* is the operator-configured services only (the registry also
    carries the builtin gateway service); *services_loaded* means
    ``services.yaml`` parsed without error. *dev_bypass_principal* is set only
    while the local-dev auth bypass is active. *metrics_port* is the port the
    metrics server bound, or None when it is disabled.
    """

    settings: Settings
    entitlement_policy: EntitlementPolicy
    service_registry: ServiceRegistry
    services: list[ServiceSpec]
    services_loaded: bool
    credential_cache: CredentialCache
    credential_registry: CredentialRegistry
    x509_provider: X509Provider | None
    x509_targets: list[str]
    krb5_targets: list[str]
    servicex_targets: list[str]
    x509_audiences: dict[str, str]
    krb5_audiences: dict[str, str]
    servicex_audiences: dict[str, str]
    target_to_alias: dict[str, str]
    identity_providers: dict[str, CredentialProvider]
    identity_provider_configs: dict[str, IdentityProviderConfig]
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
    krb5_vault_store: Krb5VaultStore | None
    servicex_vault_store: VaultServiceXStore | None
    credmon_sync: CredmonSyncService | None
    tool_listing_cache: ToolListingCache
    mcp_aggregator: FastMCP
    dev_bypass_principal: Principal | None
    metrics_port: int | None


def broker_state_of(app: Starlette) -> BrokerState:
    """Return the ``BrokerState`` the lifespan stored on *app*.

    Raises ``RuntimeError`` when none is stored: a request reaching a broker
    whose lifespan has not completed is a wiring fault, and answering it with
    defaults would hide that.
    """
    try:
        state: BrokerState = app.state.broker
    except AttributeError:
        msg = (
            "BrokerState is not published on app.state: the lifespan has not completed"
        )
        raise RuntimeError(msg) from None
    return state


def get_broker_state(request: Request) -> BrokerState:
    """FastAPI dependency (and plain accessor) for the app's ``BrokerState``."""
    return broker_state_of(request.app)
