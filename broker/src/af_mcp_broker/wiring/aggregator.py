"""Builders for the MCP aggregator and the ASGI app that serves it at ``/mcp``."""

from __future__ import annotations

from typing import TYPE_CHECKING

from af_mcp_broker.credmon.guidance import JobCredentialGuide, wired_kinds
from af_mcp_broker.mcp.aggregator import build_aggregator, build_asgi_middleware

if TYPE_CHECKING:
    from fastmcp.server.http import StarletteWithLifespan

    from af_mcp_broker.config import Settings
    from af_mcp_broker.credentials import BrokerTokenIssuer
    from af_mcp_broker.lint_observations import LintObservationStore
    from af_mcp_broker.maintenance import MaintenanceModeStore
    from af_mcp_broker.mcp.aggregator import Aggregator, BackendProviders
    from af_mcp_broker.principal_cache import PrincipalCache
    from af_mcp_broker.shared_state import SharedState
    from af_mcp_broker.token_registry import TokenRegistryBackend
    from af_mcp_broker.usage import UsageStore
    from af_mcp_broker.wiring.credentials import CredentialProviders
    from af_mcp_broker.wiring.services import IdentityTargets, ServiceCatalog


def build_job_credential_guide(
    settings: Settings, targets: IdentityTargets
) -> JobCredentialGuide | None:
    """Build the agent guidance on HTCondor job credentials (docs/credmon.md), or None unless credmon is enabled.

    The guide covers the identity targets each credmon kind redeems from,
    shared with the storer; it exists only when credmon is enabled, so sites
    without HTCondor never tell agents about job credentials.
    """
    if not settings.credmon_enabled:
        return None
    return JobCredentialGuide(
        service_prefix=settings.credmon_service_prefix,
        kinds=frozenset(wired_kinds(settings, targets.targets_by_kind)),
    )


def build_mcp_aggregator(
    settings: Settings,
    *,
    catalog: ServiceCatalog,
    targets: IdentityTargets,
    providers: CredentialProviders,
    backend_providers: BackendProviders,
    broker_token_issuer: BrokerTokenIssuer | None,
    job_credentials: JobCredentialGuide | None,
    shared_state: SharedState,
    usage_store: UsageStore,
    lint_observations: LintObservationStore,
) -> Aggregator:
    """Build the aggregator from the loaded registry, policy, credential registry, providers and stores.

    The registry/policy/settings/credential registry/identity providers feed
    the af_* diagnostic tools (issue #153). *backend_providers* is the holder
    the cache invalidator was built over, which the aggregator records its
    proxied backends into.
    """
    return build_aggregator(
        catalog.service_registry,
        settings,
        catalog.entitlement_policy,
        providers.registry,
        shared_state=shared_state,
        usage_store=usage_store,
        lint_observations=lint_observations,
        identity_providers=providers.providers,
        identity_provider_configs=providers.configs,
        target_to_alias=targets.target_to_alias,
        broker_token_issuer=broker_token_issuer,
        job_credentials=job_credentials,
        backend_providers=backend_providers,
    )


def build_mcp_app(
    aggregator: Aggregator,
    settings: Settings,
    *,
    pat_backend: TokenRegistryBackend,
    principal_cache: PrincipalCache | None,
    maintenance_mode_store: MaintenanceModeStore,
) -> StarletteWithLifespan:
    """Build the ASGI app serving *aggregator* at ``/mcp``, gated by the identity and maintenance middleware.

    The middleware enforces identity (then maintenance mode) at the ASGI
    layer, in front of FastMCP's own message-processing pipeline, so a
    missing/invalid/expired bearer token produces a genuine HTTP 401 instead
    of a 200 carrying a JSON-RPC error (issue #138/#144 step 1) -- see
    mcp/middleware/identity_mw.py's module docstring for the full mechanism
    and why IdentityMiddleware (registered inside the aggregator) survives
    alongside it as a thin hand-off.
    """
    return aggregator.http_app(
        path="/",
        stateless_http=settings.mcp_stateless_http,
        middleware=build_asgi_middleware(
            settings, pat_backend, principal_cache, maintenance_mode_store
        ),
    )
