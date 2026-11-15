"""Builders that push the loaded subsystems into the already-mounted MCP aggregator."""

from __future__ import annotations

from typing import TYPE_CHECKING

from af_mcp_broker.credmon.guidance import JobCredentialGuide, wired_kinds
from af_mcp_broker.mcp.aggregator import populate_aggregator

if TYPE_CHECKING:
    from af_mcp_broker.config import Settings
    from af_mcp_broker.credentials import BrokerTokenIssuer
    from af_mcp_broker.lint_observations import LintObservationStore
    from af_mcp_broker.maintenance import MaintenanceModeStore
    from af_mcp_broker.mcp.aggregator import Aggregator
    from af_mcp_broker.principal_cache import PrincipalCache
    from af_mcp_broker.shared_state import SharedState
    from af_mcp_broker.token_registry import TokenRegistryBackend
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


def populate_mcp_aggregator(
    aggregator: Aggregator,
    settings: Settings,
    *,
    catalog: ServiceCatalog,
    targets: IdentityTargets,
    providers: CredentialProviders,
    pat_backend: TokenRegistryBackend,
    principal_cache: PrincipalCache | None,
    broker_token_issuer: BrokerTokenIssuer | None,
    maintenance_mode_store: MaintenanceModeStore,
    job_credentials: JobCredentialGuide | None,
    shared_state: SharedState,
    lint_observations: LintObservationStore,
) -> None:
    """Push the loaded registry, policy, credential registry, providers and stores into *aggregator*.

    The FastMCP instance and its ASGI app are built eagerly at import time
    (see app.py), before any of these exist; the lifespan calls this once they
    are real. The registry/policy/settings/credential registry/identity
    providers feed the af_* diagnostic tools (issue #153), and
    *maintenance_mode_store* feeds AsgiAuthMiddleware's /mcp enforcement
    (mirroring /v1's require_not_in_maintenance, which reads it straight off
    app.state).
    """
    populate_aggregator(
        aggregator,
        catalog.service_registry,
        settings,
        catalog.entitlement_policy,
        providers.registry,
        pat_backend=pat_backend,
        principal_cache=principal_cache,
        identity_providers=providers.providers,
        identity_provider_configs=providers.configs,
        target_to_alias=targets.target_to_alias,
        broker_token_issuer=broker_token_issuer,
        maintenance_mode_store=maintenance_mode_store,
        job_credentials=job_credentials,
        shared_state=shared_state,
        lint_observations=lint_observations,
    )
