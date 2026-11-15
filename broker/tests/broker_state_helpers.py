"""Build and adjust the ``BrokerState`` that tests store on ``app.state.broker``."""

from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING, Any

from fastmcp import FastMCP

from af_mcp_broker.authorization import EntitlementPolicy
from af_mcp_broker.backend_client import ToolListingCache
from af_mcp_broker.broker_state import BrokerState
from af_mcp_broker.config import Settings
from af_mcp_broker.credentials import CredentialCache, CredentialRegistry
from af_mcp_broker.lint_observations import LintObservationStore
from af_mcp_broker.maintenance import InMemoryMaintenanceModeStore
from af_mcp_broker.mcp.middleware.identity_mw import IdentityMiddleware
from af_mcp_broker.service_registry import ServiceRegistry
from af_mcp_broker.shared_state import InMemorySharedState
from af_mcp_broker.token_registry import InMemoryTokenRegistryBackend, TokenRegistry
from af_mcp_broker.usage.store import InMemoryUsageStore

if TYPE_CHECKING:
    from collections.abc import Callable

    from starlette.applications import Starlette

    from af_mcp_broker.maintenance import MaintenanceModeStore


def make_broker_state(**overrides: Any) -> BrokerState:
    """A ``BrokerState`` of empty in-memory subsystems, with *overrides* replacing named fields."""
    shared_state = InMemorySharedState()
    fields: dict[str, Any] = {
        "settings": Settings(),
        "entitlement_policy": EntitlementPolicy(),
        "service_registry": ServiceRegistry(),
        "services": [],
        "services_loaded": False,
        "credential_cache": CredentialCache(),
        "credential_registry": CredentialRegistry(),
        "x509_provider": None,
        "x509_targets": [],
        "krb5_targets": [],
        "servicex_targets": [],
        "x509_audiences": {},
        "krb5_audiences": {},
        "servicex_audiences": {},
        "target_to_alias": {},
        "identity_providers": {},
        "identity_provider_configs": {},
        "oauth21_token_store": None,
        "oauth21_state_cipher": None,
        "token_registry": TokenRegistry(InMemoryTokenRegistryBackend(), shared_state),
        "principal_cache": None,
        "mcp_auth_code_store": None,
        "broker_token_issuer": None,
        "usage_store": InMemoryUsageStore(),
        "maintenance_mode_store": InMemoryMaintenanceModeStore(),
        "lint_observations": LintObservationStore(shared_state),
        "shared_state": shared_state,
        "krb5_vault_store": None,
        "servicex_vault_store": None,
        "credmon_sync": None,
        "tool_listing_cache": ToolListingCache(),
        "mcp_aggregator": FastMCP("test"),
        "dev_bypass_principal": None,
        "metrics_port": None,
    }
    fields.update(overrides)
    return BrokerState(**fields)


def set_broker_state(app: Starlette, **changes: Any) -> None:
    """Replace the named fields of the ``BrokerState`` stored on *app*."""
    app.state.broker = replace(app.state.broker, **changes)


def asgi_state_getter(
    mcp: FastMCP, maintenance_mode_store: MaintenanceModeStore | None = None
) -> Callable[[], BrokerState]:
    """The ``get_state`` the /mcp ASGI middleware reads, for an aggregator mounted without the broker app.

    Settings follow *mcp*'s identity middleware, which ``populate_aggregator``
    keeps current; the maintenance store defaults to an empty (disabled) one.
    """
    identity_mw = next(m for m in mcp.middleware if isinstance(m, IdentityMiddleware))
    base = make_broker_state(
        maintenance_mode_store=maintenance_mode_store or InMemoryMaintenanceModeStore()
    )
    return lambda: replace(base, settings=identity_mw.settings)
