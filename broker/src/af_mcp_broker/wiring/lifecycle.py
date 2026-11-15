"""Builders for the resources that run for the process lifetime.

Each one starts its resource and registers the matching close on the caller's
``AsyncExitStack``, so the lifespan tears everything down in reverse build
order -- including when a later builder raises partway through startup.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import structlog
from prometheus_client import start_http_server

from af_mcp_broker.credmon.factory import build_credmon_sync
from af_mcp_broker.identity import get_jwks
from af_mcp_broker.maintenance import build_maintenance_store
from af_mcp_broker.metering import build_metering_backend
from af_mcp_broker.shared_state import build_shared_state
from af_mcp_broker.usage import build_usage_store

if TYPE_CHECKING:
    from contextlib import AsyncExitStack

    from af_mcp_broker.config import Settings
    from af_mcp_broker.credentials import BrokerTokenIssuer, CredentialRegistry
    from af_mcp_broker.credentials.stores import VaultLinkStores
    from af_mcp_broker.credmon.sync import CredmonSyncService
    from af_mcp_broker.maintenance import MaintenanceModeStore
    from af_mcp_broker.metering import MeteringBackend
    from af_mcp_broker.principal_cache import PrincipalCache
    from af_mcp_broker.shared_state import SharedState
    from af_mcp_broker.usage import UsageStore
    from af_mcp_broker.vault_kv import VaultKV
    from af_mcp_broker.wiring.services import IdentityTargets

logger = structlog.get_logger(__name__)


def open_shared_state(settings: Settings, stack: AsyncExitStack) -> SharedState:
    """Build the cross-replica shared state (shared_state.py) and register its close on *stack*.

    The Settings validator has already refused more than one replica without
    a store unless the operator opted into per-replica state.
    """
    shared_state = build_shared_state(
        settings.shared_state_url, key_prefix=settings.shared_state_key_prefix
    )
    stack.push_async_callback(shared_state.close)
    return shared_state


async def start_maintenance_store(
    settings: Settings, vault_kv: VaultKV | None, stack: AsyncExitStack
) -> MaintenanceModeStore:
    """Build and start the process-wide maintenance-mode store (maintenance.py) and register its close on *stack*.

    The store has no ordering dependency on the audit/metering/usage chain:
    it is never read or written from the tool-call path those drain, only
    from the /v1 and /mcp request-gate checks (both already stopped serving
    new requests by the time shutdown reaches it) and the admin API.
    """
    store = build_maintenance_store(settings, vault_kv)
    await store.start()
    stack.push_async_callback(store.aclose)
    return store


async def start_usage_store(settings: Settings, stack: AsyncExitStack) -> UsageStore:
    """Start the per-user usage store (usage/) and register its close on *stack*.

    Started BEFORE the metering pipeline so no record the worker processes can
    miss the store, and closed only after the pipeline drains: drained records
    are still being accounted right up to the last audit write.
    """
    usage_store = build_usage_store(settings)
    await usage_store.start()
    stack.push_async_callback(usage_store.aclose)
    return usage_store


async def start_metering_pipeline(
    settings: Settings, usage_store: UsageStore, stack: AsyncExitStack
) -> MeteringBackend:
    """Start the metering backend (metering.py), feeding *usage_store*, and register its drain on *stack*.

    With the default ``in_process`` backend, success/error audit records are
    measured and written by a background worker so tool calls never wait on
    measurement or audit I/O. The drain keeps audit lines from being lost on a
    graceful stop, so it must run before the audit output is closed.
    """
    backend = build_metering_backend(settings, usage_store)
    await backend.start()
    stack.push_async_callback(backend.aclose)
    return backend


def start_metrics_server(settings: Settings, stack: AsyncExitStack) -> int | None:
    """Serve ``/metrics`` on its own port and register the server's shutdown on *stack*; return the bound port, or None when disabled.

    ``/metrics`` lives on its own port (chart NetworkPolicy allows Prometheus
    only there), served by prometheus_client's thread so the single uvicorn
    worker owns the process-wide registry.
    """
    if settings.metrics_port < 0:
        return None
    metrics_server, _ = start_http_server(settings.metrics_port)
    stack.callback(metrics_server.shutdown)
    stack.callback(metrics_server.server_close)
    logger.info("metrics_server_started", port=metrics_server.server_port)
    return int(metrics_server.server_port)


async def start_credmon_sync(
    settings: Settings,
    *,
    targets: IdentityTargets,
    credential_registry: CredentialRegistry,
    issuer: BrokerTokenIssuer | None,
    link_stores: VaultLinkStores,
    vault_kv: VaultKV | None,
    principal_cache: PrincipalCache | None,
    stack: AsyncExitStack,
) -> CredmonSyncService | None:
    """Build and start the HTCondor credmon storer (docs/credmon.md), or return None when it is disabled.

    Built for the kinds whose identity provider (and, for enumeration, Vault
    store) is actually wired.
    """
    if not settings.credmon_enabled:
        return None
    credmon_sync = await build_credmon_sync(
        settings,
        issuer=issuer,
        credential_registry=credential_registry,
        targets_by_kind=targets.targets_by_kind,
        store_prefixes={
            kind: prefix
            for kind, store, prefix in (
                ("x509", link_stores.x509, settings.x509_kv_path_prefix),
                ("krb5", link_stores.krb5, settings.krb5_kv_path_prefix),
                ("servicex", link_stores.servicex, settings.servicex_kv_path_prefix),
            )
            if store is not None
        },
        vault_kv=vault_kv,
        principal_cache=principal_cache,
    )
    credmon_sync.start()
    stack.push_async_callback(credmon_sync.stop)
    return credmon_sync


async def prime_jwks_cache(settings: Settings) -> None:
    """Prime the JWKS cache so the first request does not pay the latency cost of a remote fetch."""
    try:
        keys = await get_jwks(settings)
        logger.info("jwks_cache_primed", key_count=len(keys))
    except Exception as exc:  # noqa: BLE001  # non-fatal prime; broad catch intentional
        # Non-fatal at startup — the cache will be retried on the first request.
        logger.warning("jwks_cache_prime_failed", error=str(exc))
