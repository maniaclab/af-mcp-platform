"""Per-user usage accounting (observability roadmap PR C).

See ``usage/store.py`` for the store contract and the design constraints
(best-effort, audit records authoritative, no dollars stored). This module
owns the process-wide wiring, mirroring ``audit/pipeline.py``'s shape: a
module-level store selected by ``settings.usage_store_backend``,
initialized/closed from ``app.py``'s lifespan, and a never-raising
``record_usage`` helper the metering pipeline calls after each audit write.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import structlog

from af_mcp_broker import metrics
from af_mcp_broker.config import Settings, get_settings
from af_mcp_broker.usage.postgres import PostgresUsageStore
from af_mcp_broker.usage.store import InMemoryUsageStore, UsageAggregate, UsageStore

if TYPE_CHECKING:
    from collections.abc import Callable

    from af_mcp_broker.audit.logger import AuditRecord

__all__ = [
    "InMemoryUsageStore",
    "PostgresUsageStore",
    "UsageAggregate",
    "UsageStore",
    "aclose_usage_store",
    "get_usage_store",
    "init_usage_store",
    "record_usage",
]

logger = structlog.get_logger(__name__)

_store: UsageStore | None = None


def _build_postgres_store(settings: Settings) -> UsageStore:
    # _validate_usage_store_config guarantees the DSN is set whenever this
    # backend is selected, so the assert is a type-narrowing formality.
    assert settings.usage_postgres_dsn is not None  # noqa: S101
    return PostgresUsageStore(settings.usage_postgres_dsn.get_secret_value())


# Maps ``settings.usage_store_backend`` values to store factories. Same
# fail-closed shape as the pipeline's _BACKEND_FACTORIES: config.py's Literal
# already rejects values with no entry here, so a KeyError below means the
# Literal and this table drifted apart.
_STORE_FACTORIES: dict[str, Callable[[Settings], UsageStore]] = {
    "in_memory": lambda settings: InMemoryUsageStore(),
    "postgres": _build_postgres_store,
}


async def init_usage_store(settings: Settings | None = None) -> UsageStore:
    """Create, start, and install the process-wide store (app.py lifespan).

    The implementation is selected by ``settings.usage_store_backend``; with
    no Settings passed (tests), the process-wide ``get_settings()`` is used.
    """
    global _store
    if settings is None:
        settings = get_settings()
    _store = _STORE_FACTORIES[settings.usage_store_backend](settings)
    await _store.start()
    return _store


async def aclose_usage_store() -> None:
    """Close and uninstall the process-wide store (app.py lifespan shutdown)."""
    global _store
    if _store is None:
        return
    await _store.aclose()
    _store = None


def get_usage_store() -> UsageStore | None:
    """The installed process-wide store, or None outside the lifespan."""
    return _store


async def record_usage(record: AuditRecord) -> None:
    """Account *record* in the installed store, if it counts as usage.

    Only tool-call records (``mcp_service`` set) with outcome success or
    error are usage -- denied/unmapped calls are security events that live
    in the audit log, not in anyone's usage. Never raises: usage is
    best-effort by contract, so a store failure is logged and counted on the
    existing metering-worker error counter without ever affecting the audit
    write (which the caller performs FIRST) or the tool call itself.
    """
    if _store is None:
        return
    if record.mcp_service is None or record.outcome not in ("success", "error"):
        return
    try:
        await _store.record(record)
    except Exception as exc:  # noqa: BLE001 -- usage must never lose an audit line
        metrics.metering_worker_errors_total.inc()
        logger.warning(
            "usage_record_failed", audit_id=record.audit_id, error=str(exc)
        )
