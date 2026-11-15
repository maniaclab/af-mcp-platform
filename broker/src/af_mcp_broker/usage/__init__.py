"""Per-user usage accounting (observability roadmap PR C).

See ``usage/store.py`` for the store contract and the design constraints
(best-effort, audit records authoritative, no dollars stored). This module
builds the store selected by ``settings.usage_store_backend`` (the lifespan
owns it and hands it to its consumers) and provides the never-raising
``record_usage``/``record_usage_batch`` helpers the metering backends call,
with the store they feed, after each audit write.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, assert_never

import structlog

from af_mcp_broker import metrics
from af_mcp_broker.errors import require
from af_mcp_broker.usage.batcher import UsageBatcher
from af_mcp_broker.usage.otel_events import (
    EventEmittingUsageStore,
    OtelUsageEventEmitter,
)
from af_mcp_broker.usage.postgres import PostgresUsageStore
from af_mcp_broker.usage.store import InMemoryUsageStore, UsageAggregate, UsageStore

if TYPE_CHECKING:
    from af_mcp_broker.audit.logger import AuditRecord
    from af_mcp_broker.config import Settings

__all__ = [
    "EventEmittingUsageStore",
    "InMemoryUsageStore",
    "OtelUsageEventEmitter",
    "PostgresUsageStore",
    "UsageAggregate",
    "UsageBatcher",
    "UsageStore",
    "build_usage_store",
    "counts_as_usage",
    "record_usage",
    "record_usage_batch",
]

logger = structlog.get_logger(__name__)


def build_usage_store(settings: Settings) -> UsageStore:
    """Build the (not yet started) store selected by ``settings.usage_store_backend``.

    With ``settings.usage_events_otlp_enabled`` the store is wrapped so each
    recorded usage is also emitted as an OTel log record (``otel_events.py``).
    The ``match`` is exhaustive over the config Literal: ``assert_never`` makes
    mypy fail when a backend name is added without a branch here.
    """
    store: UsageStore
    backend = settings.usage_store_backend
    match backend:
        case "in_memory":
            store = InMemoryUsageStore()
        case "postgres":
            dsn = require(
                settings.usage_postgres_dsn,
                "usage_store_backend=postgres requires usage_postgres_dsn "
                "(_validate_usage_store_config)",
            )
            store = PostgresUsageStore(
                dsn.get_secret_value(),
                retention_days=settings.usage_retention_days,
                rollup_interval_seconds=settings.usage_rollup_interval_seconds,
            )
        case _:
            assert_never(backend)
    if settings.usage_events_otlp_enabled:
        store = EventEmittingUsageStore(store, OtelUsageEventEmitter())
    return store


async def record_usage(store: UsageStore, record: AuditRecord) -> None:
    """Account *record* in *store*, if it counts as usage.

    Only tool-call records (``mcp_service`` set) with outcome success or
    error are usage -- denied/unmapped calls are security events that live
    in the audit log, not in anyone's usage. Never raises: usage is
    best-effort by contract, so a store failure is logged and counted on the
    existing metering-worker error counter without ever affecting the audit
    write (which the caller performs FIRST) or the tool call itself.
    """
    if not counts_as_usage(record):
        return
    try:
        await store.record(record)
    except Exception as exc:  # noqa: BLE001 -- usage must never lose an audit line
        metrics.metering_worker_errors_total.inc()
        logger.warning("usage_record_failed", audit_id=record.audit_id, error=str(exc))


def counts_as_usage(record: AuditRecord) -> bool:
    """Whether *record* is a tool-call record that counts as usage."""
    return record.mcp_service is not None and record.outcome in ("success", "error")


async def record_usage_batch(store: UsageStore, records: list[AuditRecord]) -> None:
    """Account *records* (already filtered by ``counts_as_usage``) in one *store* call.

    Never raises, like ``record_usage``. A batch failure may be all-or-nothing
    (the Postgres store's is), so every row is counted on the metering-worker
    error counter -- the same per-record unit a failed single insert uses --
    and the audit_ids are logged so the rows can be rebuilt from the
    authoritative audit log.
    """
    try:
        await store.record_many(records)
    except Exception as exc:  # noqa: BLE001 -- usage must never lose an audit line
        metrics.metering_worker_errors_total.inc(len(records))
        logger.warning(
            "usage_record_batch_failed",
            batch_size=len(records),
            audit_ids=[r.audit_id for r in records],
            error=str(exc),
        )
