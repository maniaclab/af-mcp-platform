"""Opt-in per-call usage as OpenTelemetry log records (OTLP emission only).

One log record per tool-call usage record, emitted beside the usage store
that stays authoritative (Postgres backs ``/v1/usage``, ``af_usage`` and the
portal; the audit log is authoritative overall). A log record can carry
``principal_sub``, ``token_id``, ``audit_id`` and ``trace_id`` without any
cardinality cost, which metrics cannot (see ``metrics.py``'s policy) and
which sampled spans cannot guarantee. They join the audit log and traces by
``audit_id`` / ``trace_id``.

The fan-out point is the usage store seam: :class:`EventEmittingUsageStore`
wraps the configured store, so every path that records usage (the metering
worker's batches, the queue-overflow and no-pipeline inline paths) emits with
no second call site and no duplicated filtering.

The failure contract mirrors the rest of metering: emission is best-effort
and must never affect a tool call or the wrapped store's write. The emitter
only enqueues onto the SDK's ``BatchLogRecordProcessor``, which exports on its
own thread and drops on overflow; ``emit`` never raises. Delivery is
at-least-once toward the collector (a record redelivered to the store is
emitted again), so receivers dedupe on ``audit_id``.

Attributes are exactly :data:`EVENT_ATTRIBUTES`; tool arguments and results
are never included. The receiving log backend therefore holds per-user data
and needs its own access control -- out of scope here, as for traces.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import structlog
from opentelemetry._logs import SeverityNumber
from opentelemetry.exporter.otlp.proto.http._log_exporter import OTLPLogExporter
from opentelemetry.sdk._logs import LoggerProvider
from opentelemetry.sdk._logs.export import BatchLogRecordProcessor

from af_mcp_broker._version import version as __version__
from af_mcp_broker.otel_resource import broker_resource
from af_mcp_broker.usage.store import UsageAggregate, UsageStore

if TYPE_CHECKING:
    from opentelemetry.sdk._logs.export import LogRecordExporter

    from af_mcp_broker.audit.logger import AuditRecord

logger = structlog.get_logger(__name__)

EVENT_NAME = "af_mcp.usage"

# The only attributes an event may carry. Optional ones are omitted when
# unset (no token for a session JWT, no trace when untraced, nothing measured
# for an unmeasured call).
EVENT_ATTRIBUTES = (
    "audit_id",
    "trace_id",
    "principal_sub",
    "token_id",
    "service",
    "method",
    "outcome",
    "duration_ms",
    "result_bytes",
    "result_tokens_est",
)


class OtelUsageEventEmitter:
    """Emits one OTel log record per usage ``AuditRecord`` through a batch processor.

    *exporter* replaces the OTLP/HTTP exporter; it is the test seam at the
    exporter boundary, never set in production. ``OTLPLogExporter()`` is built
    argument-free so endpoint, headers, timeout and TLS come from the standard
    ``OTEL_EXPORTER_OTLP_*`` variables (appending ``/v1/logs``), shared with
    tracing and metrics.
    """

    def __init__(self, exporter: LogRecordExporter | None = None) -> None:
        self._provider = LoggerProvider(resource=broker_resource())
        self._provider.add_log_record_processor(
            BatchLogRecordProcessor(exporter or OTLPLogExporter())
        )
        self._logger = self._provider.get_logger("af_mcp_broker.usage", __version__)
        self._closed = False

    def emit(self, record: AuditRecord) -> None:
        """Enqueue *record* as a log record. Never raises."""
        if record.mcp_service is None or self._closed:
            return
        optional = {
            "trace_id": record.trace_id,
            "token_id": record.token_id,
            "duration_ms": record.duration_ms,
            "result_bytes": record.result_bytes,
            "result_tokens_est": record.result_tokens_est,
        }
        attributes = {
            "audit_id": record.audit_id,
            "principal_sub": record.principal_sub,
            "service": record.mcp_service,
            "method": record.action,
            "outcome": record.outcome,
            **{k: v for k, v in optional.items() if v is not None},
        }
        try:
            self._logger.emit(
                timestamp=round(record.timestamp * 1e9),
                severity_number=SeverityNumber.INFO,
                event_name=EVENT_NAME,
                attributes=attributes,
            )
        except Exception as exc:  # noqa: BLE001 -- emission must never affect a call
            logger.warning(
                "usage_event_emit_failed", audit_id=record.audit_id, error=str(exc)
            )

    def shutdown(self) -> None:
        """Flush and stop the processor. Idempotent; never raises."""
        if self._closed:
            return
        self._closed = True
        try:
            self._provider.shutdown()
        except Exception as exc:  # noqa: BLE001 -- an exporter problem is not the broker's
            logger.warning("usage_event_shutdown_failed", error=str(exc))


class EventEmittingUsageStore(UsageStore):
    """A ``UsageStore`` that emits each recorded usage as an OTel log record.

    Delegates everything to *store*, which stays authoritative: its failures
    propagate unchanged to ``record_usage`` / ``record_usage_batch`` (which
    count and log them), and the events go out regardless -- the two sinks are
    independent. Emission cannot raise (see ``OtelUsageEventEmitter.emit``).
    """

    def __init__(self, store: UsageStore, emitter: OtelUsageEventEmitter) -> None:
        self._store = store
        self._emitter = emitter

    async def start(self) -> None:
        await self._store.start()

    async def aclose(self) -> None:
        try:
            await self._store.aclose()
        finally:
            self._emitter.shutdown()

    async def record(self, record: AuditRecord) -> None:
        try:
            await self._store.record(record)
        finally:
            self._emitter.emit(record)

    async def record_many(self, records: list[AuditRecord]) -> None:
        try:
            await self._store.record_many(records)
        finally:
            for record in records:
                self._emitter.emit(record)

    async def query(self, subject: str, days: int) -> list[UsageAggregate]:
        return await self._store.query(subject, days)

    async def list_subjects(self, days: int) -> list[str]:
        return await self._store.list_subjects(days)
