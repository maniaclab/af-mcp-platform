"""Asynchronous tool-call metering pipeline (observability roadmap PR B).

A tool call must never wait on measurement or audit I/O: serializing and
tokenizing a large result (``audit/measure.py``) can cost tens of
milliseconds, and even the to_thread'd audit write is an inline await. The
authorization middleware therefore hands its success and error audit
records to its ``MeteringBackend`` -- ``backend.submit(record, result)`` -- and
returns; a background worker measures the result (success path) and writes
the line. DENIED and UNMAPPED records deliberately do NOT come through
here: they are security-relevant, have nothing to measure, and cost
nothing, so the middleware still writes them synchronously inline.

Nothing is ever dropped. A full queue degrades to writing the record
inline without measurement -- an overloaded broker paying that cost is
acceptable, a lost audit line is not -- counted by
``metrics.metering_queue_overflow_total``. The ``inline`` backend (unit
tests, local dev) measures and writes synchronously in the caller's call.

Metering is best-effort; audit records are authoritative.

After every audit write (worker, overflow, and fallback paths alike) the
record is also handed to the usage store (``usage/`` -- PR C). The overflow
and fallback paths write it at once via ``record_usage``; the worker buffers
it in a ``UsageBatcher`` and writes batches (``record_usage_batch``) at
``USAGE_BATCH_MAX`` records, after ``USAGE_BATCH_INTERVAL_MS``, or on drain,
so the store sees one round trip per batch instead of one per tool call.
Both helpers filter non-usage records and never raise.

The transport between the hot path and the worker is a config-selected
``MeteringBackend`` (``METERING_BACKEND`` -> ``settings.metering_backend``);
``in_process`` and ``inline`` exist today -- see the ABC's docstring. A
backend owns the usage store it feeds and the middleware owns the backend:
nothing is installed process-wide.
"""

from __future__ import annotations

import abc
import asyncio
import functools
import time
from typing import TYPE_CHECKING, Any, assert_never

import structlog

from af_mcp_broker import metrics, otel_metrics
from af_mcp_broker.audit.logger import AuditRecord, write_audit
from af_mcp_broker.audit.measure import measure_tool_result
from af_mcp_broker.usage import (
    UsageBatcher,
    counts_as_usage,
    record_usage,
    record_usage_batch,
)

if TYPE_CHECKING:
    from fastmcp.tools.base import ToolResult

    from af_mcp_broker.config import Settings
    from af_mcp_broker.usage import UsageStore

logger = structlog.get_logger(__name__)

# Queue bound. Beyond backpressure, this also bounds memory: queued items
# hold references to result payloads until the worker measures them, so an
# unbounded queue under a slow output could pin arbitrarily many results.
QUEUE_MAXSIZE = 10_000

# Enqueued by aclose(): the worker processes every record queued before it,
# then exits -- a deterministic drain with no cancellation racing a
# half-processed item.
_SENTINEL: Any = object()


async def _write_and_account(record: AuditRecord, usage_store: UsageStore) -> None:
    """Write *record* in the caller's own call, then account it as usage and in the OTel aggregates.

    The audit write raises on failure (the caller is there to hear it).
    ``record_usage`` never raises and must only ever run AFTER the audit
    write; the OTel aggregates follow the same rule.
    """
    await write_audit(record)
    await record_usage(usage_store, record)
    otel_metrics.record_tool_call(record)


def _measure_into(
    record: AuditRecord, result: ToolResult | None, settings: Settings
) -> None:
    """Fill the record's result totals and per-content-type breakdown from *result*.

    ``measure_tool_result`` already degrades to None internally (leaving the
    record unmeasured);
    the catch here is belt-and-braces for failures it did not anticipate --
    the audit line must still be written (unmeasured) if measurement blows
    up, so nothing may propagate out of this helper.
    """
    if result is None:
        return
    try:
        measurement = measure_tool_result(result, settings)
        if measurement is None:
            return
        record.result_bytes = measurement.result_bytes
        record.result_tokens_est = measurement.result_tokens_est
        record.result_content = measurement.content
    except Exception as exc:  # noqa: BLE001 -- metering must never lose an audit line
        metrics.metering_worker_errors_total.inc()
        metrics.metering_records_missing_measurements_total.inc()
        logger.warning(
            "metering_measurement_failed", audit_id=record.audit_id, error=str(exc)
        )


class MeteringBackend(abc.ABC):
    """How ``(record, result)`` pairs travel from the hot path to the worker.

    This ABC is the deliberate extension point for distributed transports --
    e.g. a future taskiq-backed backend whose worker runs in its own
    Deployment, selected by ``settings.metering_backend``. Design caveat for
    any out-of-process backend: it must serialize the result payload at
    submit time, because the worker no longer shares the broker's memory --
    the in-process backend passes an object reference across its queue,
    which is exactly why it is the default and only backend today.
    """

    @property
    @abc.abstractmethod
    def is_running(self) -> bool:
        """Whether the backend is currently able to accept submissions."""

    @abc.abstractmethod
    async def start(self) -> None:
        """Begin processing submitted records."""

    @abc.abstractmethod
    async def aclose(self) -> None:
        """Drain every already-submitted record, then stop."""

    @abc.abstractmethod
    async def submit(self, record: AuditRecord, result: ToolResult | None) -> None:
        """Hand a record (and its measurable result, if any) to the worker."""


class InProcessMeteringBackend(MeteringBackend):
    """Bounded queue + background worker measuring and writing audit records."""

    def __init__(
        self,
        settings: Settings,
        usage_store: UsageStore,
        maxsize: int = QUEUE_MAXSIZE,
    ) -> None:
        # Items are (record, result, enqueued_at, log_context) tuples --
        # enqueued_at is a time.monotonic() timestamp feeding the queue-delay
        # gauge, log_context the submitting request's structlog contextvars
        # (correlation_id, subject), which the worker task does not inherit
        # -- or the drain sentinel.
        self._settings = settings
        self.usage_store = usage_store
        self._queue: asyncio.Queue[Any] = asyncio.Queue(maxsize=maxsize)
        self._worker: asyncio.Task[None] | None = None
        self._closed = False
        self._usage_batcher = UsageBatcher(
            functools.partial(record_usage_batch, usage_store),
            max_size=settings.usage_batch_max,
            interval_seconds=settings.usage_batch_interval_ms / 1000,
        )

    @property
    def is_running(self) -> bool:
        return self._worker is not None and not self._worker.done()

    async def start(self) -> None:
        self._worker = asyncio.create_task(self._run(), name="metering-pipeline")

    async def aclose(self) -> None:
        """Drain every already-enqueued record, then stop the worker."""
        if self._worker is None:
            return
        self._closed = True
        await self._queue.put(_SENTINEL)
        await self._worker
        self._worker = None

    async def submit(self, record: AuditRecord, result: ToolResult | None) -> None:
        """Enqueue without ever blocking the caller.

        On a full queue: do NOT drop -- write the record immediately,
        without measurement (this fallback path may await; an overloaded
        broker paying that cost is acceptable, a lost audit line is not),
        and count the overflow. After ``aclose`` nothing would ever drain the
        queue, so a submission raises rather than lose the record.
        """
        if self._closed:
            msg = "the metering backend is closed; the record would never be written"
            raise RuntimeError(msg)
        try:
            self._queue.put_nowait(
                (
                    record,
                    result,
                    time.monotonic(),
                    structlog.contextvars.get_contextvars(),
                )
            )
            metrics.metering_queue_depth.set(self._queue.qsize())
        except asyncio.QueueFull:
            metrics.metering_queue_overflow_total.inc()
            if result is not None:
                # A result was there to measure and the fallback skips
                # measurement -- the line goes out incomplete, not late.
                metrics.metering_records_missing_measurements_total.inc()
            # The inline-written record is usage too (PR C): record_usage
            # filters non-usage records itself.
            await _write_and_account(record, self.usage_store)

    async def _run(self) -> None:
        while True:
            # Flush an aged batch first, so a steady trickle of submissions
            # (each satisfying the get below at once) cannot starve the
            # interval bound; then wait for the next item only as long as the
            # oldest buffered usage record may still wait.
            await self._usage_batcher.flush_if_due()
            try:
                item = await asyncio.wait_for(
                    self._queue.get(), self._usage_batcher.seconds_until_due()
                )
            except TimeoutError:
                continue
            metrics.metering_queue_depth.set(self._queue.qsize())
            if item is _SENTINEL:
                # Same deterministic drain as the queue itself: usage still
                # buffered goes out before the worker exits.
                await self._usage_batcher.flush()
                return
            record, result, enqueued_at, log_context = item
            metrics.metering_queue_delay_seconds.set(time.monotonic() - enqueued_at)
            # _measure_into never raises (see its docstring), so a
            # measurement failure still reaches the write below unmeasured.
            _measure_into(record, result, self._settings)
            try:
                with structlog.contextvars.bound_contextvars(**log_context):
                    await write_audit(record)
            except Exception:
                # The worker has no caller to raise to and must outlive the
                # failure, so surface it at error level with the traceback
                # and count it; the record's identifying fields let an
                # operator reconstruct the lost line from usage/traces.
                metrics.metering_worker_errors_total.inc()
                logger.exception(
                    "metering_audit_write_failed",
                    audit_id=record.audit_id,
                    principal_sub=record.principal_sub,
                    target=record.target,
                    action=record.action,
                    outcome=record.outcome,
                )
            else:
                metrics.metering_worker_processed_total.inc()
            # Usage accounting (PR C) runs strictly AFTER the audit write --
            # audit records are authoritative, usage is best-effort. The
            # record is buffered and written with its batch (one store round
            # trip per batch, not per tool call); the batcher's sink never
            # raises (store failures are logged and counted inside it).
            if counts_as_usage(record):
                await self._usage_batcher.add(record)
            # OTel aggregates (a no-op unless OTEL_METRICS_ENABLED) need the
            # measurements filled in above, which is why they are recorded
            # here and not on the hot path.
            otel_metrics.record_tool_call(record)


class InlineMeteringBackend(MeteringBackend):
    """Measures and writes each record synchronously in the submitting call.

    For unit tests and local dev, where no worker is wanted: the line is
    complete the moment ``submit`` returns, and a failing audit write raises
    to the submitter.
    """

    def __init__(self, settings: Settings, usage_store: UsageStore) -> None:
        self._settings = settings
        self.usage_store = usage_store

    @property
    def is_running(self) -> bool:
        return True

    async def start(self) -> None:
        """Nothing to start: every submission is processed in its own call."""

    async def aclose(self) -> None:
        """Nothing to drain: every submission was processed in its own call."""

    async def submit(self, record: AuditRecord, result: ToolResult | None) -> None:
        _measure_into(record, result, self._settings)
        await _write_and_account(record, self.usage_store)


def build_metering_backend(
    settings: Settings, usage_store: UsageStore
) -> MeteringBackend:
    """Build the (not yet started) backend selected by ``settings.metering_backend``, feeding *usage_store*.

    Adding a distributed backend later (e.g. "taskiq") is one ``case`` here
    plus widening the config Literal alongside the implementation -- see
    MeteringBackend's docstring. The ``match`` is exhaustive over the config
    Literal: ``assert_never`` makes mypy fail when a backend name is added
    without a branch here.
    """
    backend = settings.metering_backend
    match backend:
        case "in_process":
            return InProcessMeteringBackend(settings, usage_store)
        case "inline":
            return InlineMeteringBackend(settings, usage_store)
        case _:
            assert_never(backend)
