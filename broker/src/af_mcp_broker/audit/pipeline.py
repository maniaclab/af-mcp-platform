"""Asynchronous tool-call metering pipeline (observability roadmap PR B).

A tool call must never wait on measurement or audit I/O: serializing and
tokenizing a large result (``audit/measure.py``) can cost tens of
milliseconds, and even the to_thread'd audit write is an inline await. The
authorization middleware therefore hands its success and error audit
records to this pipeline -- ``submit_metered_audit(record, result)`` -- and
returns; a background worker measures the result (success path) and writes
the line. DENIED and UNMAPPED records deliberately do NOT come through
here: they are security-relevant, have nothing to measure, and cost
nothing, so the middleware still writes them synchronously inline.

Nothing is ever dropped. A full queue degrades to writing the record
inline without measurement -- an overloaded broker paying that cost is
acceptable, a lost audit line is not -- counted by
``metrics.metering_queue_overflow_total``. And with no pipeline installed
at all (unit tests, local dev), the module-level helper degrades to
measuring and writing synchronously, exactly the pre-pipeline behavior
(mirrors ``write_audit``'s graceful not-initialized fallback).

Metering is best-effort; audit records are authoritative.

The transport between the hot path and the worker is a config-selected
``MeteringBackend`` (``METERING_BACKEND`` -> ``settings.metering_backend``);
only ``in_process`` exists today -- see the ABC's docstring.
"""

from __future__ import annotations

import abc
import asyncio
import time
from typing import TYPE_CHECKING, Any

import structlog

from af_mcp_broker import metrics
from af_mcp_broker.audit.logger import AuditRecord, write_audit
from af_mcp_broker.audit.measure import measure_tool_result
from af_mcp_broker.config import Settings, get_settings

if TYPE_CHECKING:
    from collections.abc import Callable

    from fastmcp.tools.base import ToolResult

logger = structlog.get_logger(__name__)

# Queue bound. Beyond backpressure, this also bounds memory: queued items
# hold references to result payloads until the worker measures them, so an
# unbounded queue under a slow output could pin arbitrarily many results.
QUEUE_MAXSIZE = 10_000

# Enqueued by aclose(): the worker processes every record queued before it,
# then exits -- a deterministic drain with no cancellation racing a
# half-processed item.
_SENTINEL: Any = object()

_pipeline: MeteringBackend | None = None


def _measure_into(record: AuditRecord, result: ToolResult | None) -> None:
    """Fill ``record.result_bytes``/``result_tokens_est`` from *result*.

    ``measure_tool_result`` already degrades to ``(None, None)`` internally;
    the catch here is belt-and-braces for failures it did not anticipate --
    the audit line must still be written (unmeasured) if measurement blows
    up, so nothing may propagate out of this helper.
    """
    if result is None:
        return
    try:
        record.result_bytes, record.result_tokens_est = measure_tool_result(result)
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

    def __init__(self, maxsize: int = QUEUE_MAXSIZE) -> None:
        # Items are (record, result, enqueued_at) tuples -- enqueued_at is a
        # time.monotonic() timestamp feeding the queue-delay gauge -- or the
        # drain sentinel.
        self._queue: asyncio.Queue[Any] = asyncio.Queue(maxsize=maxsize)
        self._worker: asyncio.Task[None] | None = None

    @property
    def is_running(self) -> bool:
        return self._worker is not None and not self._worker.done()

    async def start(self) -> None:
        self._worker = asyncio.create_task(self._run(), name="metering-pipeline")

    async def aclose(self) -> None:
        """Drain every already-enqueued record, then stop the worker."""
        if self._worker is None:
            return
        await self._queue.put(_SENTINEL)
        await self._worker
        self._worker = None

    async def submit(self, record: AuditRecord, result: ToolResult | None) -> None:
        """Enqueue without ever blocking the caller.

        On a full queue: do NOT drop -- write the record immediately,
        without measurement (this fallback path may await; an overloaded
        broker paying that cost is acceptable, a lost audit line is not),
        and count the overflow.
        """
        try:
            self._queue.put_nowait((record, result, time.monotonic()))
            metrics.metering_queue_depth.set(self._queue.qsize())
        except asyncio.QueueFull:
            metrics.metering_queue_overflow_total.inc()
            if result is not None:
                # A result was there to measure and the fallback skips
                # measurement -- the line goes out incomplete, not late.
                metrics.metering_records_missing_measurements_total.inc()
            await write_audit(record)

    async def _run(self) -> None:
        while True:
            item = await self._queue.get()
            metrics.metering_queue_depth.set(self._queue.qsize())
            if item is _SENTINEL:
                return
            record, result, enqueued_at = item
            metrics.metering_queue_delay_seconds.set(time.monotonic() - enqueued_at)
            # _measure_into never raises (see its docstring), so a
            # measurement failure still reaches the write below unmeasured.
            _measure_into(record, result)
            try:
                await write_audit(record)
            except Exception as exc:  # noqa: BLE001 -- the worker must never die
                metrics.metering_worker_errors_total.inc()
                logger.warning(
                    "metering_audit_write_failed",
                    audit_id=record.audit_id,
                    error=str(exc),
                )
            else:
                metrics.metering_worker_processed_total.inc()


# Maps ``settings.metering_backend`` values to backend factories. Adding a
# distributed backend later (e.g. "taskiq") is one entry here plus widening
# the config Literal alongside the implementation -- see MeteringBackend's
# docstring. config.py's Literal already rejects values with no entry here,
# so a KeyError below means the Literal and this table drifted apart.
_BACKEND_FACTORIES: dict[str, Callable[[], MeteringBackend]] = {
    "in_process": InProcessMeteringBackend,
}


async def init_metering_pipeline(settings: Settings | None = None) -> MeteringBackend:
    """Create, start, and install the process-wide backend (app.py lifespan).

    The implementation is selected by ``settings.metering_backend``; with no
    Settings passed (tests), the process-wide ``get_settings()`` is used.
    """
    global _pipeline
    if settings is None:
        settings = get_settings()
    _pipeline = _BACKEND_FACTORIES[settings.metering_backend]()
    await _pipeline.start()
    return _pipeline


async def aclose_metering_pipeline() -> None:
    """Drain and uninstall the process-wide pipeline (app.py lifespan shutdown)."""
    global _pipeline
    if _pipeline is None:
        return
    await _pipeline.aclose()
    _pipeline = None


async def submit_metered_audit(record: AuditRecord, result: ToolResult | None) -> None:
    """Module-level helper to submit audit record.

    With no running pipeline installed (unit tests,
    local dev -- mirrors write_audit's graceful fallback), measure + write
    synchronously inline: behavior degrades to exactly the pre-pipeline
    inline path.
    """
    if _pipeline is None or not _pipeline.is_running:
        _measure_into(record, result)
        await write_audit(record)
        return
    await _pipeline.submit(record, result)
