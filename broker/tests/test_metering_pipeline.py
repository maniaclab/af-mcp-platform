"""Tests for ``metering.py`` -- the asynchronous metering pipeline.

The pipeline exists so a tool call never waits on result measurement or
audit I/O: the middleware hands ``(record, result)`` over and returns; a
background worker measures and writes. These tests pin down the guarantees
that make that safe: nothing is ever dropped (overflow degrades to an
inline unmeasured write), close drains everything already enqueued, a
poisoned item never kills the worker, and the explicit inline backend
measures and writes synchronously, the behavior unit tests and local dev
rely on. Every backend owns the usage store it feeds: nothing is installed
process-wide.

Deterministic by construction: conftest.py's autouse ``stub_tiktoken``
fixture supplies a fake encoder (one token per 4 characters, minimum 1),
and every ordering assertion is gated on ``aclose`` (which drains) or an
explicit asyncio.Event rather than sleeps.
"""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any

import asyncpg
import mcp.types as mt
import pytest
import structlog
from fastmcp.tools.base import ToolResult
from prometheus_client import REGISTRY

from af_mcp_broker import metering as pipeline
from af_mcp_broker.audit import AuditRecord
from af_mcp_broker.config import Settings
from af_mcp_broker.metering import (
    InlineMeteringBackend,
    InProcessMeteringBackend,
    MeteringBackend,
    build_metering_backend,
)
from af_mcp_broker.usage import InMemoryUsageStore, UsageStore, build_usage_store


def _sample(name: str) -> float:
    return REGISTRY.get_sample_value(name) or 0.0


def _overflow_count() -> float:
    return _sample("af_mcp_metering_queue_overflow_total")


# Pins the encoding name so ambient env vars can't change test behavior
# (mirrors test_measure.py).
_SETTINGS = Settings(token_estimate_encoding="o200k_base")


def _backend(
    settings: Settings = _SETTINGS,
    usage_store: UsageStore | None = None,
    **kwargs: Any,
) -> InProcessMeteringBackend:
    """An (unstarted) in-process backend feeding *usage_store*, a fresh in-memory one when omitted."""
    return InProcessMeteringBackend(
        settings, usage_store or InMemoryUsageStore(), **kwargs
    )


def _record(**overrides: Any) -> AuditRecord:
    fields: dict[str, Any] = {
        "principal_sub": "sub-abc",
        "principal_uid": 1000,
        "permission": "read_data",
        "target": "rucio",
        "action": "rucio_list_dids",
        "action_type": "read",
        "args_summary": "scope=...",
        "timestamp": 1234.5,
        "request_id": "req-1",
        "outcome": "success",
        "duration_ms": 12.5,
    }
    fields.update(overrides)
    return AuditRecord(**fields)


def _lines(audit_buffer) -> list[dict[str, Any]]:
    return [json.loads(line) for line in audit_buffer.getvalue().splitlines()]


async def test_worker_measures_result_and_writes_the_line(audit_buffer) -> None:
    """The background worker fills result_bytes/result_tokens_est from the
    handed-over ToolResult before writing the audit line."""
    backend = _backend()
    await backend.start()

    result = ToolResult(content=[mt.TextContent(type="text", text="hellohello")])
    await backend.submit(_record(), result)
    await backend.aclose()

    (line,) = _lines(audit_buffer)
    assert line["outcome"] == "success"
    assert line["result_bytes"] == len(b"hellohello")
    # Stub encoder: one token per 4 characters (10 chars -> 2 tokens).
    assert line["result_tokens_est"] == 2


async def test_submit_returns_before_the_line_is_written(
    monkeypatch: pytest.MonkeyPatch,
    audit_buffer,
) -> None:
    """The hot path never waits on the worker: submit returns while the
    audit write is still gated, and the line lands once the gate opens."""
    backend = _backend()
    await backend.start()

    gate = asyncio.Event()
    real_write_audit = pipeline.write_audit

    async def _gated_write_audit(record: AuditRecord) -> None:
        await gate.wait()
        await real_write_audit(record)

    monkeypatch.setattr(pipeline, "write_audit", _gated_write_audit)

    await backend.submit(_record(), None)

    # submit returned while the worker is still parked on the gate --
    # nothing has been written yet.
    assert audit_buffer.getvalue() == ""

    gate.set()
    await backend.aclose()
    assert len(_lines(audit_buffer)) == 1


async def test_overflow_writes_inline_unmeasured_and_drops_nothing(
    audit_buffer,
) -> None:
    """A full queue must not drop the record: it is written immediately
    without measurement, the overflow counter increments, and the records
    already enqueued are still processed by the worker."""
    # Tiny queue, worker deliberately not started yet: the queue can only
    # fill up, so the second submit overflows deterministically.
    p = _backend(Settings(), maxsize=1)

    before = _overflow_count()
    missing_before = _sample("af_mcp_metering_records_missing_measurements_total")
    await p.submit(_record(request_id="queued"), None)
    overflow_result = ToolResult(content=[mt.TextContent(type="text", text="big")])
    await p.submit(_record(request_id="overflowed"), overflow_result)

    # The overflowing record was written inline, unmeasured, and counted --
    # both as an overflow and as a record whose present result went
    # unmeasured.
    (line,) = _lines(audit_buffer)
    assert line["request_id"] == "overflowed"
    assert line["result_bytes"] is None
    assert line["result_tokens_est"] is None
    assert _overflow_count() == before + 1
    assert (
        _sample("af_mcp_metering_records_missing_measurements_total")
        == missing_before + 1
    )

    # The queued record was not dropped either: the worker still writes it.
    await p.start()
    await p.aclose()
    assert {line["request_id"] for line in _lines(audit_buffer)} == {
        "queued",
        "overflowed",
    }


async def test_aclose_drains_everything_already_enqueued(audit_buffer) -> None:
    p = _backend(Settings(), maxsize=10)
    await p.start()

    for i in range(5):
        await p.submit(_record(request_id=f"req-{i}"), None)
    await p.aclose()

    assert [line["request_id"] for line in _lines(audit_buffer)] == [
        f"req-{i}" for i in range(5)
    ]


async def test_worker_survives_measurement_failure(
    monkeypatch: pytest.MonkeyPatch,
    audit_buffer,
) -> None:
    """A poisoned item (measurement raising) still yields an unmeasured
    audit line, and the worker goes on to process the next item."""
    p = _backend(Settings())
    await p.start()

    def _boom(result: Any) -> tuple[int | None, int | None]:
        raise RuntimeError("poisoned result")

    monkeypatch.setattr(pipeline, "measure_tool_result", _boom)

    errors_before = _sample("af_mcp_metering_worker_errors_total")
    missing_before = _sample("af_mcp_metering_records_missing_measurements_total")
    poisoned = ToolResult(content=[mt.TextContent(type="text", text="x")])
    await p.submit(_record(request_id="poisoned"), poisoned)
    await p.submit(_record(request_id="next"), None)
    await p.aclose()

    lines = _lines(audit_buffer)
    assert [line["request_id"] for line in lines] == ["poisoned", "next"]
    assert lines[0]["result_bytes"] is None
    assert lines[0]["result_tokens_est"] is None
    # The failure was counted, and so was the record it left unmeasured
    # despite its present result.
    assert _sample("af_mcp_metering_worker_errors_total") == errors_before + 1
    assert (
        _sample("af_mcp_metering_records_missing_measurements_total")
        == missing_before + 1
    )


async def test_worker_survives_audit_write_failure_and_reports_it_loudly(
    monkeypatch: pytest.MonkeyPatch,
    audit_buffer,
) -> None:
    """The worker has no caller to raise to, so a failing audit write is
    logged at error level with its traceback and the identifying fields of
    the lost record, and counted -- and the worker never dies: the next item
    is still processed."""
    monkeypatch.setattr(
        pipeline, "logger", structlog.get_logger("test_metering.worker_failure")
    )
    p = _backend(Settings())
    await p.start()

    real_write_audit = pipeline.write_audit

    async def _flaky_write_audit(record: AuditRecord) -> None:
        if record.request_id == "doomed":
            raise RuntimeError("audit output unavailable")
        await real_write_audit(record)

    monkeypatch.setattr(pipeline, "write_audit", _flaky_write_audit)

    errors_before = _sample("af_mcp_metering_worker_errors_total")
    with structlog.testing.capture_logs() as logs:
        await p.submit(_record(request_id="doomed", audit_id="lost-1"), None)
        await p.submit(_record(request_id="next"), None)
        await p.aclose()

    # capture_logs diverts every structlog event, the audit lines included.
    assert [e["request_id"] for e in logs if e["event"] == "audit"] == ["next"]
    assert _sample("af_mcp_metering_worker_errors_total") == errors_before + 1
    (failure,) = [e for e in logs if e["event"] == "metering_audit_write_failed"]
    assert failure["log_level"] == "error"
    assert failure["exc_info"] is True
    assert failure["audit_id"] == "lost-1"
    assert failure["target"] == "rucio"


async def test_worker_written_line_carries_the_submitting_requests_correlation_id(
    audit_buffer,
) -> None:
    """The worker runs in its own task, so the line it writes would lose the
    request's correlation_id/subject unless they travel with the queued item."""
    structlog.contextvars.clear_contextvars()
    structlog.contextvars.bind_contextvars(correlation_id="corr-9", subject="sub-abc")
    backend = _backend()
    await backend.start()

    await backend.submit(_record(), None)
    structlog.contextvars.clear_contextvars()
    await backend.aclose()

    (line,) = _lines(audit_buffer)
    assert line["correlation_id"] == "corr-9"
    assert line["subject"] == "sub-abc"


async def test_inline_paths_raise_when_the_audit_write_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Without a worker (the inline backend, or a full queue) the write happens
    in the caller's own call, so a failure propagates to it."""

    async def _failing_write_audit(record: AuditRecord) -> None:
        raise RuntimeError("audit output unavailable")

    monkeypatch.setattr(pipeline, "write_audit", _failing_write_audit)

    with pytest.raises(RuntimeError, match="audit output unavailable"):
        await InlineMeteringBackend(_SETTINGS, InMemoryUsageStore()).submit(
            _record(), None
        )

    full = _backend(Settings(), maxsize=1)
    await full.submit(_record(), None)
    with pytest.raises(RuntimeError, match="audit output unavailable"):
        await full.submit(_record(), None)


async def test_inline_backend_measures_and_writes_synchronously(audit_buffer) -> None:
    """The inline backend (unit tests, local dev) measures and writes in the
    caller's own call, so the line is complete the moment submit returns."""
    backend = InlineMeteringBackend(_SETTINGS, InMemoryUsageStore())

    result = ToolResult(content=[mt.TextContent(type="text", text="hellohello")])
    await backend.submit(_record(), result)

    (line,) = _lines(audit_buffer)
    assert line["result_bytes"] == len(b"hellohello")
    assert line["result_tokens_est"] == 2


# ---------------------------------------------------------------------------
# MeteringBackend seam -- the transport is a config-selected implementation
# behind an ABC, so a distributed backend can be added without touching the
# hot path. Only "in_process" exists today.
# ---------------------------------------------------------------------------


def test_in_process_backend_satisfies_the_abc() -> None:
    assert issubclass(InProcessMeteringBackend, MeteringBackend)
    assert issubclass(InlineMeteringBackend, MeteringBackend)
    assert isinstance(_backend(Settings()), MeteringBackend)


@pytest.mark.parametrize(
    ("name", "expected"),
    [("in_process", InProcessMeteringBackend), ("inline", InlineMeteringBackend)],
)
def test_build_selects_the_backend_named_by_settings(
    name: Any, expected: type[MeteringBackend]
) -> None:
    """build_metering_backend dispatches on settings.metering_backend."""
    backend = build_metering_backend(
        Settings(metering_backend=name), InMemoryUsageStore()
    )

    assert type(backend) is expected


async def test_a_closed_in_process_backend_refuses_submissions() -> None:
    """A record handed to a drained queue would never be written, so the
    submitter hears about it instead."""
    backend = _backend()
    await backend.start()
    await backend.aclose()

    with pytest.raises(RuntimeError, match="closed"):
        await backend.submit(_record(), None)


# ---------------------------------------------------------------------------
# Worker health metrics -- queue depth, time-in-queue, and processed counts
# are the empirical trigger for ever introducing a distributed backend.
# ---------------------------------------------------------------------------


async def test_queue_depth_gauge_tracks_enqueue_and_dequeue(audit_buffer) -> None:
    # Worker deliberately not started: each submit only enqueues, so the
    # gauge must climb with the queue and return to zero after the drain.
    p = _backend(Settings(), maxsize=10)

    await p.submit(_record(), None)
    assert _sample("af_mcp_metering_queue_depth") == 1
    await p.submit(_record(), None)
    assert _sample("af_mcp_metering_queue_depth") == 2

    await p.start()
    await p.aclose()
    assert _sample("af_mcp_metering_queue_depth") == 0


async def test_queue_delay_gauge_set_on_dequeue(
    monkeypatch: pytest.MonkeyPatch,
    audit_buffer,
) -> None:
    """Each queued item carries its enqueue time; the worker publishes the
    time-in-queue of the most recently dequeued item. With the worker gated
    on the first record's write, the second record measurably ages in the
    queue before its dequeue."""
    p = _backend(Settings())

    gate = asyncio.Event()
    real_write_audit = pipeline.write_audit

    async def _gated_write_audit(record: AuditRecord) -> None:
        await gate.wait()
        await real_write_audit(record)

    monkeypatch.setattr(pipeline, "write_audit", _gated_write_audit)

    await p.start()
    await p.submit(_record(request_id="first"), None)
    await p.submit(_record(request_id="second"), None)
    # Not an ordering sleep -- it exists purely so "second" accrues a
    # nonzero time-in-queue while the worker is parked on the gate.
    await asyncio.sleep(0.02)
    gate.set()
    await p.aclose()

    assert _sample("af_mcp_metering_queue_delay_seconds") > 0.0


async def test_worker_processed_total_counts_written_records(audit_buffer) -> None:
    p = _backend(Settings())
    await p.start()

    before = _sample("af_mcp_metering_worker_processed_total")
    await p.submit(_record(), None)
    await p.submit(
        _record(), ToolResult(content=[mt.TextContent(type="text", text="x")])
    )
    await p.aclose()

    assert _sample("af_mcp_metering_worker_processed_total") == before + 2


# ---------------------------------------------------------------------------
# Usage store feed (PR C) -- after each audit write the record is accounted
# in the installed UsageStore (tool-call records with outcome success/error
# only). Best-effort: a store failure never affects the audit write, which
# always happens FIRST.
# ---------------------------------------------------------------------------


@pytest.fixture
def usage_store() -> InMemoryUsageStore:
    return InMemoryUsageStore()


async def test_worker_feeds_the_usage_store_after_the_audit_write(
    usage_store,
    audit_buffer,
) -> None:
    backend = _backend(usage_store=usage_store)
    await backend.start()

    await backend.submit(_record(mcp_service="rucio", timestamp=time.time()), None)
    await backend.aclose()

    assert len(_lines(audit_buffer)) == 1
    (agg,) = await usage_store.query("sub-abc", days=30)
    assert agg.calls == 1
    assert agg.service == "rucio"


async def test_inline_backend_feeds_the_usage_store(usage_store, audit_buffer) -> None:
    """The inline backend still accounts usage."""
    backend = InlineMeteringBackend(_SETTINGS, usage_store)

    await backend.submit(_record(mcp_service="rucio", timestamp=time.time()), None)

    (agg,) = await usage_store.query("sub-abc", days=30)
    assert agg.calls == 1


async def test_overflow_inline_write_feeds_the_usage_store(
    usage_store, audit_buffer
) -> None:
    """The full-queue degradation writes the line inline unmeasured -- that
    written record is usage too, not a gap in the accounting."""
    # Tiny queue, worker deliberately not started: the second submit
    # overflows deterministically (same setup as the overflow test above).
    p = _backend(Settings(), usage_store, maxsize=1)
    await p.submit(
        _record(request_id="queued", mcp_service="rucio", timestamp=time.time()), None
    )
    await p.submit(
        _record(request_id="overflowed", mcp_service="rucio", timestamp=time.time()),
        None,
    )

    # Only the overflowed record has been written (and accounted) so far.
    (agg,) = await usage_store.query("sub-abc", days=30)
    assert agg.calls == 1
    await p.start()
    await p.aclose()
    (agg,) = await usage_store.query("sub-abc", days=30)
    assert agg.calls == 2


async def test_worker_skips_usage_for_records_without_an_mcp_service(
    usage_store,
    audit_buffer,
) -> None:
    """Non-tool-call records flow through the same write paths but are not
    usage (no service to attribute them to)."""

    await InlineMeteringBackend(_SETTINGS, usage_store).submit(
        _record(mcp_service=None, timestamp=time.time()), None
    )

    assert len(_lines(audit_buffer)) == 1
    assert await usage_store.query("sub-abc", days=30) == []


async def test_usage_store_failure_never_affects_the_audit_write(
    usage_store,
    monkeypatch: pytest.MonkeyPatch,
    audit_buffer,
) -> None:
    """The audit write happens FIRST and a store failure after it is caught,
    logged, and counted -- the line is intact and the worker survives."""

    async def _boom(record: AuditRecord) -> None:
        raise RuntimeError("usage store down")

    monkeypatch.setattr(usage_store, "record", _boom)

    backend = _backend(usage_store=usage_store)
    await backend.start()

    errors_before = _sample("af_mcp_metering_worker_errors_total")
    await backend.submit(_record(mcp_service="rucio", timestamp=time.time()), None)
    await backend.aclose()

    (line,) = _lines(audit_buffer)
    assert line["outcome"] == "success"
    assert _sample("af_mcp_metering_worker_errors_total") == errors_before + 1


# ---------------------------------------------------------------------------
# Usage batching -- the worker buffers usage records and writes them with one
# UsageStore.record_many per batch: at USAGE_BATCH_MAX records, after
# USAGE_BATCH_INTERVAL_MS, or on aclose. The audit line is still written first
# and per record; only the usage write is batched. The inline paths (overflow,
# no pipeline running) are unbatched and covered above.
# ---------------------------------------------------------------------------

_NEVER_MS = 3_600_000  # an interval that cannot fire during a test


class _BatchRecordingStore(InMemoryUsageStore):
    """In-memory store that remembers each record_many call's audit_ids."""

    def __init__(self) -> None:
        super().__init__()
        self.batches: list[list[str]] = []
        self.flushed = asyncio.Event()

    async def record_many(self, records: list[AuditRecord]) -> None:
        self.batches.append([r.audit_id for r in records])
        await super().record_many(records)
        self.flushed.set()


@pytest.fixture
def batch_store() -> _BatchRecordingStore:
    return _BatchRecordingStore()


def _usage_record(**overrides: Any) -> AuditRecord:
    return _record(mcp_service="rucio", timestamp=time.time(), **overrides)


async def _until(predicate) -> None:
    """Poll *predicate* with tiny sleeps; fail rather than hang."""
    async with asyncio.timeout(5):
        while not predicate():
            await asyncio.sleep(0.005)


async def test_usage_is_written_in_one_batch_when_the_batch_is_full(
    batch_store: _BatchRecordingStore,
    audit_buffer,
) -> None:
    p = _backend(
        Settings(usage_batch_max=3, usage_batch_interval_ms=_NEVER_MS),
        usage_store=batch_store,
    )
    await p.start()

    records = [_usage_record() for _ in range(3)]
    for r in records:
        await p.submit(r, None)
    async with asyncio.timeout(5):
        await batch_store.flushed.wait()

    assert batch_store.batches == [[r.audit_id for r in records]]
    await p.aclose()


async def test_usage_below_the_batch_size_waits_then_flushes_on_aclose(
    batch_store: _BatchRecordingStore,
    audit_buffer,
) -> None:
    p = _backend(
        Settings(usage_batch_max=10, usage_batch_interval_ms=_NEVER_MS),
        usage_store=batch_store,
    )
    await p.start()

    await p.submit(_usage_record(), None)
    await p.submit(_usage_record(), None)
    # Audit lines are written per record, immediately; only usage waits.
    await _until(lambda: len(_lines(audit_buffer)) == 2)
    assert batch_store.batches == []

    await p.aclose()

    assert len(batch_store.batches) == 1
    assert len(batch_store.batches[0]) == 2


async def test_usage_is_flushed_when_the_interval_elapses(
    batch_store: _BatchRecordingStore,
    audit_buffer,
) -> None:
    p = _backend(
        Settings(usage_batch_max=100, usage_batch_interval_ms=20),
        usage_store=batch_store,
    )
    await p.start()

    record = _usage_record()
    await p.submit(record, None)
    # No further submissions and no aclose: only the interval can flush.
    async with asyncio.timeout(5):
        await batch_store.flushed.wait()

    assert batch_store.batches == [[record.audit_id]]
    await p.aclose()
    assert batch_store.batches == [[record.audit_id]]


async def test_non_usage_records_are_not_buffered(
    batch_store: _BatchRecordingStore,
    audit_buffer,
) -> None:
    p = _backend(
        Settings(usage_batch_max=1, usage_batch_interval_ms=_NEVER_MS),
        usage_store=batch_store,
    )
    await p.start()

    await p.submit(_record(mcp_service=None), None)
    await p.aclose()

    assert batch_store.batches == []


async def test_a_failed_usage_batch_is_counted_per_row_and_audit_lines_survive(
    batch_store: _BatchRecordingStore,
    audit_buffer,
) -> None:
    async def _boom(records: list[AuditRecord]) -> None:
        raise RuntimeError("usage store down")

    batch_store.record_many = _boom  # type: ignore[method-assign]
    p = _backend(
        Settings(usage_batch_max=3, usage_batch_interval_ms=_NEVER_MS),
        usage_store=batch_store,
    )
    await p.start()

    errors_before = _sample("af_mcp_metering_worker_errors_total")
    for _ in range(3):
        await p.submit(_usage_record(), None)
    await p.aclose()

    assert len(_lines(audit_buffer)) == 3
    assert _sample("af_mcp_metering_worker_errors_total") == errors_before + 3


async def test_duplicate_audit_ids_through_the_pipeline_count_once_in_postgres(
    postgres_dsn: str,
    audit_buffer,
) -> None:
    """End to end against a real postgres: the same record redelivered in one
    batch and again in a later batch still produces a single usage row."""
    store = build_usage_store(
        Settings(
            usage_store_backend="postgres",
            usage_postgres_dsn=postgres_dsn,
            usage_batch_max=2,
            usage_batch_interval_ms=_NEVER_MS,
        )
    )
    await store.start()
    conn = await asyncpg.connect(postgres_dsn)
    try:
        await conn.execute("TRUNCATE af_mcp_usage_events")
    finally:
        await conn.close()
    p = _backend(
        Settings(usage_batch_max=2, usage_batch_interval_ms=_NEVER_MS),
        usage_store=store,
    )
    await p.start()

    record = _usage_record()
    await p.submit(record, None)
    await p.submit(record, None)  # fills the batch: duplicate within a batch
    await p.submit(record, None)  # next batch: duplicate across batches
    await p.aclose()

    (agg,) = await store.query("sub-abc", days=30)
    assert agg.calls == 1
    await store.aclose()
