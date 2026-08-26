"""Tests for ``audit/pipeline.py`` -- the asynchronous metering pipeline.

The pipeline exists so a tool call never waits on result measurement or
audit I/O: the middleware hands ``(record, result)`` over and returns; a
background worker measures and writes. These tests pin down the guarantees
that make that safe: nothing is ever dropped (overflow degrades to an
inline unmeasured write), close drains everything already enqueued, a
poisoned item never kills the worker, and an uninitialized pipeline
degrades to the synchronous measure+write behavior unit tests and local
dev rely on.

Deterministic by construction: conftest.py's autouse ``stub_tiktoken``
fixture supplies a fake encoder (one token per 4 characters, minimum 1),
and every ordering assertion is gated on ``aclose`` (which drains) or an
explicit asyncio.Event rather than sleeps.
"""

from __future__ import annotations

import asyncio
import io
import json
from typing import Any

import mcp.types as mt
import pytest
from fastmcp.tools.base import ToolResult
from prometheus_client import REGISTRY

from af_mcp_broker.audit import AuditRecord, measure, pipeline
from af_mcp_broker.audit.logger import init_audit_logger
from af_mcp_broker.audit.pipeline import (
    InProcessMeteringBackend,
    MeteringBackend,
    aclose_metering_pipeline,
    init_metering_pipeline,
    submit_metered_audit,
)
from af_mcp_broker.config import Settings


def _sample(name: str) -> float:
    return REGISTRY.get_sample_value(name) or 0.0


def _overflow_count() -> float:
    return _sample("af_mcp_metering_queue_overflow_total")


@pytest.fixture(autouse=True)
def pinned_encoding(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pin the encoding name so ambient env vars can't change test behavior
    (mirrors test_measure.py's identical fixture)."""
    monkeypatch.setattr(
        measure,
        "get_settings",
        lambda: Settings(token_estimate_encoding="o200k_base"),
    )


@pytest.fixture(autouse=True)
async def clean_pipeline():
    """Never leak an installed module-level pipeline into other tests."""
    yield
    await aclose_metering_pipeline()


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


def _lines(buffer: io.StringIO) -> list[dict[str, Any]]:
    return [json.loads(line) for line in buffer.getvalue().splitlines()]


async def test_worker_measures_result_and_writes_the_line() -> None:
    """The background worker fills result_bytes/result_tokens_est from the
    handed-over ToolResult before writing the audit line."""
    buffer = io.StringIO()
    init_audit_logger(buffer)
    await init_metering_pipeline()

    result = ToolResult(content=[mt.TextContent(type="text", text="hellohello")])
    await submit_metered_audit(_record(), result)
    await aclose_metering_pipeline()

    (line,) = _lines(buffer)
    assert line["outcome"] == "success"
    assert line["result_bytes"] == len(b"hellohello")
    # Stub encoder: one token per 4 characters (10 chars -> 2 tokens).
    assert line["result_tokens_est"] == 2


async def test_submit_returns_before_the_line_is_written(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The hot path never waits on the worker: submit returns while the
    audit write is still gated, and the line lands once the gate opens."""
    buffer = io.StringIO()
    init_audit_logger(buffer)
    await init_metering_pipeline()

    gate = asyncio.Event()
    real_write_audit = pipeline.write_audit

    async def _gated_write_audit(record: AuditRecord) -> None:
        await gate.wait()
        await real_write_audit(record)

    monkeypatch.setattr(pipeline, "write_audit", _gated_write_audit)

    await submit_metered_audit(_record(), None)

    # submit returned while the worker is still parked on the gate --
    # nothing has been written yet.
    assert buffer.getvalue() == ""

    gate.set()
    await aclose_metering_pipeline()
    assert len(_lines(buffer)) == 1


async def test_overflow_writes_inline_unmeasured_and_drops_nothing() -> None:
    """A full queue must not drop the record: it is written immediately
    without measurement, the overflow counter increments, and the records
    already enqueued are still processed by the worker."""
    buffer = io.StringIO()
    init_audit_logger(buffer)
    # Tiny queue, worker deliberately not started yet: the queue can only
    # fill up, so the second submit overflows deterministically.
    p = InProcessMeteringBackend(maxsize=1)

    before = _overflow_count()
    missing_before = _sample("af_mcp_metering_records_missing_measurements_total")
    await p.submit(_record(request_id="queued"), None)
    overflow_result = ToolResult(content=[mt.TextContent(type="text", text="big")])
    await p.submit(_record(request_id="overflowed"), overflow_result)

    # The overflowing record was written inline, unmeasured, and counted --
    # both as an overflow and as a record whose present result went
    # unmeasured.
    (line,) = _lines(buffer)
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
    assert {line["request_id"] for line in _lines(buffer)} == {"queued", "overflowed"}


async def test_aclose_drains_everything_already_enqueued() -> None:
    buffer = io.StringIO()
    init_audit_logger(buffer)
    p = InProcessMeteringBackend(maxsize=10)
    await p.start()

    for i in range(5):
        await p.submit(_record(request_id=f"req-{i}"), None)
    await p.aclose()

    assert [line["request_id"] for line in _lines(buffer)] == [
        f"req-{i}" for i in range(5)
    ]


async def test_worker_survives_measurement_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A poisoned item (measurement raising) still yields an unmeasured
    audit line, and the worker goes on to process the next item."""
    buffer = io.StringIO()
    init_audit_logger(buffer)
    p = InProcessMeteringBackend()
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

    lines = _lines(buffer)
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


async def test_worker_survives_audit_write_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """write_audit itself failing is logged, not raised -- the worker must
    never die, and the next item is still processed."""
    buffer = io.StringIO()
    init_audit_logger(buffer)
    p = InProcessMeteringBackend()
    await p.start()

    real_write_audit = pipeline.write_audit

    async def _flaky_write_audit(record: AuditRecord) -> None:
        if record.request_id == "doomed":
            raise RuntimeError("audit output unavailable")
        await real_write_audit(record)

    monkeypatch.setattr(pipeline, "write_audit", _flaky_write_audit)

    errors_before = _sample("af_mcp_metering_worker_errors_total")
    await p.submit(_record(request_id="doomed"), None)
    await p.submit(_record(request_id="next"), None)
    await p.aclose()

    assert [line["request_id"] for line in _lines(buffer)] == ["next"]
    assert _sample("af_mcp_metering_worker_errors_total") == errors_before + 1


async def test_uninitialized_helper_measures_and_writes_inline() -> None:
    """Without init_metering_pipeline() (unit tests, local dev) the helper
    degrades to exactly the pre-pipeline behavior: measure + write
    synchronously, so the line is complete the moment the helper returns."""
    buffer = io.StringIO()
    init_audit_logger(buffer)

    result = ToolResult(content=[mt.TextContent(type="text", text="hellohello")])
    await submit_metered_audit(_record(), result)

    (line,) = _lines(buffer)
    assert line["result_bytes"] == len(b"hellohello")
    assert line["result_tokens_est"] == 2


# ---------------------------------------------------------------------------
# MeteringBackend seam -- the transport is a config-selected implementation
# behind an ABC, so a distributed backend can be added without touching the
# hot path. Only "in_process" exists today.
# ---------------------------------------------------------------------------


def test_in_process_backend_satisfies_the_abc() -> None:
    assert issubclass(InProcessMeteringBackend, MeteringBackend)
    assert isinstance(InProcessMeteringBackend(), MeteringBackend)


async def test_init_builds_the_backend_selected_by_settings() -> None:
    """init_metering_pipeline dispatches on settings.metering_backend and
    starts the backend it built."""
    backend = await init_metering_pipeline(Settings(metering_backend="in_process"))
    assert isinstance(backend, InProcessMeteringBackend)
    assert backend.is_running


# ---------------------------------------------------------------------------
# Worker health metrics -- queue depth, time-in-queue, and processed counts
# are the empirical trigger for ever introducing a distributed backend.
# ---------------------------------------------------------------------------


async def test_queue_depth_gauge_tracks_enqueue_and_dequeue() -> None:
    buffer = io.StringIO()
    init_audit_logger(buffer)
    # Worker deliberately not started: each submit only enqueues, so the
    # gauge must climb with the queue and return to zero after the drain.
    p = InProcessMeteringBackend(maxsize=10)

    await p.submit(_record(), None)
    assert _sample("af_mcp_metering_queue_depth") == 1
    await p.submit(_record(), None)
    assert _sample("af_mcp_metering_queue_depth") == 2

    await p.start()
    await p.aclose()
    assert _sample("af_mcp_metering_queue_depth") == 0


async def test_queue_delay_gauge_set_on_dequeue(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Each queued item carries its enqueue time; the worker publishes the
    time-in-queue of the most recently dequeued item. With the worker gated
    on the first record's write, the second record measurably ages in the
    queue before its dequeue."""
    buffer = io.StringIO()
    init_audit_logger(buffer)
    p = InProcessMeteringBackend()

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


async def test_worker_processed_total_counts_written_records() -> None:
    buffer = io.StringIO()
    init_audit_logger(buffer)
    p = InProcessMeteringBackend()
    await p.start()

    before = _sample("af_mcp_metering_worker_processed_total")
    await p.submit(_record(), None)
    await p.submit(
        _record(), ToolResult(content=[mt.TextContent(type="text", text="x")])
    )
    await p.aclose()

    assert _sample("af_mcp_metering_worker_processed_total") == before + 2
