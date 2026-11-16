"""Integration tests for the area ``test_usage_otel_events.py`` covers; the unit tests live in ``unit/test_usage_otel_events.py``."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any

import asyncpg
import pytest
from opentelemetry.sdk._logs.export import (
    InMemoryLogRecordExporter,
    LogRecordExporter,
    LogRecordExportResult,
)
from usage_otel_events_support import (  # noqa: F401
    _full_record,
    _logs,
    emitter_fixture,
    exporter_fixture,
)

from af_mcp_broker.usage import (
    EventEmittingUsageStore,
    OtelUsageEventEmitter,
    PostgresUsageStore,
)

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Sequence

    from opentelemetry.sdk._logs import ReadableLogRecord


class _RaisingExporter(LogRecordExporter):
    def export(self, batch: Sequence[ReadableLogRecord]) -> LogRecordExportResult:
        raise RuntimeError("collector exploded")

    def force_flush(self, timeout_millis: int = 30_000) -> bool:
        return True

    def shutdown(self) -> None:
        return


class _BlockingExporter(LogRecordExporter):
    def export(self, batch: Sequence[ReadableLogRecord]) -> LogRecordExportResult:
        time.sleep(2)
        return LogRecordExportResult.FAILURE

    def force_flush(self, timeout_millis: int = 30_000) -> bool:
        return True

    def shutdown(self) -> None:
        return


@pytest.fixture
async def pg_store(postgres_dsn: str) -> AsyncIterator[PostgresUsageStore]:
    s = PostgresUsageStore(postgres_dsn)
    await s.start()
    conn = await asyncpg.connect(postgres_dsn)
    try:
        await conn.execute("TRUNCATE af_mcp_usage_events CASCADE")
    finally:
        await conn.close()
    yield s
    await s.aclose()


async def _pg_count(dsn: str) -> int:
    conn = await asyncpg.connect(dsn)
    try:
        return int(await conn.fetchval("SELECT count(*) FROM af_mcp_usage_events"))
    finally:
        await conn.close()


# --- composite store: Postgres stays authoritative -------------------------


async def test_events_are_emitted_beside_the_postgres_write(
    pg_store: PostgresUsageStore,
    emitter: OtelUsageEventEmitter,
    exporter: InMemoryLogRecordExporter,
    postgres_dsn: str,
) -> None:
    store = EventEmittingUsageStore(pg_store, emitter)

    await store.record(_full_record(audit_id="single"))
    await store.record_many([_full_record(audit_id="b1"), _full_record(audit_id="b2")])
    emitter.shutdown()

    assert await _pg_count(postgres_dsn) == 3
    assert sorted(log.attributes["audit_id"] for log in _logs(exporter)) == [
        "b1",
        "b2",
        "single",
    ]


async def test_reads_delegate_to_the_wrapped_store(
    pg_store: PostgresUsageStore, emitter: OtelUsageEventEmitter
) -> None:
    store = EventEmittingUsageStore(pg_store, emitter)
    await store.record_many([_full_record()])

    (agg,) = await store.query("alice-sub", days=1)
    assert agg.calls == 1
    assert await store.list_subjects(days=1) == ["alice-sub"]


# --- a bad collector never affects the call path or the Postgres write -----


@pytest.mark.parametrize(
    "bad_exporter",
    [_RaisingExporter, _BlockingExporter],
    ids=["raising", "blocking"],
)
async def test_a_failing_exporter_does_not_affect_postgres_or_the_caller(
    pg_store: PostgresUsageStore,
    postgres_dsn: str,
    bad_exporter: type[LogRecordExporter],
) -> None:
    emitter = OtelUsageEventEmitter(bad_exporter())
    store = EventEmittingUsageStore(pg_store, emitter)

    started = time.monotonic()
    await store.record_many([_full_record(audit_id=f"id-{i}") for i in range(20)])
    await store.record(_full_record(audit_id="single"))
    elapsed = time.monotonic() - started

    assert await _pg_count(postgres_dsn) == 21
    # The batch processor exports on its own thread: a blocking exporter must
    # not hold up the caller.
    assert elapsed < 1.0
    emitter.shutdown()  # must not raise


async def test_an_unreachable_collector_does_not_affect_postgres_or_the_caller(
    pg_store: PostgresUsageStore,
    postgres_dsn: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:1")
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_TIMEOUT", "1")
    emitter = OtelUsageEventEmitter()  # the real OTLPLogExporter
    store = EventEmittingUsageStore(pg_store, emitter)

    started = time.monotonic()
    await store.record_many([_full_record(audit_id=f"id-{i}") for i in range(20)])
    elapsed = time.monotonic() - started

    assert await _pg_count(postgres_dsn) == 20
    assert elapsed < 1.0
    emitter.shutdown()  # must not raise


async def test_an_emitter_that_raises_does_not_affect_postgres(
    pg_store: PostgresUsageStore,
    emitter: OtelUsageEventEmitter,
    postgres_dsn: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def boom(*_a: Any, **_k: Any) -> None:
        raise RuntimeError("sdk bug")

    monkeypatch.setattr(emitter._logger, "emit", boom)
    store = EventEmittingUsageStore(pg_store, emitter)

    await store.record_many([_full_record()])  # must not raise

    assert await _pg_count(postgres_dsn) == 1
