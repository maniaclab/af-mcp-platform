"""Tests for ``usage/otel_events.py`` -- opt-in per-call usage as OTel log records.

Test doubles sit at the exporter boundary only:

* ``InMemoryLogRecordExporter`` for what the broker emits (the exact
  attribute set, event name, ordering relative to Postgres).
* Exporters that raise or block, and a real ``OTLPLogExporter`` pointed at an
  unreachable port, for the contract that a bad collector never affects the
  call path or the Postgres write. The Postgres store is the real one, on the
  repo's ephemeral server.
* A real ``OTLPLogExporter`` against an in-process OTLP/HTTP receiver
  (``_otlp_collector.OtlpCollector``) for what goes on the wire.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any

import asyncpg  # type: ignore[import-untyped]
import pytest
from _otlp_collector import OtlpCollector
from opentelemetry.sdk._logs.export import (
    InMemoryLogRecordExporter,
    LogRecordExporter,
    LogRecordExportResult,
)
from test_usage_postgres import _record

import af_mcp_broker.usage as usage_module
from af_mcp_broker import otel_metrics, tracing
from af_mcp_broker.config import Settings
from af_mcp_broker.usage import (
    EventEmittingUsageStore,
    InMemoryUsageStore,
    OtelUsageEventEmitter,
    PostgresUsageStore,
    aclose_usage_store,
    init_usage_store,
    record_usage,
    record_usage_batch,
)

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Iterator, Sequence

    from opentelemetry.sdk._logs import ReadableLogRecord

    from af_mcp_broker.audit.logger import AuditRecord

_ENDPOINT = "http://collector.invalid:4318"

# The exact attribute set of a fully populated record: nothing else may be
# added (never tool arguments or results).
_EVENT_ATTRIBUTES = {
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
}


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
def exporter() -> InMemoryLogRecordExporter:
    return InMemoryLogRecordExporter()


@pytest.fixture
def emitter(exporter: InMemoryLogRecordExporter) -> Iterator[OtelUsageEventEmitter]:
    e = OtelUsageEventEmitter(exporter)
    yield e
    e.shutdown()


@pytest.fixture
async def pg_store(postgres_dsn: str) -> AsyncIterator[PostgresUsageStore]:
    s = PostgresUsageStore(postgres_dsn)
    await s.start()
    conn = await asyncpg.connect(postgres_dsn)
    try:
        await conn.execute("TRUNCATE af_mcp_usage_events")
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


def _full_record(**overrides: Any) -> AuditRecord:
    fields: dict[str, Any] = {
        "audit_id": "audit-1",
        "trace_id": "a" * 32,
        "principal_sub": "alice-sub",
        "token_id": "tok-1",
        "args_summary": "scope=SECRET-ARGUMENT",
        "duration_ms": 12.5,
        "result_bytes": 321,
        "result_tokens_est": 80,
    }
    fields.update(overrides)
    return _record(**fields)


def _logs(exporter: InMemoryLogRecordExporter) -> list[Any]:
    return [r.log_record for r in exporter.get_finished_logs()]


# --- settings / wiring -----------------------------------------------------


def test_off_by_default_and_reads_env(monkeypatch: pytest.MonkeyPatch) -> None:
    assert Settings().usage_events_otlp_enabled is False
    monkeypatch.setenv("USAGE_EVENTS_OTLP_ENABLED", "true")
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", _ENDPOINT)
    assert Settings().usage_events_otlp_enabled is True


def test_enabled_without_an_endpoint_is_a_startup_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("OTEL_EXPORTER_OTLP_ENDPOINT", raising=False)
    with pytest.raises(ValueError, match="USAGE_EVENTS_OTLP_ENABLED") as excinfo:
        Settings(usage_events_otlp_enabled=True)
    assert "OTEL_EXPORTER_OTLP_ENDPOINT" in str(excinfo.value)


async def test_disabled_leaves_the_store_unwrapped() -> None:
    store = await init_usage_store(Settings())
    try:
        assert isinstance(store, InMemoryUsageStore)
    finally:
        await aclose_usage_store()


async def test_enabled_wraps_the_configured_store() -> None:
    store = await init_usage_store(
        Settings(usage_events_otlp_enabled=True, otel_exporter_otlp_endpoint=_ENDPOINT)
    )
    try:
        assert isinstance(store, EventEmittingUsageStore)
    finally:
        await aclose_usage_store()


# --- what is emitted -------------------------------------------------------


def test_emits_one_record_with_exactly_the_documented_attributes(
    emitter: OtelUsageEventEmitter, exporter: InMemoryLogRecordExporter
) -> None:
    emitter.emit(_full_record())
    emitter.shutdown()

    (log,) = _logs(exporter)
    assert log.event_name == "af_mcp.usage"
    assert dict(log.attributes) == {
        "audit_id": "audit-1",
        "trace_id": "a" * 32,
        "principal_sub": "alice-sub",
        "token_id": "tok-1",
        "service": "rucio",
        "method": "rucio_list_dids",
        "outcome": "success",
        "duration_ms": 12.5,
        "result_bytes": 321,
        "result_tokens_est": 80,
    }
    assert set(log.attributes) == _EVENT_ATTRIBUTES


def test_never_carries_tool_arguments_or_results(
    emitter: OtelUsageEventEmitter, exporter: InMemoryLogRecordExporter
) -> None:
    emitter.emit(_full_record())
    emitter.shutdown()

    (log,) = _logs(exporter)
    everything = [log.body, *log.attributes.values()]
    assert not any("SECRET-ARGUMENT" in str(v) for v in everything)
    assert "args_summary" not in log.attributes
    assert "request_id" not in log.attributes


def test_unset_optional_fields_are_omitted_not_null(
    emitter: OtelUsageEventEmitter, exporter: InMemoryLogRecordExporter
) -> None:
    emitter.emit(
        _full_record(
            trace_id=None,
            token_id=None,
            duration_ms=None,
            result_bytes=None,
            result_tokens_est=None,
        )
    )
    emitter.shutdown()

    (log,) = _logs(exporter)
    assert set(log.attributes) == {
        "audit_id",
        "principal_sub",
        "service",
        "method",
        "outcome",
    }


def test_records_without_a_service_are_not_emitted(
    emitter: OtelUsageEventEmitter, exporter: InMemoryLogRecordExporter
) -> None:
    emitter.emit(_full_record(mcp_service=None))
    emitter.shutdown()

    assert _logs(exporter) == []


def test_event_timestamp_is_the_call_time(
    emitter: OtelUsageEventEmitter, exporter: InMemoryLogRecordExporter
) -> None:
    emitter.emit(_full_record(timestamp=1_700_000_000.5))
    emitter.shutdown()

    (log,) = _logs(exporter)
    assert log.timestamp == 1_700_000_000_500_000_000


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


async def test_the_record_usage_path_emits_through_the_installed_store(
    exporter: InMemoryLogRecordExporter,
) -> None:
    emitter = OtelUsageEventEmitter(exporter)
    inner = InMemoryUsageStore()
    usage_module._store = EventEmittingUsageStore(inner, emitter)
    try:
        await record_usage(_full_record(audit_id="one"))
        await record_usage_batch([_full_record(audit_id="two")])
        # Denied calls are security events, not usage: filtered before the store.
        await record_usage(_full_record(audit_id="denied", outcome="denied"))
        emitter.shutdown()
    finally:
        usage_module._store = None

    assert sorted(log.attributes["audit_id"] for log in _logs(exporter)) == [
        "one",
        "two",
    ]


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


async def test_a_postgres_failure_still_propagates_and_events_still_go_out(
    emitter: OtelUsageEventEmitter, exporter: InMemoryLogRecordExporter
) -> None:
    """The wrapped store's failure must reach record_usage_batch (which counts
    and logs it); the opt-in event stream is independent of it."""

    class FailingStore(InMemoryUsageStore):
        async def record_many(self, records: list[AuditRecord]) -> None:
            raise RuntimeError("postgres down")

    store = EventEmittingUsageStore(FailingStore(), emitter)

    with pytest.raises(RuntimeError, match="postgres down"):
        await store.record_many([_full_record()])
    emitter.shutdown()

    assert len(_logs(exporter)) == 1


# --- real exporter on the wire ---------------------------------------------


def test_real_exporter_sends_the_exact_attribute_set_over_otlp(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with OtlpCollector() as collector:
        monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", collector.endpoint)
        emitter = OtelUsageEventEmitter()
        emitter.emit(_full_record())
        emitter.shutdown()  # final flush

    assert collector.paths == {"/v1/logs"}
    keys: set[str] = set()
    values: list[str] = []
    for req in collector.requests["/v1/logs"]:
        for rl in req.resource_logs:
            for sl in rl.scope_logs:
                for lr in sl.log_records:
                    assert lr.event_name == "af_mcp.usage"
                    keys |= {kv.key for kv in lr.attributes}
                    values += [str(kv.value) for kv in lr.attributes]
    assert keys == _EVENT_ATTRIBUTES
    assert not any("SECRET-ARGUMENT" in v for v in values)


def test_all_three_signals_share_the_one_endpoint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One OTEL_EXPORTER_OTLP_ENDPOINT carries traces, metrics and usage
    events, each on its own /v1/<signal> path."""
    monkeypatch.setattr(tracing.trace, "set_tracer_provider", lambda _p: None)
    with OtlpCollector() as collector:
        monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", collector.endpoint)
        settings = Settings(
            tracing_enabled=True,
            otel_metrics_enabled=True,
            usage_events_otlp_enabled=True,
            otel_exporter_otlp_endpoint=collector.endpoint,
        )
        tracing.init_tracing(settings)
        otel_metrics.init_otel_metrics(settings)
        emitter = OtelUsageEventEmitter()
        with tracing.get_tracer().start_as_current_span("probe"):
            pass
        record = _full_record()
        otel_metrics.record_tool_call(record)
        emitter.emit(record)
        emitter.shutdown()
        otel_metrics.shutdown_otel_metrics()
        tracing.shutdown_tracing()

    assert collector.paths == {"/v1/traces", "/v1/metrics", "/v1/logs"}
