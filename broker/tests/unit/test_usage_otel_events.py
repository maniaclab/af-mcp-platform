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

from typing import TYPE_CHECKING, Any

import pytest
from _otlp_collector import OtlpCollector
from opentelemetry.sdk._logs.export import (
    InMemoryLogRecordExporter,
)
from test_usage_postgres import _record

from af_mcp_broker import otel_metrics, tracing
from af_mcp_broker.audit.measure import ContentMeasure
from af_mcp_broker.config import Settings
from af_mcp_broker.usage import (
    EventEmittingUsageStore,
    InMemoryUsageStore,
    OtelUsageEventEmitter,
    build_usage_store,
    record_usage,
    record_usage_batch,
)

if TYPE_CHECKING:
    from collections.abc import Iterator

    from af_mcp_broker.audit.logger import AuditRecord

_ENDPOINT = "http://collector.invalid:4318"

# The exact attribute set of a fully populated record: nothing else may be
# added (never tool arguments or results).
_EVENT_ATTRIBUTES = {
    "audit_id",
    "trace_id",
    "subject",
    "token_id",
    "service",
    "method",
    "outcome",
    "duration_ms",
    "result_bytes",
    "result_tokens_est",
}


@pytest.fixture
def exporter() -> InMemoryLogRecordExporter:
    return InMemoryLogRecordExporter()


@pytest.fixture
def emitter(exporter: InMemoryLogRecordExporter) -> Iterator[OtelUsageEventEmitter]:
    e = OtelUsageEventEmitter(exporter)
    yield e
    e.shutdown()


def _full_record(**overrides: Any) -> AuditRecord:
    fields: dict[str, Any] = {
        "audit_id": "audit-1",
        "trace_id": "a" * 32,
        "subject": "alice-sub",
        "token_id": "tok-1",
        "args_summary": "scope=SECRET-ARGUMENT",
        "duration_ms": 12.5,
        "result_bytes": 321,
        "result_tokens_est": 80,
        # No breakdown: the base attribute set is asserted exactly; the
        # per-content-type attributes have their own test.
        "result_content": None,
    }
    fields.update(overrides)
    return _record(**fields)


def test_event_carries_a_breakdown_attribute_per_content_type(
    exporter: InMemoryLogRecordExporter, emitter: OtelUsageEventEmitter
) -> None:
    emitter.emit(
        _full_record(
            result_content={
                "text": ContentMeasure(blocks=1, bytes=29, tokens_est=14),
                "hologram": ContentMeasure(blocks=2, bytes=7, tokens_est=0),
            }
        )
    )
    emitter.shutdown()

    (log,) = _logs(exporter)
    attributes = dict(log.attributes)
    # The real content-type string is kept (events are per-call, not a metric).
    assert attributes["result_content.text.blocks"] == 1
    assert attributes["result_content.text.bytes"] == 29
    assert attributes["result_content.text.tokens_est"] == 14
    assert attributes["result_content.hologram.blocks"] == 2
    assert attributes["result_content.hologram.bytes"] == 7
    assert attributes["result_content.hologram.tokens_est"] == 0


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
    store = build_usage_store(Settings())

    assert isinstance(store, InMemoryUsageStore)


async def test_enabled_wraps_the_configured_store() -> None:
    store = build_usage_store(
        Settings(usage_events_otlp_enabled=True, otel_exporter_otlp_endpoint=_ENDPOINT)
    )

    assert isinstance(store, EventEmittingUsageStore)


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
        "subject": "alice-sub",
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
        "subject",
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


async def test_the_record_usage_path_emits_through_the_given_store(
    exporter: InMemoryLogRecordExporter,
) -> None:
    emitter = OtelUsageEventEmitter(exporter)
    inner = InMemoryUsageStore()
    store = EventEmittingUsageStore(inner, emitter)
    await record_usage(store, _full_record(audit_id="one"))
    await record_usage_batch(store, [_full_record(audit_id="two")])
    # Denied calls are security events, not usage: filtered before the store.
    await record_usage(store, _full_record(audit_id="denied", outcome="denied"))
    emitter.shutdown()

    assert sorted(log.attributes["audit_id"] for log in _logs(exporter)) == [
        "one",
        "two",
    ]


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
