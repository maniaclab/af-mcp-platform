"""Tests for ``otel_metrics.py`` -- opt-in OTLP aggregate metrics.

Two seams, both at the exporter boundary only:

* ``InMemoryMetricReader`` injected through ``init_otel_metrics(reader=...)``
  for what the broker records (values and the exact attribute set).
* A real ``OTLPMetricExporter`` pointed at an in-process OTLP/HTTP receiver
  (a ``ThreadingHTTPServer`` on a random loopback port) for what goes on the
  wire, and at an unreachable port for the "a dead collector is harmless"
  contract.
"""

from __future__ import annotations

import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import TYPE_CHECKING, Any

import pytest
from opentelemetry.proto.collector.metrics.v1.metrics_service_pb2 import (
    ExportMetricsServiceRequest,
)
from opentelemetry.sdk.metrics.export import InMemoryMetricReader
from test_usage_postgres import _record

from af_mcp_broker import otel_metrics
from af_mcp_broker.audit import pipeline
from af_mcp_broker.config import Settings

if TYPE_CHECKING:
    from collections.abc import Iterator
    from typing import Self

# Attribute names a metric must never carry (see metrics.py's cardinality
# policy): identity, credential, or per-request identifiers.
_FORBIDDEN_ATTRIBUTES = {
    "principal_sub",
    "sub",
    "user",
    "username",
    "unixname",
    "token_id",
    "jti",
    "request_id",
    "audit_id",
    "trace_id",
    "args_summary",
}
_ALLOWED_ATTRIBUTES = {"service", "method", "action_type", "outcome"}


@pytest.fixture(autouse=True)
def _reset_module_state() -> Iterator[None]:
    otel_metrics.shutdown_otel_metrics()
    yield
    otel_metrics.shutdown_otel_metrics()


@pytest.fixture
def reader() -> InMemoryMetricReader:
    r = InMemoryMetricReader()
    otel_metrics.init_otel_metrics(Settings(otel_metrics_enabled=True), reader=r)
    return r


def _metrics(reader: InMemoryMetricReader) -> dict[str, Any]:
    data = reader.get_metrics_data()
    assert data is not None
    return {
        m.name: m
        for rm in data.resource_metrics
        for sm in rm.scope_metrics
        for m in sm.metrics
    }


def _points(reader: InMemoryMetricReader, name: str) -> list[Any]:
    return list(_metrics(reader)[name].data.data_points)


def test_disabled_by_default_installs_nothing() -> None:
    assert Settings().otel_metrics_enabled is False
    otel_metrics.init_otel_metrics(Settings())

    assert otel_metrics._provider is None
    otel_metrics.record_tool_call(_record())  # must be a harmless no-op


def test_enabled_setting_reads_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OTEL_METRICS_ENABLED", "true")
    assert Settings().otel_metrics_enabled is True


def test_records_calls_errors_duration_bytes_and_tokens(
    reader: InMemoryMetricReader,
) -> None:
    otel_metrics.record_tool_call(_record(duration_ms=250.0))
    otel_metrics.record_tool_call(_record(duration_ms=750.0, audit_id="b"))
    otel_metrics.record_tool_call(
        _record(
            outcome="error",
            duration_ms=100.0,
            result_bytes=None,
            result_tokens_est=None,
            audit_id="c",
        )
    )

    by_outcome = {
        p.attributes["outcome"]: p for p in _points(reader, "af_mcp.tool.calls")
    }
    assert by_outcome["success"].value == 2
    assert by_outcome["error"].value == 1
    (errors,) = _points(reader, "af_mcp.tool.errors")
    assert errors.value == 1
    assert errors.attributes["outcome"] == "error"

    durations = {
        p.attributes["outcome"]: p for p in _points(reader, "af_mcp.tool.duration")
    }
    assert durations["success"].count == 2
    assert durations["success"].sum == pytest.approx(1.0)  # seconds
    assert durations["error"].sum == pytest.approx(0.1)

    # An unmeasured call (None) adds nothing to the size counters.
    (result_bytes,) = _points(reader, "af_mcp.tool.result_bytes")
    assert result_bytes.value == 200
    (tokens,) = _points(reader, "af_mcp.tool.result_tokens_est")
    assert tokens.value == 50


def test_attribute_set_is_exactly_service_method_action_type_outcome(
    reader: InMemoryMetricReader,
) -> None:
    """The cardinality policy (metrics.py): no user, token, jti or request-id
    attribute, whatever the record carries. This fails if any metric gains
    one, by name or by leaking an identity value into an attribute value."""
    record = _record(
        principal_sub="alice-sub-secret",
        token_id="tok-secret-lookup",
        request_id="req-secret",
        trace_id="f" * 32,
        audit_id="audit-secret",
    )
    otel_metrics.record_tool_call(record)

    metrics = _metrics(reader)
    assert set(metrics) == {
        "af_mcp.tool.calls",
        "af_mcp.tool.duration",
        "af_mcp.tool.result_bytes",
        "af_mcp.tool.result_tokens_est",
    }
    leaked_values = {
        "alice-sub-secret",
        "tok-secret-lookup",
        "req-secret",
        "f" * 32,
        "audit-secret",
    }
    for metric in metrics.values():
        for point in metric.data.data_points:
            assert set(point.attributes) == _ALLOWED_ATTRIBUTES
            assert not set(point.attributes) & _FORBIDDEN_ATTRIBUTES
            assert not leaked_values & set(point.attributes.values())
    (point,) = _points(reader, "af_mcp.tool.calls")
    assert dict(point.attributes) == {
        "service": "rucio",
        "method": "rucio_list_dids",
        "action_type": "read",
        "outcome": "success",
    }


def test_error_counter_attributes_obey_the_same_policy(
    reader: InMemoryMetricReader,
) -> None:
    otel_metrics.record_tool_call(_record(outcome="error", principal_sub="alice"))

    (point,) = _points(reader, "af_mcp.tool.errors")
    assert set(point.attributes) == _ALLOWED_ATTRIBUTES


def test_the_declared_attribute_names_cannot_include_identity() -> None:
    assert set(otel_metrics.METRIC_ATTRIBUTES) == _ALLOWED_ATTRIBUTES
    assert not set(otel_metrics.METRIC_ATTRIBUTES) & _FORBIDDEN_ATTRIBUTES


@pytest.mark.parametrize(
    "overrides",
    [
        {"outcome": "denied"},
        {"outcome": "unmapped"},
        {"mcp_service": None, "outcome": "success"},
    ],
    ids=["denied", "unmapped", "no-service"],
)
def test_non_usage_records_are_not_counted(
    reader: InMemoryMetricReader, overrides: dict[str, Any]
) -> None:
    """Same filter as usage accounting: an unmapped tool name is
    client-supplied and unbounded, so it must never become an attribute."""
    otel_metrics.record_tool_call(_record(**overrides))

    data = reader.get_metrics_data()
    assert (
        data is None
        or not data.resource_metrics
        or not any(
            sm.metrics for rm in data.resource_metrics for sm in rm.scope_metrics
        )
    )


def test_a_failing_instrument_never_raises_into_the_caller(
    reader: InMemoryMetricReader, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(*_a: Any, **_k: Any) -> None:
        raise RuntimeError("instrument down")

    assert otel_metrics._instruments is not None
    monkeypatch.setattr(otel_metrics._instruments.calls, "add", boom)

    otel_metrics.record_tool_call(_record())  # must not raise


# --- metering pipeline wiring ----------------------------------------------


async def test_inline_fallback_path_records_metrics(
    reader: InMemoryMetricReader,
) -> None:
    """With no pipeline installed, submit_metered_audit measures and writes
    inline; that path must feed the metrics too."""
    await pipeline.submit_metered_audit(_record(), None)

    (point,) = _points(reader, "af_mcp.tool.calls")
    assert point.value == 1


async def test_metering_worker_records_metrics_with_measured_sizes(
    reader: InMemoryMetricReader,
) -> None:
    backend = pipeline.InProcessMeteringBackend(settings=Settings())
    await backend.start()
    try:
        await backend.submit(_record(result_bytes=None, result_tokens_est=None), None)
    finally:
        await backend.aclose()

    (point,) = _points(reader, "af_mcp.tool.calls")
    assert point.value == 1


async def test_queue_overflow_path_records_metrics(
    reader: InMemoryMetricReader,
) -> None:
    backend = pipeline.InProcessMeteringBackend(settings=Settings(), maxsize=1)
    # Not started: the first submit fills the queue, the second overflows
    # and is written inline.
    await backend.submit(_record(audit_id="queued"), None)
    await backend.submit(_record(audit_id="overflow"), None)

    (point,) = _points(reader, "af_mcp.tool.calls")
    assert point.value == 1


# --- real exporter, in-process OTLP receiver -------------------------------


class _Collector:
    """In-process OTLP/HTTP receiver capturing exported metric requests."""

    def __init__(self) -> None:
        self.requests: list[ExportMetricsServiceRequest] = []
        self.paths: list[str] = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                body = self.rfile.read(int(self.headers["Content-Length"]))
                req = ExportMetricsServiceRequest()
                req.ParseFromString(body)
                outer.requests.append(req)
                outer.paths.append(self.path)
                self.send_response(200)
                self.send_header("Content-Type", "application/x-protobuf")
                self.end_headers()

            def log_message(self, *_args: Any) -> None:
                return

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.endpoint = f"http://127.0.0.1:{self._server.server_port}"
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def __enter__(self) -> Self:
        self._thread.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        self._server.shutdown()
        self._server.server_close()


def test_real_exporter_sends_only_the_allowed_attributes_over_otlp(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with _Collector() as collector:
        monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", collector.endpoint)
        otel_metrics.init_otel_metrics(Settings(otel_metrics_enabled=True))
        otel_metrics.record_tool_call(
            _record(principal_sub="alice-sub-secret", token_id="tok-secret")
        )
        otel_metrics.shutdown_otel_metrics()  # final flush

    assert collector.paths
    assert set(collector.paths) == {"/v1/metrics"}
    wire_attributes: set[str] = set()
    wire_values: set[str] = set()
    names: set[str] = set()
    for req in collector.requests:
        for rm in req.resource_metrics:
            for sm in rm.scope_metrics:
                for metric in sm.metrics:
                    names.add(metric.name)
                    kind = metric.WhichOneof("data")
                    for dp in getattr(metric, kind).data_points:
                        for kv in dp.attributes:
                            wire_attributes.add(kv.key)
                            wire_values.add(kv.value.string_value)
    assert "af_mcp.tool.calls" in names
    assert wire_attributes == _ALLOWED_ATTRIBUTES
    assert not {"alice-sub-secret", "tok-secret"} & wire_values


def test_an_unreachable_collector_never_breaks_recording_or_shutdown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Port 1 on loopback refuses connections; the short timeout bounds the
    # exporter's own retry loop so the test stays fast.
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:1")
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_TIMEOUT", "1")
    otel_metrics.init_otel_metrics(Settings(otel_metrics_enabled=True))

    started = time.monotonic()
    for i in range(100):
        otel_metrics.record_tool_call(_record(audit_id=f"id-{i}"))
    recording_seconds = time.monotonic() - started

    otel_metrics.shutdown_otel_metrics()  # must not raise
    assert recording_seconds < 0.5


def test_init_is_idempotent(reader: InMemoryMetricReader) -> None:
    first = otel_metrics._provider
    otel_metrics.init_otel_metrics(Settings(otel_metrics_enabled=True))
    assert otel_metrics._provider is first
