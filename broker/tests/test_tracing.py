from __future__ import annotations

import pytest
from fastapi import FastAPI
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
    InMemorySpanExporter,
)
from opentelemetry.util.http import parse_excluded_urls

from af_mcp_broker import tracing
from af_mcp_broker.config import Settings

# A fixed W3C traceparent for the inbound-propagation tests -- the trace/span
# ids below are the ones asserted against.
_TRACEPARENT = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
_TRACE_ID_HEX = "4bf92f3577b34da6a3ce929d0e0e4736"


@pytest.fixture
def local_exporter(monkeypatch: pytest.MonkeyPatch) -> InMemorySpanExporter:
    """Inject a test-local TracerProvider through the module seam.

    ``trace.set_tracer_provider`` is once-only per process, so tests never
    touch the OTel global -- ``tracing.get_tracer()`` reads the module-level
    ``_tracer_provider`` first precisely so this injection point exists.
    """
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    monkeypatch.setattr(tracing, "_tracer_provider", provider)
    return exporter


def test_default_settings_leave_tracing_off(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OTEL_EXPORTER_OTLP_ENDPOINT", raising=False)
    tracing.init_tracing(Settings())
    assert tracing._tracer_provider is None


def test_init_tracing_installs_sdk_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    installed: list[object] = []
    monkeypatch.setattr(tracing.trace, "set_tracer_provider", installed.append)
    settings = Settings(otel_exporter_otlp_endpoint="http://collector.invalid:4318")
    tracing.init_tracing(settings)
    try:
        provider = tracing._tracer_provider
        assert provider is not None
        assert installed == [provider]
        assert provider.resource.attributes["service.name"] == "af-mcp-broker"
        # The broker version rides along so a trace can be tied to a rollout.
        assert provider.resource.attributes["service.version"]
    finally:
        tracing.shutdown_tracing()
    assert tracing._tracer_provider is None


def test_init_tracing_is_idempotent(monkeypatch: pytest.MonkeyPatch) -> None:
    installed: list[object] = []
    monkeypatch.setattr(tracing.trace, "set_tracer_provider", installed.append)
    settings = Settings(otel_exporter_otlp_endpoint="http://collector.invalid:4318")
    tracing.init_tracing(settings)
    try:
        tracing.init_tracing(settings)
        # set_tracer_provider is once-only; a second init must not re-install.
        assert len(installed) == 1
    finally:
        tracing.shutdown_tracing()


def test_shutdown_without_init_is_a_noop() -> None:
    assert tracing._tracer_provider is None
    tracing.shutdown_tracing()
    assert tracing._tracer_provider is None


def test_current_trace_id_inside_recording_span(
    local_exporter: InMemorySpanExporter,
) -> None:
    tracer = tracing.get_tracer()
    assert tracing.current_trace_id() is None
    with tracer.start_as_current_span("test-span") as span:
        trace_id = tracing.current_trace_id()
        assert trace_id == format(span.get_span_context().trace_id, "032x")
        assert len(trace_id) == 32
        assert trace_id == trace_id.lower()
    assert tracing.current_trace_id() is None


def test_current_trace_id_none_when_tracing_disabled() -> None:
    # No module provider installed: get_tracer() falls back to the OTel
    # global, whose default no-op tracer yields a non-recording span.
    assert tracing._tracer_provider is None
    tracer = tracing.get_tracer()
    with tracer.start_as_current_span("noop-span"):
        assert tracing.current_trace_id() is None


def test_parent_context_from_meta_extracts_remote_parent() -> None:
    ctx = tracing.parent_context_from_meta({"traceparent": _TRACEPARENT})
    parent = trace.get_current_span(ctx).get_span_context()
    assert parent.is_valid
    assert parent.is_remote
    assert format(parent.trace_id, "032x") == _TRACE_ID_HEX


def test_parent_context_from_meta_without_meta() -> None:
    ctx = tracing.parent_context_from_meta(None)
    assert not trace.get_current_span(ctx).get_span_context().is_valid


def test_instrument_fastapi_only_when_enabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("OTEL_EXPORTER_OTLP_ENDPOINT", raising=False)
    disabled_app = FastAPI()
    tracing.instrument_fastapi(disabled_app, Settings())
    assert not getattr(disabled_app, "_is_instrumented_by_opentelemetry", False)

    enabled_app = FastAPI()
    tracing.instrument_fastapi(
        enabled_app, Settings(otel_exporter_otlp_endpoint="http://collector:4318")
    )
    assert getattr(enabled_app, "_is_instrumented_by_opentelemetry", False)


def test_excluded_urls_cover_probes_and_mcp() -> None:
    """Health probes are noise; /mcp must stay out of HTTP instrumentation so
    fastmcp's SEP-414 `_meta` traceparent extraction (which defers to an
    already-valid ambient trace context) still sees the client's trace as the
    remote parent instead of a broker-local HTTP span."""
    excluded = parse_excluded_urls(tracing._EXCLUDED_URLS)
    assert excluded.url_disabled("http://broker:8080/healthz")
    assert excluded.url_disabled("http://broker:8080/readyz")
    assert excluded.url_disabled("http://broker:8080/mcp")
    assert excluded.url_disabled("http://broker:8080/mcp/")
    assert not excluded.url_disabled("http://broker:8080/v1/usage")
