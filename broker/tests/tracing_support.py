"""Fixtures and constants shared by the tests of ``test_tracing``."""

from __future__ import annotations

import pytest
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
    InMemorySpanExporter,
)

from af_mcp_broker import tracing

# A fixed W3C traceparent for the inbound-propagation tests -- the trace/span
# ids below are the ones asserted against.
_TRACEPARENT = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"


_TRACE_ID_HEX = "4bf92f3577b34da6a3ce929d0e0e4736"


@pytest.fixture(name="local_exporter")
def local_exporter_fixture(monkeypatch: pytest.MonkeyPatch) -> InMemorySpanExporter:
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
