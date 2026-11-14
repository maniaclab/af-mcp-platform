"""Opt-in OpenTelemetry aggregate metrics (OTLP emission only).

The broker is an EMITTER only -- no metrics backend is shipped or assumed.
With ``OTEL_METRICS_ENABLED`` true, :func:`init_otel_metrics` installs an SDK
``MeterProvider`` whose ``PeriodicExportingMetricReader`` exports OTLP/HTTP
metrics to the collector named by the standard ``OTEL_EXPORTER_OTLP_*``
variables (the same ones tracing uses). With it unset (the default) nothing
is installed and :func:`record_tool_call` returns at once: zero behaviour
change. Prometheus on ``METRICS_PORT`` (``metrics.py``) is independent and
unchanged. Export failures are the reader's background problem, never the
broker's: an unreachable collector must not fail startup or a tool call.

Only aggregates leave here, labelled by :data:`METRIC_ATTRIBUTES` and nothing
else. The cardinality policy in ``metrics.py`` applies unchanged: no user,
token, jti, request-id or argument attribute, because the per-call record
with identity lives in the audit log (and, opt-in, in OTel log events -- a
different signal with no cardinality cost).

Where a call is recorded: the metering worker (``audit/pipeline.py``) calls
:func:`record_tool_call` after each audit write, because ``result_bytes`` and
``result_tokens_est`` only exist once the worker has measured the result.
That makes the instruments below usage-shaped: success and error tool calls
only. Denied and unmapped calls never reach the worker (an unmapped tool name
is client-supplied and unbounded, so it must never be an attribute).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

import structlog
from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.sdk.resources import Resource

from af_mcp_broker._version import version as __version__
from af_mcp_broker.usage import counts_as_usage

if TYPE_CHECKING:
    from opentelemetry.metrics import Counter, Histogram
    from opentelemetry.sdk.metrics.export import MetricReader

    from af_mcp_broker.audit.logger import AuditRecord
    from af_mcp_broker.config import Settings

logger = structlog.get_logger(__name__)

# The ONLY attribute names any instrument here may carry. ``service`` and
# ``action_type`` come from the operator's services.yaml / policy.yaml;
# ``method`` is a registered service's own fixed tool name; ``outcome`` is
# success or error. See the cardinality policy in metrics.py.
METRIC_ATTRIBUTES = ("service", "method", "action_type", "outcome")

# Same bucket layout as the Prometheus tool-duration histogram (metrics.py),
# in seconds: tool calls can include credential minting via ephemeral k8s
# Jobs (tens of seconds to minutes), not just fast HTTP proxying.
_DURATION_BUCKETS = (
    0.05,
    0.1,
    0.25,
    0.5,
    1.0,
    2.5,
    5.0,
    10.0,
    30.0,
    60.0,
    120.0,
    300.0,
)


@dataclass(frozen=True)
class _Instruments:
    calls: Counter
    errors: Counter
    duration: Histogram
    result_bytes: Counter
    result_tokens_est: Counter


_provider: MeterProvider | None = None
_instruments: _Instruments | None = None


def init_otel_metrics(settings: Settings, reader: MetricReader | None = None) -> None:
    """Install the SDK meter provider when ``OTEL_METRICS_ENABLED`` is set.

    Idempotent: a second call while a provider is installed does nothing.
    *reader* replaces the OTLP exporter reader; it is the test seam at the
    exporter boundary (an in-memory reader), never set in production.

    ``OTLPMetricExporter()`` is constructed argument-free on purpose: the SDK
    reads the standard ``OTEL_EXPORTER_OTLP_*`` variables natively, including
    appending ``/v1/metrics`` to ``OTEL_EXPORTER_OTLP_ENDPOINT``, so endpoint,
    headers, timeout and TLS settings are shared with tracing.
    """
    global _provider, _instruments
    if not settings.otel_metrics_enabled:
        return
    if _provider is not None:
        return
    if reader is None:
        reader = PeriodicExportingMetricReader(OTLPMetricExporter())
    provider = MeterProvider(
        resource=Resource.create(
            {"service.name": "af-mcp-broker", "service.version": __version__}
        ),
        metric_readers=[reader],
    )
    meter = provider.get_meter("af_mcp_broker", __version__)
    _instruments = _Instruments(
        calls=meter.create_counter(
            "af_mcp.tool.calls",
            unit="{call}",
            description="Tool calls that reached a backend, by service, method, "
            "action_type and outcome (success or error).",
        ),
        errors=meter.create_counter(
            "af_mcp.tool.errors",
            unit="{call}",
            description="Tool calls that ended in error, by service, method, "
            "action_type and outcome.",
        ),
        duration=meter.create_histogram(
            "af_mcp.tool.duration",
            unit="s",
            description="Wall time of the downstream tool call (credential "
            "resolution plus the backend call).",
            explicit_bucket_boundaries_advisory=_DURATION_BUCKETS,
        ),
        result_bytes=meter.create_counter(
            "af_mcp.tool.result_bytes",
            unit="By",
            description="Serialized size of tool results injected into the LLM "
            "client's context (an estimate, not wire size).",
        ),
        result_tokens_est=meter.create_counter(
            "af_mcp.tool.result_tokens_est",
            unit="{token}",
            description="Estimated tokens of tool results (tiktoken estimate).",
        ),
    )
    _provider = provider
    logger.info("otel_metrics_initialized")


def shutdown_otel_metrics() -> None:
    """Flush and shut down the installed provider, if any.

    Called from the lifespan teardown after the metering drain, so the last
    records' measurements are exported on a graceful stop. Never raises: a
    collector that is down only costs the final flush.
    """
    global _provider, _instruments
    if _provider is None:
        return
    provider, _provider, _instruments = _provider, None, None
    try:
        provider.shutdown()
    except Exception as exc:  # noqa: BLE001 -- an exporter problem is not the broker's
        logger.warning("otel_metrics_shutdown_failed", error=str(exc))


def record_tool_call(record: AuditRecord) -> None:
    """Record *record* on the aggregate instruments, if enabled and usage-shaped.

    Never raises: metrics are best-effort, and the audit write the caller
    performed first is authoritative.
    """
    instruments = _instruments
    service = record.mcp_service
    # counts_as_usage already implies a service; the None check narrows the
    # type for the attribute dict.
    if instruments is None or service is None or not counts_as_usage(record):
        return
    attributes = {
        "service": service,
        "method": record.action,
        "action_type": record.action_type,
        "outcome": record.outcome,
    }
    try:
        instruments.calls.add(1, attributes)
        if record.outcome == "error":
            instruments.errors.add(1, attributes)
        if record.duration_ms is not None:
            instruments.duration.record(record.duration_ms / 1000, attributes)
        if record.result_bytes is not None:
            instruments.result_bytes.add(record.result_bytes, attributes)
        if record.result_tokens_est is not None:
            instruments.result_tokens_est.add(record.result_tokens_est, attributes)
    except Exception as exc:  # noqa: BLE001 -- metrics must never affect a call
        logger.warning("otel_metrics_record_failed", error=str(exc))
