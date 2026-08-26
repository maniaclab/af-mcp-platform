"""Env-gated OpenTelemetry trace emission (observability roadmap PR D).

The broker is an EMITTER only -- no trace backend is shipped or assumed.
When ``OTEL_EXPORTER_OTLP_ENDPOINT`` is set, :func:`init_tracing` installs an
SDK ``TracerProvider`` exporting OTLP/HTTP spans toward that collector; when
it is empty (the default), no provider is installed and every OTel API call
in the process -- the broker's own spans in
``mcp/middleware/authorization_mw.py`` and fastmcp's native spans alike --
no-ops against the API's default provider. Export failures are the batch
exporter's background problem, never the broker's: a misconfigured or
unreachable collector must not fail startup or a tool call.

Division of labor (the trace <-> audit join): spans carry identity, outcome,
and timing; measurements (result bytes / token estimates) stay in the audit
log, whose records are written by a background worker AFTER the response
returns (audit/pipeline.py) and therefore can never be span attributes. The
two are joined on ``AuditRecord.trace_id`` (:func:`current_trace_id`).

Testability: ``trace.set_tracer_provider`` is once-only per process, so tests
never install a real global. :func:`get_tracer` reads the module-level
``_tracer_provider`` first, giving tests an injection seam
(``monkeypatch.setattr(tracing, "_tracer_provider", ...)``) for a test-local
provider wired to an ``InMemorySpanExporter``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import structlog
from fastmcp.telemetry import extract_trace_context
from opentelemetry import trace

# The OTLP exporter package nests the class under an unwieldy path; the
# import is at top per house style (no inline imports), which costs a few ms
# at process import even when tracing is off -- acceptable, unlike paying
# anything per request.
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

from af_mcp_broker._version import version as __version__

if TYPE_CHECKING:
    from fastapi import FastAPI
    from opentelemetry.context import Context

    from af_mcp_broker.config import Settings

logger = structlog.get_logger(__name__)

# The provider init_tracing() installed, if any. Held here (in addition to
# being set as the OTel global) for two reasons: shutdown_tracing() needs the
# concrete SDK handle to flush, and get_tracer() reads this first so tests
# can inject a test-local provider without touching the once-only global --
# see the module docstring.
_tracer_provider: TracerProvider | None = None

# URLs excluded from /v1 HTTP instrumentation (comma-separated regexes, see
# opentelemetry.util.http.parse_excluded_urls). healthz/readyz are probe
# noise with no user identity. /mcp is excluded deliberately even though the
# mount sits inside this app's ASGI middleware stack: fastmcp's SEP-414
# ``_meta`` traceparent extraction (fastmcp.telemetry.extract_trace_context)
# defers to an already-valid ambient trace context, so an HTTP-level span
# around the /mcp POST would shadow the client's own trace and break the
# "a client's _meta traceparent joins the broker's spans" contract --
# tool-call spans for /mcp come from authorization_mw.py instead.
_EXCLUDED_URLS = "healthz,readyz,/mcp"


def init_tracing(settings: Settings) -> None:
    """Install the SDK tracer provider when an OTLP endpoint is configured.

    With ``settings.otel_exporter_otlp_endpoint`` empty this returns without
    touching the global tracer provider -- fastmcp's and the broker's OTel
    calls then no-op against the API's default provider (zero overhead when
    off). Idempotent: a second call while a provider is installed does
    nothing, since ``trace.set_tracer_provider`` is once-only.

    Call this before the FastMCP aggregator/app objects are constructed
    (app.py does, at module scope). Verified against the pinned fastmcp
    3.4.4: it acquires its tracer lazily per span (``get_tracer()`` inside
    each ``server_span``/``client_span``), never at import or construction,
    so this early placement is conservative rather than load-bearing -- but
    it keeps us safe against a future fastmcp caching the tracer earlier.
    """
    global _tracer_provider
    if not settings.otel_exporter_otlp_endpoint:
        return
    if _tracer_provider is not None:
        return
    resource = Resource.create(
        {"service.name": "af-mcp-broker", "service.version": __version__}
    )
    provider = TracerProvider(resource=resource)
    # OTLPSpanExporter() is constructed argument-free on purpose: the SDK
    # reads the standard OTEL_EXPORTER_OTLP_* env vars natively (including
    # appending the /v1/traces signal path to OTEL_EXPORTER_OTLP_ENDPOINT);
    # passing endpoint= explicitly would bypass that path handling. The
    # same goes for sampling: OTEL_TRACES_SAMPLER / OTEL_TRACES_SAMPLER_ARG
    # are read natively by the SDK (default parentbased_always_on, fine at
    # tool-call volumes), so the broker adds no sampler plumbing of its own.
    provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
    trace.set_tracer_provider(provider)
    _tracer_provider = provider
    logger.info("tracing_initialized", endpoint=settings.otel_exporter_otlp_endpoint)


def shutdown_tracing() -> None:
    """Flush and shut down the installed provider, if any.

    Called from the lifespan teardown so spans buffered in the batch
    processor are exported on a graceful stop. The OTel global keeps pointing
    at the (now shut down) provider -- it cannot be unset -- which is fine
    for the production single-lifespan case this exists for; tests never
    install the global at all (see the module docstring).
    """
    global _tracer_provider
    if _tracer_provider is None:
        return
    _tracer_provider.shutdown()
    _tracer_provider = None


def get_tracer() -> trace.Tracer:
    """Tracer for the broker's own spans (authorization_mw.py).

    Prefers the module-installed provider (production via init_tracing, or a
    test-local injection); falls back to the OTel global, which is the API's
    no-op default unless something else installed one.
    """
    if _tracer_provider is not None:
        return _tracer_provider.get_tracer("af_mcp_broker", __version__)
    return trace.get_tracer("af_mcp_broker", __version__)


def current_trace_id() -> str | None:
    """32-hex-lowercase trace id of the current recording span, or None.

    The trace <-> audit <-> usage join key: authorization_mw.py stamps this
    into every AuditRecord it builds. Cheap enough for the request path
    (a context-var read plus an int format), and correct even though the
    audit write itself happens later on the metering worker -- the id is
    captured while the span is still current. None whenever there is no
    recording span (tracing disabled, or a sampler dropped this trace).
    """
    span = trace.get_current_span()
    span_context = span.get_span_context()
    if not (span.is_recording() and span_context.is_valid):
        return None
    return format(span_context.trace_id, "032x")


def parent_context_from_meta(meta: Any) -> Context:
    """OTel context carrying the inbound MCP ``_meta`` traceparent, if any.

    *meta* is the request's ``_meta`` -- either a plain mapping or the MCP
    SDK's pydantic ``RequestParams.Meta`` model (both convert via ``dict()``,
    mirroring how fastmcp's own server-side extraction handles it).

    SEP-414: an MCP client tracing its own agent sends ``traceparent`` /
    ``tracestate`` inside the request's ``_meta``; parsing it here makes the
    broker's tool-call span a child of the client's span (remote parent).
    Delegates to fastmcp's own extractor, which also refuses to override an
    already-valid ambient trace context and falls back to the current
    context when nothing is carried. The inbound value is only ever parsed
    -- never forwarded verbatim; see authorization_mw.py's propagation
    invariant.
    """
    if meta is None:
        return extract_trace_context(None)
    return extract_trace_context(dict(meta))


def instrument_fastapi(app: FastAPI, settings: Settings) -> None:
    """Instrument the /v1 FastAPI surface, only when tracing is enabled.

    Gated on the same setting as init_tracing so a disabled deployment gets
    no extra ASGI middleware at all. See _EXCLUDED_URLS for what is excluded
    and why /mcp is on that list.
    """
    if not settings.otel_exporter_otlp_endpoint:
        return
    FastAPIInstrumentor.instrument_app(app, excluded_urls=_EXCLUDED_URLS)
