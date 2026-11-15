"""Request id, JSON logs, access log and optional OpenTelemetry spans (L1 to L4)."""

from __future__ import annotations

import json
import logging
import os
import sys
import time
import uuid
from contextvars import ContextVar
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, TextIO

from fastmcp.server.dependencies import get_access_token
from fastmcp.server.middleware import Middleware
from opentelemetry import propagate, trace
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from starlette.datastructures import Headers

if TYPE_CHECKING:
    from fastmcp.server.middleware import CallNext, MiddlewareContext
    from fastmcp.tools import ToolResult
    from mcp.types import CallToolRequestParams
    from starlette.types import ASGIApp, Message, Receive, Scope, Send

HEALTH_PATH = "/healthz"
MAX_REQUEST_ID_CHARS = 128

log = logging.getLogger("shelf_mcp")
tracer = trace.get_tracer("shelf_mcp")
# The broker's X-Request-ID for the request being served (L1). A ContextVar so
# tool code and library log calls carry it without passing it around.
request_id_var: ContextVar[str | None] = ContextVar("request_id", default=None)


class JsonFormatter(logging.Formatter):
    """One JSON object per line with the standard fields (L2).

    Call-specific fields travel as ``extra={"fields": {...}}``.
    """

    def format(self, record: logging.LogRecord) -> str:
        """Render the record as a single JSON line."""
        entry: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, UTC).isoformat(
                timespec="milliseconds"
            ),
            "level": record.levelname.lower(),
            "logger": record.name,
            "event": record.getMessage(),
        }
        if request_id := request_id_var.get():
            entry["request_id"] = request_id
        entry.update(getattr(record, "fields", {}))
        if record.exc_info:
            entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(entry, default=str)


def configure_logging(stream: TextIO | None = None) -> None:
    """Send every log line, the server's and uvicorn's, to stdout as JSON."""
    handler = logging.StreamHandler(stream or sys.stdout)
    handler.setFormatter(JsonFormatter())
    logging.basicConfig(level=logging.INFO, handlers=[handler], force=True)


def configure_tracing() -> None:
    """Export spans over OTLP only when the standard OTEL_* variables ask for it (L4).

    The endpoint, headers and service name come from ``OTEL_EXPORTER_OTLP_*``
    and ``OTEL_SERVICE_NAME``; with none set the tracer stays a no-op.
    """
    if not (
        os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT")
        or os.environ.get("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
    ):
        return
    provider = TracerProvider()
    provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
    trace.set_tracer_provider(provider)


class RequestLogMiddleware:
    """Bind ``X-Request-ID`` for the request and write its access line (L1, L3).

    The broker's id is authoritative; one is generated only when the header is
    absent, so every line still carries an id. A health probe that succeeds
    writes no access line; a failing one does.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Serve one request inside its request-id context."""
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        header = Headers(scope=scope).get("x-request-id", "")
        reset = request_id_var.set(header[:MAX_REQUEST_ID_CHARS] or uuid.uuid4().hex)
        status = 500
        started = time.perf_counter()

        async def send_and_note_status(message: Message) -> None:
            nonlocal status
            if message["type"] == "http.response.start":
                status = message["status"]
            await send(message)

        try:
            await self.app(scope, receive, send_and_note_status)
        finally:
            if scope["path"] != HEALTH_PATH or status >= 400:
                log.info(
                    "http.request",
                    extra={
                        "fields": {
                            "method": scope["method"],
                            "path": scope["path"],
                            "status": status,
                            "duration_ms": round(
                                (time.perf_counter() - started) * 1000, 1
                            ),
                        }
                    },
                )
            request_id_var.reset(reset)


class ToolCallMiddleware(Middleware):
    """One ``tool.call`` log line and one span per tool call (L2, L4)."""

    async def on_call_tool(
        self,
        context: MiddlewareContext[CallToolRequestParams],
        call_next: CallNext[CallToolRequestParams, ToolResult],
    ) -> ToolResult:
        """Time the call, log its outcome, and continue the caller's trace."""
        name = context.message.name
        meta = context.message.meta
        # A W3C traceparent rides in the request's _meta, not an HTTP header.
        parent = propagate.extract(dict(meta) if meta else {})
        token = get_access_token()
        subject = token.claims.get("sub") if token else None
        outcome = "error"
        started = time.perf_counter()
        try:
            with tracer.start_as_current_span(f"tools/call {name}", context=parent):
                result = await call_next(context)
            outcome = "success"
        finally:
            log.info(
                "tool.call",
                extra={
                    "fields": {
                        "subject": subject,
                        "tool": name,
                        "duration_ms": round((time.perf_counter() - started) * 1000, 1),
                        "outcome": outcome,
                    }
                },
            )
        return result
