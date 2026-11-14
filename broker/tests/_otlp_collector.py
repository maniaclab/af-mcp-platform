"""In-process OTLP/HTTP receiver for exporter tests.

A ``ThreadingHTTPServer`` on a random loopback port that parses each POST body
as the OTLP ``Export*ServiceRequest`` protobuf message for its signal path
(``/v1/traces``, ``/v1/metrics``, ``/v1/logs``) and records it. It stands in
for a collector at the wire boundary only: the broker side under test is the
real SDK exporter.
"""

from __future__ import annotations

import threading
from collections import defaultdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Self

from opentelemetry.proto.collector.logs.v1.logs_service_pb2 import (
    ExportLogsServiceRequest,
)
from opentelemetry.proto.collector.metrics.v1.metrics_service_pb2 import (
    ExportMetricsServiceRequest,
)
from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import (
    ExportTraceServiceRequest,
)

_REQUEST_TYPES: dict[str, type[Any]] = {
    "/v1/traces": ExportTraceServiceRequest,
    "/v1/metrics": ExportMetricsServiceRequest,
    "/v1/logs": ExportLogsServiceRequest,
}


class OtlpCollector:
    """Capture OTLP/HTTP exports: ``requests[path]`` is the parsed messages for that path."""

    def __init__(self) -> None:
        self.requests: dict[str, list[Any]] = defaultdict(list)
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                body = self.rfile.read(int(self.headers["Content-Length"]))
                request = _REQUEST_TYPES[self.path]()
                request.ParseFromString(body)
                outer.requests[self.path].append(request)
                self.send_response(200)
                self.send_header("Content-Type", "application/x-protobuf")
                self.end_headers()

            def log_message(self, *_args: Any) -> None:
                return

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.endpoint = f"http://127.0.0.1:{self._server.server_port}"
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    @property
    def paths(self) -> set[str]:
        """The signal paths that received at least one export."""
        return set(self.requests)

    def __enter__(self) -> Self:
        self._thread.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        self._server.shutdown()
        self._server.server_close()
