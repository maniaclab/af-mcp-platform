"""In-process OTLP/HTTP receiver for exporter tests.

A ``ThreadingHTTPServer`` on a random loopback port that parses each POST body
as the given OTLP ``Export*ServiceRequest`` protobuf message class and records
it with its request path. It stands in for a collector at the wire boundary
only: the broker side under test is the real SDK exporter.
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Self


class OtlpCollector:
    """Capture OTLP/HTTP exports of one signal (*request_type* is its request message)."""

    def __init__(self, request_type: type[Any]) -> None:
        self.requests: list[Any] = []
        self.paths: list[str] = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                body = self.rfile.read(int(self.headers["Content-Length"]))
                request = request_type()
                request.ParseFromString(body)
                outer.requests.append(request)
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
