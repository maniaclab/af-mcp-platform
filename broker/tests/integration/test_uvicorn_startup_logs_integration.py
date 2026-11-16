"""Integration tests for the area ``test_uvicorn_startup_logs.py`` covers; the unit tests live in ``unit/test_uvicorn_startup_logs.py``."""

from __future__ import annotations

import json
import re
import shlex
import signal
import subprocess
import sys
import textwrap
import time
from typing import TYPE_CHECKING

import pytest
from fastmcp.utilities.http import find_available_port
from test_uvicorn_startup_logs import (
    _container_log_config_args,
)

if TYPE_CHECKING:
    from pathlib import Path

STARTUP_TIMEOUT_SECONDS = 30.0

_EXPECTED_LIFECYCLE_EVENTS = [
    r"Started server process \[\d+\]",
    r"Waiting for application startup\.",
    r"Application startup complete\.",
    r"Uvicorn running on http://127\.0\.0\.1:\d+ \(Press CTRL\+C to quit\)",
    r"Shutting down",
    r"Waiting for application shutdown\.",
    r"Application shutdown complete\.",
    r"Finished server process \[\d+\]",
]


def test_uvicorn_started_with_the_container_log_config_emits_only_json_lines(
    tmp_path: Path,
) -> None:
    (tmp_path / "tiny_app.py").write_text(
        textwrap.dedent(
            """
            async def app(scope, receive, send):
                if scope["type"] == "lifespan":
                    while True:
                        message = await receive()
                        if message["type"] == "lifespan.startup":
                            await send({"type": "lifespan.startup.complete"})
                        else:
                            await send({"type": "lifespan.shutdown.complete"})
                            return
            """
        )
    )
    port = find_available_port()
    command = [
        sys.executable,
        "-m",
        "uvicorn",
        "tiny_app:app",
        "--host",
        "127.0.0.1",
        "--port",
        str(port),
        *_container_log_config_args(),
    ]
    server = subprocess.Popen(
        command,
        cwd=tmp_path,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        # uvicorn is listening once it has logged its address; stdout is a
        # pipe read to EOF below, so wait on the child's readiness line first.
        deadline = time.monotonic() + STARTUP_TIMEOUT_SECONDS
        stdout_lines: list[str] = []
        assert server.stdout is not None
        while time.monotonic() < deadline:
            line = server.stdout.readline()
            if not line:
                break
            stdout_lines.append(line)
            if "Uvicorn running on" in line:
                break
        else:
            pytest.fail(f"uvicorn did not start: {stdout_lines!r}")
        server.send_signal(signal.SIGINT)
        out, err = server.communicate(timeout=STARTUP_TIMEOUT_SECONDS)
    finally:
        if server.poll() is None:
            server.kill()
            server.communicate()

    stdout_lines.extend(out.splitlines())
    assert err == "", shlex.quote(err)
    events = []
    for line in stdout_lines:
        record = json.loads(line)  # raises on a plain-text line
        assert record["level"] == "info"
        assert record["logger"].startswith("uvicorn")
        assert record["timestamp"].endswith("Z")
        events.append(record["event"])
    assert len(events) == len(_EXPECTED_LIFECYCLE_EVENTS), events
    for event, pattern in zip(events, _EXPECTED_LIFECYCLE_EVENTS, strict=True):
        assert re.fullmatch(pattern, event), (event, pattern)
