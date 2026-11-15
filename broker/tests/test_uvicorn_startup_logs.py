"""The real uvicorn server, started the way ``Containerfile.broker`` starts it, emits only JSON lines.

The log pipeline parses every line a broker pod writes. uvicorn's lifecycle
lines (server process start, application startup, the listening address, and
the shutdown counterparts) are written by uvicorn's own loggers, which
uvicorn configures before the broker's code runs, so only uvicorn's
``--log-config`` can make them JSON from the first line.
"""

from __future__ import annotations

import json
import re
import shlex
import signal
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest
from fastmcp.utilities.http import find_available_port

REPO_ROOT = Path(__file__).resolve().parents[2]
CONTAINERFILE = REPO_ROOT / "Containerfile.broker"

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


def _container_log_config_args() -> list[str]:
    """The ``--log-config <file>`` arguments of the Containerfile's CMD, with the file resolved to this checkout."""
    cmd_line = next(
        line
        for line in CONTAINERFILE.read_text().splitlines()
        if line.startswith("CMD")
    )
    cmd = json.loads(cmd_line.removeprefix("CMD "))
    path = Path(cmd[cmd.index("--log-config") + 1])
    # The image keeps the sources at /app/broker/src.
    checkout_path = REPO_ROOT / path.relative_to("/app")
    assert checkout_path.is_file(), f"{path} in the CMD is not shipped"
    return ["--log-config", str(checkout_path)]


def test_containerfile_cmd_points_uvicorn_at_the_json_log_config() -> None:
    assert _container_log_config_args()


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
