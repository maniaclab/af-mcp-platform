"""Shared fixtures for the af-mcp-builder audit script tests."""

from __future__ import annotations

import importlib.util
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator
    from types import ModuleType

SKILL_DIR = Path(__file__).resolve().parent.parent
SCRIPT = SKILL_DIR / "scripts" / "audit_tools.py"
FIXTURE_SERVERS = Path(__file__).resolve().parent / "fixture_servers.py"


@pytest.fixture(scope="session")
def audit() -> ModuleType:
    """Import scripts/audit_tools.py, which is not on the package path."""
    spec = importlib.util.spec_from_file_location("audit_tools", SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # dataclasses resolves annotations through sys.modules at class creation.
    sys.modules["audit_tools"] = module
    spec.loader.exec_module(module)
    return module


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _wait_for_port(port: int, proc: subprocess.Popen[bytes], timeout: float = 30.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            msg = f"fixture server exited early with {proc.returncode}"
            raise RuntimeError(msg)
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.1)
    msg = "fixture server did not open its port"
    raise RuntimeError(msg)


@pytest.fixture
def serve() -> Iterator[Callable[[str, str], int]]:
    """Start a fixture server subprocess on a free port; return its port.

    Call as ``serve("compliant", "http")`` or ``serve("status", "401")``.
    """
    procs: list[subprocess.Popen[bytes]] = []

    def start(kind: str, mode: str) -> int:
        port = _free_port()
        proc = subprocess.Popen(  # noqa: S603
            [sys.executable, str(FIXTURE_SERVERS), kind, mode, str(port)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        procs.append(proc)
        _wait_for_port(port, proc)
        return port

    yield start
    for proc in procs:
        proc.terminate()
        proc.wait(timeout=10)


@pytest.fixture
def run_audit() -> Callable[..., subprocess.CompletedProcess[str]]:
    """Run the audit script as a subprocess; the exit code is the contract."""

    def run(*args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(  # noqa: S603
            [sys.executable, str(SCRIPT), *args],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )

    return run
