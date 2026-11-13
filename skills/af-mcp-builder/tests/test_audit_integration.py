"""End-to-end tests: run audit_tools.py as a subprocess against real fastmcp servers.

No mocks. The servers are in fixture_servers.py and run as their own
processes, over stdio (spawned by the script) and streamable HTTP (a real
socket on a free port).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import subprocess
    from collections.abc import Callable

    import pytest

FIXTURE_SERVERS = Path(__file__).resolve().parent / "fixture_servers.py"
GOOD_TOKEN = "fixture-good-token"

# Every finding the violating server must produce, as (item, level, tool).
VIOLATING_FINDINGS = {
    ("A1", "MUST", "bare_tool"),
    ("N1", "MUST", "bare_tool"),
    ("N2", "MUST", "bare_tool"),
    ("O1", "MUST", "bare_tool"),
    ("S1", "MUST", "bare_tool"),
    ("N2", "MUST", "fx_write_thing"),
    ("A2", "SHOULD", "fx_write_thing"),
    ("N3", "SHOULD", "fx_write_thing"),
    ("B1", "MUST", "fx_list_things"),
    ("U3", "MUST", "fx_list_things"),
    ("U6", "MUST", "fx_list_things"),
}
# Added by --call fx_get_thing --expect-error: the tool reports failure as text.
VIOLATING_CALL_FINDING = ("E1", "MUST", "fx_get_thing")


def stdio_command(kind: str) -> str:
    return f"{sys.executable} {FIXTURE_SERVERS} {kind} stdio"


def rows(stdout: str) -> set[tuple[str, str, str]]:
    """Parse the findings table into (item, level, tool) tuples."""
    out = set()
    for line in stdout.splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if (
            line.startswith("| ")
            and len(cells) == 4
            and cells[0] not in ("Item", "------")
        ):
            out.add((cells[0], cells[1], cells[2].strip("`")))
    return out


class TestOverStdio:
    def test_compliant_server_has_no_findings(
        self, run_audit: Callable[..., subprocess.CompletedProcess[str]]
    ) -> None:
        proc = run_audit("--stdio", stdio_command("compliant"), "--prefix", "fx")
        assert proc.returncode == 0, proc.stdout
        assert "Audited 3 tools." in proc.stdout
        assert "No findings." in proc.stdout

    def test_compliant_server_failing_call_is_clean(
        self, run_audit: Callable[..., subprocess.CompletedProcess[str]]
    ) -> None:
        proc = run_audit(
            "--stdio", stdio_command("compliant"), "--prefix", "fx",
            "--call", "fx_get_thing", "--args-json", '{"thing_id": "nope"}', "--expect-error",
        )  # fmt: skip
        assert proc.returncode == 0, proc.stdout
        assert "No findings." in proc.stdout

    def test_compliant_server_good_call_is_clean(
        self, run_audit: Callable[..., subprocess.CompletedProcess[str]]
    ) -> None:
        proc = run_audit(
            "--stdio", stdio_command("compliant"), "--prefix", "fx",
            "--call", "fx_get_thing", "--args-json", '{"thing_id": "known"}',
        )  # fmt: skip
        assert proc.returncode == 0, proc.stdout

    def test_violating_server_findings_are_exact_and_exit_is_1(
        self, run_audit: Callable[..., subprocess.CompletedProcess[str]]
    ) -> None:
        proc = run_audit("--stdio", stdio_command("violating"), "--prefix", "fx")
        assert proc.returncode == 1
        assert rows(proc.stdout) == VIOLATING_FINDINGS
        assert "Audited 4 tools." in proc.stdout
        assert "9 MUST, 2 SHOULD." in proc.stdout

    def test_violating_server_call_adds_e1(
        self, run_audit: Callable[..., subprocess.CompletedProcess[str]]
    ) -> None:
        proc = run_audit(
            "--stdio", stdio_command("violating"), "--prefix", "fx",
            "--call", "fx_get_thing", "--args-json", '{"thing_id": "nope"}', "--expect-error",
        )  # fmt: skip
        assert proc.returncode == 1
        assert rows(proc.stdout) == VIOLATING_FINDINGS | {VIOLATING_CALL_FINDING}

    def test_without_prefix_the_prefix_check_is_skipped(
        self, run_audit: Callable[..., subprocess.CompletedProcess[str]]
    ) -> None:
        proc = run_audit("--stdio", stdio_command("violating"))
        assert ("N1", "MUST", "bare_tool") not in rows(proc.stdout)
        assert proc.returncode == 1  # other MUST findings remain

    def test_unknown_tool_for_call_exits_with_message(
        self, run_audit: Callable[..., subprocess.CompletedProcess[str]]
    ) -> None:
        proc = run_audit(
            "--stdio", stdio_command("compliant"), "--call", "no_such_tool"
        )
        assert proc.returncode == 2
        assert "no tool named 'no_such_tool'" in proc.stderr


class TestOverHttp:
    def test_compliant_server_has_no_findings(
        self,
        run_audit: Callable[..., subprocess.CompletedProcess[str]],
        serve: Callable[[str, str], int],
    ) -> None:
        port = serve("compliant", "http")
        proc = run_audit("--url", f"http://127.0.0.1:{port}/mcp", "--prefix", "fx")
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert "No findings." in proc.stdout

    def test_violating_server_findings_match_stdio(
        self,
        run_audit: Callable[..., subprocess.CompletedProcess[str]],
        serve: Callable[[str, str], int],
    ) -> None:
        port = serve("violating", "http")
        proc = run_audit(
            "--url", f"http://127.0.0.1:{port}/mcp", "--prefix", "fx",
            "--call", "fx_get_thing", "--args-json", '{"thing_id": "nope"}', "--expect-error",
        )  # fmt: skip
        assert proc.returncode == 1
        assert rows(proc.stdout) == VIOLATING_FINDINGS | {VIOLATING_CALL_FINDING}


class TestCheck401EndToEnd:
    def test_stateless_server_that_answers_200_to_a_bad_bearer(
        self,
        run_audit: Callable[..., subprocess.CompletedProcess[str]],
        serve: Callable[[str, str], int],
    ) -> None:
        port = serve("compliant", "stateless")  # no auth: accepts any bearer
        proc = run_audit(
            "--url", f"http://127.0.0.1:{port}/mcp", "--prefix", "fx", "--check-401"
        )
        assert proc.returncode == 1
        assert rows(proc.stdout) == {("X2", "MUST", "(transport)")}
        assert "HTTP 200" in proc.stdout

    def test_stateful_server_without_auth_answers_400_not_401(
        self,
        run_audit: Callable[..., subprocess.CompletedProcess[str]],
        serve: Callable[[str, str], int],
    ) -> None:
        port = serve("compliant", "http")  # bare tools/list has no session id
        proc = run_audit(
            "--url", f"http://127.0.0.1:{port}/mcp", "--prefix", "fx", "--check-401"
        )
        assert proc.returncode == 1
        assert rows(proc.stdout) == {("X2", "MUST", "(transport)")}
        assert "HTTP 400" in proc.stdout

    def test_server_that_answers_401_to_a_bad_bearer(
        self,
        run_audit: Callable[..., subprocess.CompletedProcess[str]],
        serve: Callable[[str, str], int],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        port = serve("compliant-auth", "http")
        monkeypatch.setitem(os.environ, "MCP_BEARER_TOKEN", GOOD_TOKEN)
        proc = run_audit(
            "--url", f"http://127.0.0.1:{port}/mcp", "--prefix", "fx", "--check-401"
        )
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert "No findings." in proc.stdout

    def test_auth_server_rejects_audit_without_a_token(
        self,
        run_audit: Callable[..., subprocess.CompletedProcess[str]],
        serve: Callable[[str, str], int],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        port = serve("compliant-auth", "http")
        monkeypatch.delenv("MCP_BEARER_TOKEN", raising=False)
        proc = run_audit("--url", f"http://127.0.0.1:{port}/mcp", "--prefix", "fx")
        assert proc.returncode == 2  # cannot connect, so no audit table
        assert "audit could not run" in proc.stderr


class TestCheckStatelessEndToEnd:
    def test_stateless_server_passes(
        self,
        run_audit: Callable[..., subprocess.CompletedProcess[str]],
        serve: Callable[[str, str], int],
    ) -> None:
        port = serve("compliant", "stateless")
        proc = run_audit(
            "--url",
            f"http://127.0.0.1:{port}/mcp",
            "--prefix",
            "fx",
            "--check-stateless",
        )
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert "No findings." in proc.stdout

    def test_stateful_server_fails_x1(
        self,
        run_audit: Callable[..., subprocess.CompletedProcess[str]],
        serve: Callable[[str, str], int],
    ) -> None:
        port = serve("compliant", "http")  # SDK default: stateful
        proc = run_audit(
            "--url",
            f"http://127.0.0.1:{port}/mcp",
            "--prefix",
            "fx",
            "--check-stateless",
        )
        assert proc.returncode == 1
        assert rows(proc.stdout) == {("X1", "MUST", "(transport)")}
        assert "HTTP 400" in proc.stdout

    def test_stateless_server_with_auth_passes_with_a_token(
        self,
        run_audit: Callable[..., subprocess.CompletedProcess[str]],
        serve: Callable[[str, str], int],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        port = serve("compliant-auth", "stateless")
        monkeypatch.setitem(os.environ, "MCP_BEARER_TOKEN", GOOD_TOKEN)
        proc = run_audit(
            "--url",
            f"http://127.0.0.1:{port}/mcp",
            "--prefix",
            "fx",
            "--check-stateless",
        )
        assert proc.returncode == 0, proc.stdout + proc.stderr


class TestLegacySseEndToEnd:
    def test_legacy_sse_server_fails_x1(
        self,
        run_audit: Callable[..., subprocess.CompletedProcess[str]],
        serve: Callable[[str, str], int],
    ) -> None:
        port = serve("legacy-sse", "sse")
        proc = run_audit("--url", f"http://127.0.0.1:{port}/sse", "--prefix", "fx")
        assert proc.returncode == 1, proc.stdout + proc.stderr
        assert rows(proc.stdout) == {("X1", "MUST", "(transport)")}
        assert "HTTP+SSE" in proc.stdout

    def test_streamable_server_is_not_flagged(
        self,
        run_audit: Callable[..., subprocess.CompletedProcess[str]],
        serve: Callable[[str, str], int],
    ) -> None:
        port = serve("compliant", "stateless")
        proc = run_audit("--url", f"http://127.0.0.1:{port}/mcp", "--prefix", "fx")
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert "No findings." in proc.stdout
