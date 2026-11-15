"""Guards that keep references/example-server in line with docs/mcp-design.md.

Each test starts the example as a real process (`python -m shelf_mcp.server`) behind a
real JWKS endpoint, so a drift in transport, auth, logging or the tool surface
fails here. Set EXAMPLE_SERVER_DIR to run the same guards against another copy
of the example.
"""

from __future__ import annotations

import http.server
import json
import os
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

SKILL_DIR = Path(__file__).resolve().parent.parent
EXAMPLE_DIR = Path(
    os.environ.get("EXAMPLE_SERVER_DIR", SKILL_DIR / "references" / "example-server")
)
ISSUER = "https://broker.example.org"
AUDIENCE = "shelf-mcp"
KID = "test-key"
MCP_HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json, text/event-stream",
}


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


@dataclass
class JwksServer:
    """Serves one public key at /.well-known/jwks.json and counts the fetches."""

    private_key: rsa.RSAPrivateKey
    port: int
    fetches: list[str] = field(default_factory=list)

    @property
    def uri(self) -> str:
        return f"http://127.0.0.1:{self.port}/.well-known/jwks.json"

    def token(self, **overrides: Any) -> str:
        """Mint a broker-style identity token (docs/auth.md, "The token format")."""
        now = int(time.time())
        claims = {
            "iss": ISSUER,
            "sub": "user-sub-1",
            "aud": AUDIENCE,
            "iat": now,
            "exp": now + 600,
            "jti": "jti-1",
        } | overrides
        return jwt.encode(
            claims, self.private_key, algorithm="RS256", headers={"kid": KID}
        )


@pytest.fixture
def jwks() -> Iterator[JwksServer]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    body = json.dumps({"keys": [{**jwk, "kid": KID, "use": "sig", "alg": "RS256"}]})
    server = JwksServer(private_key=key, port=_free_port())

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            server.fetches.append(self.path)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body.encode())

        def log_message(self, *args: object) -> None:
            pass

    httpd = http.server.HTTPServer(("127.0.0.1", server.port), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield server
    httpd.shutdown()
    httpd.server_close()


@dataclass
class Example:
    """A running example server and the way to read its stdout log."""

    port: int
    proc: subprocess.Popen[bytes]
    log_path: Path

    @property
    def mcp_url(self) -> str:
        return f"http://127.0.0.1:{self.port}/mcp"

    def post(
        self, body: dict[str, Any], headers: dict[str, str]
    ) -> tuple[int, dict[str, Any] | None]:
        req = urllib.request.Request(
            self.mcp_url,
            data=json.dumps(body).encode(),
            method="POST",
            headers=MCP_HEADERS | headers,
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                return resp.status, _parse_rpc(resp.read().decode())
        except urllib.error.HTTPError as exc:
            return exc.code, None

    def get(self, path: str, headers: dict[str, str] | None = None) -> int:
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}{path}", headers=headers or {}
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            return int(resp.status)

    def stop(self) -> list[dict[str, Any]]:
        """Stop the server and return every stdout line, parsed as JSON."""
        self.proc.terminate()
        self.proc.wait(timeout=15)
        lines = self.log_path.read_text().splitlines()
        # A line that is not JSON fails the structured-logging guard (L2).
        return [json.loads(line) for line in lines if line.strip()]


def _parse_rpc(text: str) -> dict[str, Any] | None:
    """Parse a JSON or a text/event-stream JSON-RPC response body."""
    for line in text.splitlines():
        payload = line.removeprefix("data:").strip()
        if payload.startswith("{"):
            result: dict[str, Any] = json.loads(payload)
            return result
    return None


@pytest.fixture
def start_example(jwks: JwksServer, tmp_path: Path) -> Iterator[Callable[[], Example]]:
    started: list[Example] = []

    def start() -> Example:
        port = _free_port()
        log_path = tmp_path / f"example-{port}.log"
        env = {
            **os.environ,
            "PYTHONPATH": str(EXAMPLE_DIR),
            "SHELF_JWKS_URI": jwks.uri,
            "SHELF_ISSUER": ISSUER,
            "SHELF_AUDIENCE": AUDIENCE,
            "SHELF_PORT": str(port),
        }
        with log_path.open("wb") as log:
            proc = subprocess.Popen(
                [sys.executable, "-m", "shelf_mcp.server"],
                cwd=EXAMPLE_DIR,
                env=env,
                stdout=log,
                stderr=subprocess.DEVNULL,
            )
        example = Example(port=port, proc=proc, log_path=log_path)
        started.append(example)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                msg = f"example server exited early with {proc.returncode}"
                raise RuntimeError(msg)
            try:
                example.get("/healthz")
            except OSError:
                time.sleep(0.1)
            else:
                return example
        msg = "example server did not become healthy"
        raise RuntimeError(msg)

    yield start
    for example in started:
        if example.proc.poll() is None:
            example.proc.terminate()
        example.proc.wait(timeout=15)


def _tools_list() -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}


def _call(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments},
    }


class TestExampleAudit:
    """The example passes the mechanical audit (docs/mcp-design.md, "What it checks")."""

    def test_audit_reports_no_findings(
        self,
        start_example: Callable[[], Example],
        jwks: JwksServer,
        run_audit: Callable[..., subprocess.CompletedProcess[str]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        example = start_example()
        monkeypatch.setenv("MCP_BEARER_TOKEN", jwks.token())
        base = ("--url", example.mcp_url, "--prefix", "shelf")

        listing = run_audit(*base, "--check-401", "--check-stateless")
        failing = run_audit(
            *base,
            "--call",
            "shelf_get_dataset",
            "--args-json",
            '{"name": "does-not-exist"}',
            "--expect-error",
        )
        succeeding = run_audit(
            *base,
            "--call",
            "shelf_get_dataset",
            "--args-json",
            '{"name": "mc23_ttbar"}',
        )

        for proc in (listing, failing, succeeding):
            assert proc.returncode == 0, proc.stdout + proc.stderr
            assert "No findings." in proc.stdout


class TestExampleWire:
    """X1, X2, X3, U1, U2: the transport and the broker token."""

    def test_tools_list_with_a_valid_broker_token(
        self, start_example: Callable[[], Example], jwks: JwksServer
    ) -> None:
        example = start_example()

        status, body = example.post(
            _tools_list(), {"Authorization": f"Bearer {jwks.token()}"}
        )

        assert status == 200
        assert body is not None
        names = {tool["name"] for tool in body["result"]["tools"]}
        assert names == {"shelf_list_datasets", "shelf_get_dataset"}

    @pytest.mark.parametrize(
        "overrides",
        [{"aud": "another-service"}, {"iss": "https://evil.example"}, {"exp": 1}],
        ids=["wrong-audience", "wrong-issuer", "expired"],
    )
    def test_token_that_fails_validation_gets_401(
        self,
        start_example: Callable[[], Example],
        jwks: JwksServer,
        overrides: dict[str, Any],
    ) -> None:
        example = start_example()

        status, _ = example.post(
            _tools_list(), {"Authorization": f"Bearer {jwks.token(**overrides)}"}
        )

        assert status == 401

    def test_valid_requests_fetch_the_jwks_once(
        self, start_example: Callable[[], Example], jwks: JwksServer
    ) -> None:
        example = start_example()
        headers = {"Authorization": f"Bearer {jwks.token()}"}

        for _ in range(5):
            status, _ = example.post(_tools_list(), headers)
            assert status == 200

        assert len(jwks.fetches) == 1


class TestExampleLogs:
    """L1, L2, L3: request id, structured fields, probe noise."""

    def test_request_id_header_is_on_every_line_of_the_request(
        self, start_example: Callable[[], Example], jwks: JwksServer
    ) -> None:
        example = start_example()
        headers = {"Authorization": f"Bearer {jwks.token()}", "X-Request-ID": "abc"}

        status, _ = example.post(
            _call("shelf_get_dataset", {"name": "mc23_ttbar"}), headers
        )
        lines = example.stop()

        assert status == 200
        tool_lines = [line for line in lines if line.get("event") == "tool.call"]
        access_lines = [line for line in lines if line.get("event") == "http.request"]
        assert len(tool_lines) == 1
        assert [line["request_id"] for line in tool_lines + access_lines] == ["abc"] * 2
        assert {
            "timestamp",
            "level",
            "logger",
            "event",
            "request_id",
            "subject",
            "tool",
            "duration_ms",
            "outcome",
        } <= set(tool_lines[0])
        assert tool_lines[0]["subject"] == "user-sub-1"
        assert tool_lines[0]["outcome"] == "ok"

    def test_healthz_writes_no_access_line_but_failures_are_kept(
        self, start_example: Callable[[], Example], jwks: JwksServer
    ) -> None:
        example = start_example()
        for _ in range(3):
            assert example.get("/healthz", {"X-Request-ID": "probe"}) == 200
        status, _ = example.post(_tools_list(), {"Authorization": "Bearer nope"})
        lines = example.stop()

        assert status == 401
        access = [line for line in lines if line.get("event") == "http.request"]
        assert [line["path"] for line in access] == ["/mcp"]
        assert access[0]["status"] == 401
