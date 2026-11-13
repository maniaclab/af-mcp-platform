"""End-to-end tests for policy.yaml's ``rate_limits`` (issue #165): the real broker app boots from a real policy.yaml, a real MCP client with a real bearer token hits the limit and gets the retry information. No mocks of the broker, its middleware or the backend."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

import pytest
from conftest import (
    AUDIENCE,
    ISSUER,
    make_claims,
    run_broker_in_process,
    run_inprocess_server,
)
from fastmcp import FastMCP
from fastmcp.exceptions import ToolError

from af_mcp_broker.config import get_settings

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable
    from pathlib import Path

_POLICY_HEAD = """
group_permissions:
  atlas: [read_data]
  __authenticated__: []
"""


def _backend() -> FastMCP:
    mcp = FastMCP(name="rate-limit-e2e-backend")

    @mcp.tool
    def echo(message: str) -> str:
        return message

    return mcp


@pytest.fixture
async def backend_url() -> AsyncIterator[str]:
    async with run_inprocess_server(_backend(), path="/mcp") as url:
        yield url


async def _directory_resolve(self: Any, principal_id: str) -> Any:
    from af_mcp_broker.principal_directory import PrincipalAttributes

    return PrincipalAttributes(
        uid=None, gid=None, unixname=None, groups=["atlas"], email=""
    )


def _boot_broker(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    backend_url: str,
    policy_body: str,
    sig_key: Any,
    prime_jwks: Any,
) -> Any:
    """Write services.yaml and policy.yaml, point the broker's env at them, and return the real app singleton."""
    services_file = tmp_path / "services.yaml"
    services_file.write_text(
        f"""
services:
  - name: toy
    prefix: toy
    url: "{backend_url}"
    transport: http
    required_permission: read_data
    auth_type: none
"""
    )
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text(_POLICY_HEAD + policy_body)
    monkeypatch.setenv("SERVICES_FILE", str(services_file))
    monkeypatch.setenv("POLICY_FILE", str(policy_file))
    monkeypatch.setenv("OIDC_ISSUER", ISSUER)
    monkeypatch.setenv("OIDC_AUDIENCE", AUDIENCE)
    monkeypatch.setenv("METRICS_PORT", "0")
    monkeypatch.delenv("BROKER_DEV_INSECURE_PRINCIPAL", raising=False)
    monkeypatch.setenv("KEYCLOAK_ADMIN_CLIENT_ID", "test-admin-client")
    monkeypatch.setenv("KEYCLOAK_ADMIN_CLIENT_SECRET", "test-admin-secret")
    monkeypatch.setattr(
        "af_mcp_broker.principal_directory.KeycloakPrincipalDirectory.resolve",
        _directory_resolve,
    )
    get_settings.cache_clear()
    prime_jwks([sig_key.jwk])

    from af_mcp_broker.app import app

    return app


async def test_client_hits_the_limit_and_gets_retry_information(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    backend_url: str,
    sig_key: Any,
    prime_jwks: Any,
) -> None:
    app = _boot_broker(
        monkeypatch,
        tmp_path,
        backend_url,
        """
rate_limits:
  - tool: "toy_echo"
    limit: 2
    window_seconds: 3600
""",
        sig_key,
        prime_jwks,
    )
    token = sig_key.sign(make_claims())

    async with (
        run_broker_in_process(app) as server,
        server.client(headers={"Authorization": f"Bearer {token}"}) as client,
    ):
        for _ in range(2):
            assert (await client.call_tool("toy_echo", {"message": "hi"})).data == "hi"
        with pytest.raises(ToolError) as excinfo:
            await client.call_tool("toy_echo", {"message": "hi"})

    message = str(excinfo.value)
    assert "Rate limit of 2 calls per 3600s exceeded for toy_echo" in message
    # The window opened at the first call, a moment ago on the real clock.
    assert re.search(r"Retry-After: (3600|3599) seconds", message)
    assert re.search(r"retry_at: \d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", message)


async def test_policy_without_rate_limits_never_refuses(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    backend_url: str,
    sig_key: Any,
    prime_jwks: Any,
) -> None:
    app = _boot_broker(monkeypatch, tmp_path, backend_url, "", sig_key, prime_jwks)
    token = sig_key.sign(make_claims())

    async with (
        run_broker_in_process(app) as server,
        server.client(headers={"Authorization": f"Bearer {token}"}) as client,
    ):
        for _ in range(10):
            assert (await client.call_tool("toy_echo", {"message": "hi"})).data == "hi"


def test_broker_refuses_to_start_on_a_malformed_rate_limit_block(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    app_client_factory: Callable[..., Any],
) -> None:
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text(
        _POLICY_HEAD
        + """
rate_limits:
  - tool: "toy_*"
    limit: 5
    window_seconds: soon
"""
    )
    monkeypatch.setenv("POLICY_FILE", str(policy_file))

    with pytest.raises(ValueError, match=r"rate_limits\[0\]: window_seconds"):  # noqa: SIM117
        with app_client_factory():
            pass
