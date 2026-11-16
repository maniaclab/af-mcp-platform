"""The MCP flow a real client runs against a deployed broker.

initialize (the ``mcp_client`` fixture), tools/list and one read-only
tools/call, over the wire with a real bearer token. Run by an operator after
a release with ``pixi run test-e2e``; see docs/testing.md. Nothing is faked:
the tests skip, with the reason, when the deployment or the credential is not
given.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING, NoReturn

import pytest
from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

BROKER_URL_ENV_VAR = "E2E_BROKER_URL"
TOKEN_ENV_VAR = "MCP_BEARER_TOKEN"
TOOL_ENV_VAR = "E2E_TOOL"

# The gateway's own identity tool: read-only, and it needs no linked identity,
# so it succeeds for any principal the broker accepts. E2E_TOOL names another
# read-only, argument-free tool (e.g. rucio_whoami) to prove a backend is
# reached through the broker.
DEFAULT_READ_ONLY_TOOL = "af_whoami"
READ_ONLY_TOOL = os.environ.get(TOOL_ENV_VAR) or DEFAULT_READ_ONLY_TOOL


# Substring of a failure's message -> what it means and what to do. The strings
# are the ones af_mcp_broker.mcp.aggregator's _make_client_factory and
# mcp.middleware.authorization_mw raise, so a hint only fires for the error
# path it names.
_HINTS: dict[str, str] = {
    "not linked": (
        "The credential provider for this service has no linked account for "
        "you yet. Visit the portal's Identities page and click 'Link', then "
        "run the tests again."
    ),
    "Credential unlock required": (
        "Your x509/VOMS proxy needs a passphrase unlock. Visit the portal URL "
        "in the error."
    ),
    "Authorization denied": (
        "Your Keycloak groups don't grant the permission this service "
        "requires. Check `GET /v1/permissions` for what you currently have."
    ),
    "requires an x509/VOMS proxy, which needs a POSIX": (
        "x509 services are callable via /mcp, but this account has no "
        "POSIX/grid identity, which voms-token-service needs to mint a proxy "
        "as you -- see docs/x509-deployment-notes.md. Contact your Analysis "
        "Facility operator to request a grid identity."
    ),
    "No service registered for tool": (
        "The tool name doesn't match any configured service's prefix. Check "
        "the exact names in the tools/list output."
    ),
    "All connection attempts failed": (
        "Nothing answered at E2E_BROKER_URL: check the host, the port and that "
        "the URL is the broker's own origin, without the /mcp path."
    ),
    "CERTIFICATE_VERIFY_FAILED": (
        "The broker's TLS certificate is not trusted by this machine: check "
        "E2E_BROKER_URL names the host the certificate was issued for."
    ),
    "401": (
        "The broker rejected the bearer token: it is expired, for another "
        "realm, or not a Keycloak access token or PAT. Mint a fresh one."
    ),
}


def _fail(step: str, exc: Exception) -> NoReturn:
    """Fail the test with the error, and a hint when the error is a known one."""
    message = f"{step}: {type(exc).__name__}: {exc}"
    hint = next((text for part, text in _HINTS.items() if part in str(exc)), None)
    pytest.fail(f"{message}\nhint: {hint}" if hint else message, pytrace=False)


def _group_by_service(tool_names: list[str]) -> dict[str, list[str]]:
    """Group tool names by the segment before the first underscore.

    A display heuristic, not authoritative: every service in services.yaml
    namespaces its tools as "<prefix>_<name>" (or already self-prefixes the
    same way), see ServiceSpec.apply_namespace.
    """
    grouped: dict[str, list[str]] = {}
    for name in tool_names:
        grouped.setdefault(name.split("_", 1)[0], []).append(name)
    return grouped


def _format_tools(tool_names: list[str]) -> str:
    grouped = _group_by_service(tool_names)
    lines = [f"{len(tool_names)} tool(s) across {len(grouped)} service(s)"]
    for prefix in sorted(grouped):
        lines.append(f"  {prefix}:")
        lines.extend(f"    - {name}" for name in grouped[prefix])
    return "\n".join(lines)


@pytest.fixture(scope="session")
def broker_url() -> str:
    url = os.environ.get(BROKER_URL_ENV_VAR)
    if not url:
        pytest.skip(
            f"{BROKER_URL_ENV_VAR} is not set; e2e tests need the base URL of a "
            "deployed broker, e.g. https://mcp.example.org"
        )
    return url.rstrip("/")


@pytest.fixture(scope="session")
def bearer_token() -> str:
    token = os.environ.get(TOKEN_ENV_VAR)
    if not token:
        pytest.skip(
            f"{TOKEN_ENV_VAR} is not set; e2e tests need a real bearer token "
            "(a Keycloak access token or a PAT) for the deployment"
        )
    return token


@pytest.fixture
async def mcp_client(broker_url: str, bearer_token: str) -> AsyncIterator[Client]:
    """A connected client: entering it performs the MCP initialize handshake."""
    transport = StreamableHttpTransport(
        f"{broker_url}/mcp/", headers={"Authorization": f"Bearer {bearer_token}"}
    )
    client = Client(transport)
    try:
        await client.__aenter__()
    except Exception as exc:  # noqa: BLE001 -- report whatever the transport raises, with a hint
        _fail(f"connecting to {broker_url}/mcp/ (MCP initialize)", exc)
    try:
        yield client
    finally:
        await client.__aexit__(None, None, None)


async def _visible_tools(client: Client) -> list[str]:
    try:
        return sorted(tool.name for tool in await client.list_tools())
    except Exception as exc:  # noqa: BLE001
        _fail("tools/list", exc)


async def test_initialize_handshake(mcp_client: Client) -> None:
    assert mcp_client.is_connected()
    # The negotiated protocol era varies by client and server version, so
    # assert what every era reports rather than the legacy InitializeResult.
    assert mcp_client.protocol_version
    assert mcp_client.server_info.name


async def test_tools_list_is_entitlement_filtered(mcp_client: Client) -> None:
    tool_names = await _visible_tools(mcp_client)
    # Shown with `pytest -s` (the test-e2e task passes it): what the caller can
    # see, grouped by service.
    print(f"\n{_format_tools(tool_names)}")  # noqa: T201 -- operator-facing output

    # An empty list means no group of this principal grants a permission any
    # service requires; the gateway's own tools are visible to everyone.
    assert DEFAULT_READ_ONLY_TOOL in tool_names, (
        f"visible tools:\n{_format_tools(tool_names)}"
    )


async def test_read_only_tool_call(mcp_client: Client) -> None:
    visible = await _visible_tools(mcp_client)
    assert READ_ONLY_TOOL in visible, f"visible tools:\n{_format_tools(visible)}"

    try:
        result = await mcp_client.call_tool(READ_ONLY_TOOL, {})
    except Exception as exc:  # noqa: BLE001
        _fail(f"tools/call {READ_ONLY_TOOL}", exc)

    assert not result.is_error
    assert result.data
