"""The MCP flow a real client runs against a deployed broker.

initialize (the ``mcp_client`` fixture), tools/list and one read-only
tools/call, over the wire with a real bearer token. Run by an operator after
a release with ``pixi run test-e2e``; see docs/testing.md. Nothing is faked:
the tests skip, with the reason, when the deployment or the credential is not
given.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

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
    async with Client(transport) as client:
        yield client


async def test_initialize_handshake(mcp_client: Client) -> None:
    assert mcp_client.is_connected()
    # The negotiated protocol era varies by client and server version, so
    # assert what every era reports rather than the legacy InitializeResult.
    assert mcp_client.protocol_version
    assert mcp_client.server_info.name


async def test_tools_list_is_entitlement_filtered(mcp_client: Client) -> None:
    tool_names = sorted(tool.name for tool in await mcp_client.list_tools())

    # An empty list means no group of this principal grants a permission any
    # service requires; the gateway's own tools are visible to everyone.
    assert DEFAULT_READ_ONLY_TOOL in tool_names, f"visible tools: {tool_names}"


async def test_read_only_tool_call(mcp_client: Client) -> None:
    assert READ_ONLY_TOOL in {tool.name for tool in await mcp_client.list_tools()}

    result = await mcp_client.call_tool(READ_ONLY_TOOL, {})

    assert not result.is_error
    assert result.data
