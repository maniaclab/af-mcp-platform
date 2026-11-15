"""Integration tests for the tools, called through an in-memory MCP client."""

from __future__ import annotations

from typing import Any

import httpx2
import pytest
from fastmcp import Client
from shelf_mcp.auth import BrokerTokenVerifier, JwksCache
from shelf_mcp.data import ShelfClient, ShelfUnavailableError
from shelf_mcp.server import MAX_ROWS, build_server

pytestmark = pytest.mark.asyncio


class DownShelf(ShelfClient):
    """A client whose service is unreachable."""

    def iter_datasets(self, pattern: str) -> Any:
        raise ShelfUnavailableError(pattern)

    def get_dataset(self, name: str) -> Any:
        raise ShelfUnavailableError(name)


def _server(shelf: ShelfClient) -> Client[Any]:
    # The in-memory transport does not carry a bearer, so the verifier is never called.
    jwks = JwksCache("https://broker.example.org/jwks", httpx2.AsyncClient())
    return Client(build_server(BrokerTokenVerifier(jwks, "iss", "aud"), shelf))


async def test_list_returns_typed_rows_and_a_text_block() -> None:
    async with _server(ShelfClient()) as client:
        result = await client.call_tool("shelf_list_datasets", {"pattern": "mc23_*"})

    assert [d["name"] for d in result.structured_content["datasets"]] == [
        "mc23_ttbar",
        "mc23_zee",
    ]
    assert result.content[0].text  # O2: text alongside structuredContent


async def test_list_announces_truncation_and_how_to_continue() -> None:
    async with _server(ShelfClient()) as client:
        result = await client.call_tool("shelf_list_datasets", {"limit": 1})

    assert result.structured_content["truncated"] is True
    assert "raise `limit`" in result.structured_content["next_step"]


async def test_empty_list_names_a_next_step() -> None:
    async with _server(ShelfClient()) as client:
        result = await client.call_tool("shelf_list_datasets", {"pattern": "nope*"})

    assert result.structured_content["datasets"] == []
    assert "broader wildcard" in result.structured_content["next_step"]


async def test_limit_is_bounded_by_the_schema() -> None:
    async with _server(ShelfClient()) as client:
        result = await client.call_tool(
            "shelf_list_datasets", {"limit": MAX_ROWS + 1}, raise_on_error=False
        )

    assert result.is_error


async def test_unknown_dataset_is_a_tool_error_with_a_next_step() -> None:
    async with _server(ShelfClient()) as client:
        result = await client.call_tool(
            "shelf_get_dataset", {"name": "missing"}, raise_on_error=False
        )

    assert result.is_error
    assert "shelf_list_datasets" in result.content[0].text


async def test_unreachable_service_is_a_retryable_tool_error() -> None:
    async with _server(DownShelf()) as client:
        result = await client.call_tool(
            "shelf_get_dataset", {"name": "mc23_zee"}, raise_on_error=False
        )

    assert result.is_error
    assert "retry" in result.content[0].text
