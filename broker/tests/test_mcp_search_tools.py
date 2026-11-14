from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest
from conftest import (
    AUDIENCE,
    ISSUER,
    make_claims,
    run_aggregator_async,
    run_inprocess_server,
)
from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from fastmcp.server.middleware import Middleware
from mcp.types import ToolAnnotations

from af_mcp_broker.authorization import EntitlementPolicy
from af_mcp_broker.config import Settings
from af_mcp_broker.credentials import CredentialRegistry
from af_mcp_broker.mcp.aggregator import build_aggregator
from af_mcp_broker.mcp.registry import (
    DIAGNOSTIC_TOOL_NAMES,
    SEARCH_TOOLS_TOOL_NAME,
    ServiceRegistry,
    ServiceSpec,
)

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from fastmcp import Client

# ---------------------------------------------------------------------------
# af_search_tools (issue #186's "cheap next step"): lexical search over the
# caller's *entitled* tools, served from the same per-(subject, service)
# listing cache tools/list uses. Exercised end to end through a real
# aggregator and real in-process backends, because the two properties that
# matter -- an unentitled tool never appears, and no extra backend listing --
# only mean something through the real middleware and cache.
# ---------------------------------------------------------------------------


class _ListCounter(Middleware):
    """Backend-side middleware counting the tools/list requests a backend serves."""

    def __init__(self) -> None:
        self.count = 0

    async def on_list_tools(self, context: Any, call_next: Any) -> Any:
        self.count += 1
        return await call_next(context)


def _data_backend(counter: _ListCounter) -> FastMCP:
    backend = FastMCP(name="data-backend", middleware=[counter])

    @backend.tool(description="Return one replica of a dataset.")
    def replica() -> str:
        return "ok"

    @backend.tool(description="Enumerate things.")
    def replica_list() -> str:
        return "ok"

    @backend.tool(
        description="Look up where a dataset lives, by replicas location.",
        annotations=ToolAnnotations(read_only_hint=True),
        tags={"locality"},
    )
    def find() -> str:
        return "ok"

    return backend


def _secret_backend() -> FastMCP:
    backend = FastMCP(name="secret-backend")

    @backend.tool(description="Return a replica only admins may see.")
    def replica() -> str:
        return "ok"

    return backend


@pytest.fixture
def data_counter() -> _ListCounter:
    return _ListCounter()


@pytest.fixture
async def search_client(
    data_counter: _ListCounter,
    sig_key: Any,
    prime_jwks: Any,
    static_principal_cache: Any,
) -> AsyncIterator[Client]:
    principal_cache, directory = static_principal_cache
    directory.groups_by_subject["user-123"] = ["af-atlas-users"]
    prime_jwks([sig_key.jwk])
    token = sig_key.sign(make_claims())
    registry = ServiceRegistry()
    async with (
        run_inprocess_server(_data_backend(data_counter)) as data_url,
        run_inprocess_server(_secret_backend()) as secret_url,
    ):
        for name, url, permission in (
            ("data", data_url, "read_data"),
            ("secret", secret_url, "admin_data"),
        ):
            registry.register(
                ServiceSpec(
                    name=f"{name}_service",
                    prefix=name,
                    url=url,
                    transport="http",
                    required_permission=permission,
                    auth_type="none",
                )
            )
        mcp = build_aggregator(
            registry,
            Settings(oidc_issuer=ISSUER, oidc_audience=AUDIENCE),
            EntitlementPolicy(group_permissions={"af-atlas-users": ["read_data"]}),
            CredentialRegistry(),
            principal_cache=principal_cache,
        )
        async with (
            run_aggregator_async(mcp, path="/mcp") as server,
            server.client(headers={"Authorization": f"Bearer {token}"}) as client,
        ):
            yield client


async def _search(client: Client, query: str, **kwargs: Any) -> dict[str, Any]:
    result = await client.call_tool(SEARCH_TOOLS_TOOL_NAME, {"query": query, **kwargs})
    return result.structured_content


def _names(payload: dict[str, Any]) -> list[str]:
    return [hit["name"] for hit in payload["tools"]]


def test_search_tool_is_a_registered_gateway_tool() -> None:
    assert SEARCH_TOOLS_TOOL_NAME == "af_search_tools"
    assert SEARCH_TOOLS_TOOL_NAME in DIAGNOSTIC_TOOL_NAMES


async def test_search_declares_object_output_schema_and_read_only_annotations(
    search_client: Client,
) -> None:
    tool = next(
        t for t in await search_client.list_tools() if t.name == SEARCH_TOOLS_TOOL_NAME
    )

    assert tool.output_schema is not None
    assert tool.output_schema["type"] == "object"
    assert not tool.output_schema.get("x-fastmcp-wrap-result")
    assert tool.annotations is not None
    assert tool.annotations.read_only_hint is True
    assert tool.annotations.open_world_hint is False
    assert (tool.description or "").splitlines()[0].strip()


async def test_exact_name_ranks_before_name_token_before_description_token(
    search_client: Client,
) -> None:
    payload = await _search(search_client, "data_replica")
    assert _names(payload)[:2] == ["data_replica", "data_replica_list"]

    # Name-token hits (data_replica, data_replica_list) outrank the
    # description-token hit (data_find); ties break by name.
    payload = await _search(search_client, "replica")
    assert _names(payload) == ["data_replica", "data_replica_list", "data_find"]


async def test_exact_name_ranks_first_even_when_other_tools_match_more_tokens(
    search_client: Client,
) -> None:
    payload = await _search(search_client, "data_replica_list")

    assert _names(payload) == ["data_replica_list"]


async def test_every_query_token_must_match(search_client: Client) -> None:
    payload = await _search(search_client, "replica enumerate")

    assert _names(payload) == ["data_replica_list"]


async def test_tags_and_prefix_tokens_are_searched(search_client: Client) -> None:
    assert _names(await _search(search_client, "locality")) == ["data_find"]
    # "replica" is a prefix of the description word "replicas"; the reverse
    # (a plural query finding a singular word) does not match.
    assert "data_find" in _names(await _search(search_client, "replica"))
    assert _names(await _search(search_client, "locations")) == []


async def test_hit_carries_name_summary_service_and_annotations(
    search_client: Client,
) -> None:
    payload = await _search(search_client, "data_find")

    (hit,) = payload["tools"]
    assert hit["name"] == "data_find"
    assert hit["service"] == "data_service"
    assert hit["summary"] == "Look up where a dataset lives, by replicas location."
    assert hit["annotations"]["readOnlyHint"] is True


async def test_unentitled_tool_never_appears_even_on_exact_name_match(
    search_client: Client,
) -> None:
    exact = await _search(search_client, "secret_replica")
    assert "secret_replica" not in _names(exact)
    assert exact["tools"] == []

    broad = await _search(search_client, "replica")
    assert not any(name.startswith("secret_") for name in _names(broad))
    assert broad["total"] == len(broad["tools"])


async def test_no_match_result_names_the_next_step(search_client: Client) -> None:
    payload = await _search(search_client, "zzzznomatch")

    assert payload["tools"] == []
    assert payload["total"] == 0
    assert "af_list_mcp_servers" in payload["note"]


@pytest.mark.parametrize("query", ["", "   "])
async def test_empty_query_is_a_tool_error_naming_the_next_step(
    search_client: Client, query: str
) -> None:
    with pytest.raises(ToolError, match="af_list_mcp_servers"):
        await _search(search_client, query)


async def test_limit_truncates_and_says_so(search_client: Client) -> None:
    payload = await _search(search_client, "replica", limit=1)

    assert _names(payload) == ["data_replica"]
    assert payload["total"] == 3
    assert "limit" in payload["note"]


@pytest.mark.parametrize("limit", [0, -1, 51])
async def test_limit_outside_bounds_is_rejected(
    search_client: Client, limit: int
) -> None:
    with pytest.raises(ToolError):
        await _search(search_client, "replica", limit=limit)


async def test_search_reuses_the_listing_cache(
    search_client: Client, data_counter: _ListCounter
) -> None:
    await search_client.list_tools()
    warm = data_counter.count
    assert warm >= 1

    await _search(search_client, "replica")
    await _search(search_client, "locality")

    assert data_counter.count == warm
