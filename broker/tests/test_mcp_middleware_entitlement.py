from __future__ import annotations

from typing import Any

import pytest
from fastmcp.tools.base import Tool

from af_mcp_broker.authorization import EntitlementPolicy
from af_mcp_broker.mcp.middleware.entitlement_mw import EntitlementMiddleware
from af_mcp_broker.mcp.registry import BackendRegistry, BackendSpec


class _FakeFastMCPContext:
    def __init__(self, state: dict[str, Any]) -> None:
        self._state = state

    async def get_state(self, key: str) -> Any:
        return self._state.get(key)


class _FakeMiddlewareContext:
    def __init__(self, fastmcp_context: _FakeFastMCPContext | None) -> None:
        self.fastmcp_context = fastmcp_context


def _tool(name: str) -> Tool:
    return Tool(name=name, parameters={"type": "object", "properties": {}})


@pytest.fixture
def registry() -> BackendRegistry:
    reg = BackendRegistry()
    reg.register(
        BackendSpec(
            name="rucio",
            prefix="rucio",
            url="http://rucio.invalid/mcp",
            transport="http",
            required_capability="read_data",
            apply_namespace=False,
        )
    )
    reg.register(
        BackendSpec(
            name="docs",
            prefix="docs",
            url="http://docs.invalid/mcp",
            transport="http",
            required_capability="__none__",
        )
    )
    return reg


@pytest.fixture
def policy() -> EntitlementPolicy:
    return EntitlementPolicy(
        group_capabilities={"atlas": ["read_data"], "__authenticated__": []},
        target_capabilities={"rucio": "read_data", "docs": "__none__"},
    )


def _call_next_factory(tools: list[Tool]):
    async def _call_next(context: Any) -> list[Tool]:
        return tools

    return _call_next


async def test_entitled_principal_sees_gated_and_open_tools(
    registry, policy, make_principal
):
    mw = EntitlementMiddleware(registry, policy)
    principal = make_principal(groups=["atlas"])
    context = _FakeMiddlewareContext(_FakeFastMCPContext({"principal": principal}))
    tools = [_tool("rucio_list_dids"), _tool("docs_search")]

    result = await mw.on_list_tools(context, _call_next_factory(tools))

    assert {t.name for t in result} == {"rucio_list_dids", "docs_search"}


async def test_unentitled_principal_only_sees_open_tools(
    registry, policy, make_principal
):
    mw = EntitlementMiddleware(registry, policy)
    principal = make_principal(groups=[])
    context = _FakeMiddlewareContext(_FakeFastMCPContext({"principal": principal}))
    tools = [_tool("rucio_list_dids"), _tool("docs_search")]

    result = await mw.on_list_tools(context, _call_next_factory(tools))

    assert {t.name for t in result} == {"docs_search"}


async def test_tool_with_unknown_prefix_is_denied(registry, policy, make_principal):
    """Fail-closed: a tool that doesn't map to any registered backend is
    hidden even for a fully-entitled principal."""
    mw = EntitlementMiddleware(registry, policy)
    principal = make_principal(groups=["atlas"])
    context = _FakeMiddlewareContext(_FakeFastMCPContext({"principal": principal}))
    tools = [_tool("rucio_list_dids"), _tool("mystery_tool")]

    result = await mw.on_list_tools(context, _call_next_factory(tools))

    assert {t.name for t in result} == {"rucio_list_dids"}


async def test_missing_principal_returns_empty_list(registry, policy):
    """identity_mw (registered first / outermost) should always have set the
    principal by the time this runs; if it somehow didn't, fail closed."""
    mw = EntitlementMiddleware(registry, policy)
    context = _FakeMiddlewareContext(_FakeFastMCPContext({}))
    tools = [_tool("rucio_list_dids"), _tool("docs_search")]

    result = await mw.on_list_tools(context, _call_next_factory(tools))

    assert result == []


async def test_missing_fastmcp_context_returns_empty_list(registry, policy):
    mw = EntitlementMiddleware(registry, policy)
    context = _FakeMiddlewareContext(None)
    tools = [_tool("rucio_list_dids")]

    result = await mw.on_list_tools(context, _call_next_factory(tools))

    assert result == []


async def test_registry_and_policy_are_mutable_attributes(
    registry, policy, make_principal
):
    """populate_aggregator() refreshes these in place on every lifespan
    entry rather than constructing a new middleware instance."""
    mw = EntitlementMiddleware(BackendRegistry(), EntitlementPolicy())
    mw.registry = registry
    mw.policy = policy

    principal = make_principal(groups=["atlas"])
    context = _FakeMiddlewareContext(_FakeFastMCPContext({"principal": principal}))
    tools = [_tool("rucio_list_dids")]

    result = await mw.on_list_tools(context, _call_next_factory(tools))

    assert {t.name for t in result} == {"rucio_list_dids"}
