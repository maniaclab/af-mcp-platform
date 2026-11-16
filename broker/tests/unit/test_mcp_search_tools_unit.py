from __future__ import annotations

from af_mcp_broker.service_registry import (
    DIAGNOSTIC_TOOL_NAMES,
    SEARCH_TOOLS_TOOL_NAME,
)


def test_search_tool_is_a_registered_gateway_tool() -> None:
    assert SEARCH_TOOLS_TOOL_NAME == "af_search_tools"
    assert SEARCH_TOOLS_TOOL_NAME in DIAGNOSTIC_TOOL_NAMES
