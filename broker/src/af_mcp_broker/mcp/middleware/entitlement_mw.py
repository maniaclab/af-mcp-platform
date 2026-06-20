from __future__ import annotations

from typing import Any

import structlog

logger = structlog.get_logger(__name__)

# on_list_tools middleware: filters the tool list to capabilities the Principal has.
# Backends whose required_capability the Principal lacks are hidden entirely.


async def entitlement_middleware(request: Any, call_next: Any) -> Any:
    """Filter visible tools to those the caller is entitled to.

    Operates on list_tools responses. Tool call requests are checked by broker_mw.
    """
    from af_mcp_broker.authorization import get_principal_capabilities

    principal = getattr(request, "context", {}).get("principal")
    if principal is None:
        # identity_mw should always set this; if absent, pass through (fail-closed at broker_mw)
        return await call_next(request)

    response = await call_next(request)

    # Filter tools: only show tools from backends the principal has the capability for.
    # The registry maps tool prefix -> backend -> required_capability.
    # We filter at the list_tools level by calling the registry.
    from af_mcp_broker.mcp.registry import BackendRegistry
    registry: BackendRegistry | None = getattr(request, "app_registry", None)
    if registry is None:
        return response

    policy = getattr(request, "app_policy", None)
    if policy is None:
        return response

    principal_caps = get_principal_capabilities(principal, policy)

    if hasattr(response, "tools"):
        response.tools = [
            tool for tool in response.tools
            if _tool_is_allowed(tool, registry, principal_caps)
        ]

    return response


def _tool_is_allowed(
    tool: Any,
    registry: Any,
    principal_caps: set[str],
) -> bool:
    tool_name: str = getattr(tool, "name", "") or ""
    backend = registry.get_by_tool_prefix(tool_name)
    if backend is None:
        return True  # unknown prefix: pass through
    required = backend.required_capability
    if required == "__none__":
        return True
    return required in principal_caps
