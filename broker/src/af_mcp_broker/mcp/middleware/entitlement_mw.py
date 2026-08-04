from __future__ import annotations

from typing import TYPE_CHECKING

import structlog
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext

from af_mcp_broker.authorization import EntitlementPolicy, get_principal_capabilities

if TYPE_CHECKING:
    from collections.abc import Sequence

    import mcp.types as mt
    from fastmcp.tools.base import Tool

    from af_mcp_broker.mcp.registry import BackendRegistry

logger = structlog.get_logger(__name__)

# on_list_tools middleware: filters the tool list to capabilities the
# Principal (stored by identity_mw, which must be registered first so it
# runs outermost) actually has. Backends whose required_capability the
# Principal lacks are hidden entirely, as are tools that don't map to any
# known backend.


class EntitlementMiddleware(Middleware):
    def __init__(self, registry: BackendRegistry, policy: EntitlementPolicy) -> None:
        # Mutable on purpose: populate_aggregator() refreshes these in place
        # on every lifespan entry rather than constructing a new middleware
        # instance each time.
        self.registry = registry
        self.policy = policy

    async def on_list_tools(
        self,
        context: MiddlewareContext[mt.ListToolsRequest],
        call_next: CallNext[mt.ListToolsRequest, Sequence[Tool]],
    ) -> Sequence[Tool]:
        tools = await call_next(context)

        principal = (
            await context.fastmcp_context.get_state("principal")
            if context.fastmcp_context is not None
            else None
        )
        if principal is None:
            # identity_mw should always have set this by now; fail closed
            # rather than leak the unfiltered tool list if it somehow didn't.
            return []

        principal_caps = get_principal_capabilities(principal, self.policy)
        return [tool for tool in tools if self._tool_is_allowed(tool, principal_caps)]

    def _tool_is_allowed(self, tool: Tool, principal_caps: set[str]) -> bool:
        backend = self.registry.get_by_tool_prefix(tool.name)
        if backend is None:
            return False  # unknown prefix: deny by default (fail-closed)
        if (
            backend.required_capability is None
            or backend.required_capability == "__none__"
        ):
            # Omitted -> the credential layer is the gate (see app.py's
            # startup validation); "__none__" -> open to any authenticated
            # user. Either way, no capability check gates this tool's listing.
            return True
        return backend.required_capability in principal_caps
