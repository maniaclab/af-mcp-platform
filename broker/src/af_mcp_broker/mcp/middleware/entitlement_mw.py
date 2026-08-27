from __future__ import annotations

from typing import TYPE_CHECKING

import structlog
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext

from af_mcp_broker.authorization import EntitlementPolicy, get_principal_permissions

if TYPE_CHECKING:
    from collections.abc import Sequence

    import mcp.types as mt
    from fastmcp.tools.base import Tool

    from af_mcp_broker.mcp.registry import ServiceRegistry

logger = structlog.get_logger(__name__)

# on_list_tools middleware: filters the tool list to permissions the
# Principal (stored by identity_mw, which must be registered first so it
# runs outermost) actually has. Services whose required_permission the
# Principal lacks are hidden entirely, as are tools that don't map to any
# known service.


class EntitlementMiddleware(Middleware):
    def __init__(self, registry: ServiceRegistry, policy: EntitlementPolicy) -> None:
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

        principal_caps = get_principal_permissions(principal, self.policy)
        return [tool for tool in tools if self._tool_is_allowed(tool, principal_caps)]

    def _tool_is_allowed(self, tool: Tool, principal_caps: set[str]) -> bool:
        # The broker's own af_* methods (issue #153) route here too, via the
        # builtin gateway service the registry always carries (issue #240):
        # its "__none__" permission keeps them visible to every authenticated
        # caller regardless of entitlements, precisely because they're how a
        # caller self-diagnoses a missing/denied tool elsewhere. No operator
        # service can ever claim the af prefix (ServiceRegistry.register()
        # refuses it), so a real service's tool can't ride that entry past
        # the permission check below.
        service = self.registry.get_by_tool_prefix(tool.name)
        if service is None:
            return False  # unknown prefix: deny by default (fail-closed)
        if (
            service.required_permission is None
            or service.required_permission == "__none__"
        ):
            # Omitted -> the credential layer is the gate (see app.py's
            # startup validation); "__none__" -> open to any authenticated
            # user. Either way, no permission check gates this tool's listing.
            return True
        return service.required_permission in principal_caps
