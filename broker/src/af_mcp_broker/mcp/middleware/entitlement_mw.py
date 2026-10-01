from __future__ import annotations

from typing import TYPE_CHECKING

import structlog
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext

from af_mcp_broker import metrics
from af_mcp_broker.authorization import (
    DISABLED_PERMISSION,
    EntitlementPolicy,
    annotation_disagrees_with_policy,
    get_principal_permissions,
    resolve_action_type,
)
from af_mcp_broker.mcp.registry import AnnotationMismatch, ToolMappingDrift

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
        self._lint_annotations(tools)
        self._lint_tool_mapping(tools)

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

    def _lint_annotations(self, tools: Sequence[Tool]) -> None:
        """Warn (log + metric) when a tool's declared read_only_hint disagrees with the policy-resolved action_type (issue #238 B.8's "forward + lint" decision).

        Runs on every tools/list request's full
        (pre-filter) tool set, independent of which caller triggered it --
        this is about the server's own declared config, not caller identity.
        Recorded onto the registry (ServiceRegistry.record_annotation_mismatch)
        so GET /v1/admin/annotation-mismatches can surface the
        current set without a live probe of its own; the warning/metric
        only fire the first time a given (service, tool) mismatch is
        observed, not on every request that re-observes an already-known
        one, to avoid drowning the log in a repeat per tools/list call.
        """
        for tool in tools:
            service = self.registry.get_by_tool_prefix(tool.name)
            if service is None:
                continue  # unmapped; _tool_is_allowed already denies it
            permission = self.registry.required_permission_for(tool.name, service)
            if permission == DISABLED_PERMISSION:
                # Denied outright, so its "read" action type is only a
                # fallback; comparing it to the backend's hint is noise.
                self.registry.clear_annotation_mismatch(service.name, tool.name)
                continue
            action_type, resolved_via = resolve_action_type(
                service.name, tool.name, permission, self.policy
            )
            read_only_hint = (
                tool.annotations.read_only_hint if tool.annotations else None
            )
            if not annotation_disagrees_with_policy(read_only_hint, action_type):
                self.registry.clear_annotation_mismatch(service.name, tool.name)
                continue
            assert read_only_hint is not None  # disagreement implies declared
            mismatch = AnnotationMismatch(
                service=service.name,
                tool=tool.name,
                declared_read_only_hint=read_only_hint,
                resolved_action_type=action_type,
                resolved_via=resolved_via,
                permission=permission if permission is not None else "__none__",
            )
            if (
                self.registry.get_annotation_mismatch(service.name, tool.name)
                != mismatch
            ):
                logger.warning(
                    "entitlement.annotation_policy_mismatch",
                    service=mismatch.service,
                    tool=mismatch.tool,
                    declared_read_only_hint=mismatch.declared_read_only_hint,
                    resolved_action_type=mismatch.resolved_action_type,
                    resolved_via=mismatch.resolved_via,
                    permission=mismatch.permission,
                )
                metrics.annotation_policy_mismatches_total.labels(
                    service=mismatch.service, tool=mismatch.tool
                ).inc()
            self.registry.record_annotation_mismatch(mismatch)

    def _lint_tool_mapping(self, tools: Sequence[Tool]) -> None:
        """Record (log + metric) drift between each dict-form ``required_permission`` and the tools its backend advertises (issue #330).

        Like _lint_annotations, runs on the full pre-filter tool set. A
        service advertising no tools in this listing is skipped: that is
        indistinguishable from an unreachable backend or a caller with no
        linked credential, and would flag every key as stale.
        """
        advertised: dict[str, set[str]] = {}
        for tool in tools:
            service = self.registry.get_by_tool_prefix(tool.name)
            if service is not None:
                advertised.setdefault(service.name, set()).add(tool.name)
        for service in self.registry.all_services():
            if service.builtin or not isinstance(service.required_permission, dict):
                continue
            names = advertised.get(service.name)
            if not names:
                continue
            unmapped = {
                name
                for name in names
                if self.registry.required_permission_for(name, service)
                == DISABLED_PERMISSION
            }
            stale = self.registry.mapped_tool_names(service) - names
            if not unmapped and not stale:
                self.registry.clear_tool_mapping_drift(service.name)
                continue
            drift = ToolMappingDrift(
                service=service.name,
                unmapped=tuple(sorted(unmapped)),
                stale=tuple(sorted(stale)),
            )
            previous = self.registry.get_tool_mapping_drift(service.name)
            if previous != drift:
                logger.warning(
                    "entitlement.tool_mapping_drift",
                    service=drift.service,
                    unmapped=drift.unmapped,
                    stale=drift.stale,
                )
                for kind, current, before in (
                    ("unmapped", drift.unmapped, previous.unmapped if previous else ()),
                    ("stale", drift.stale, previous.stale if previous else ()),
                ):
                    metrics.tool_mapping_drift_total.labels(
                        service=drift.service, kind=kind
                    ).inc(len(set(current) - set(before)))
            self.registry.record_tool_mapping_drift(drift)

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
        permission = self.registry.required_permission_for(tool.name, service)
        if permission is None or permission == "__none__":
            # Omitted -> the credential layer is the gate (see app.py's
            # startup validation); "__none__" -> open to any authenticated
            # user. Either way, no permission check gates this tool's listing.
            return True
        if permission == DISABLED_PERMISSION:
            # Dict-form required_permission, this tool isn't one of its
            # explicit keys, and there's no __default__ -- opt-in-only means
            # nobody can hold a permission that would satisfy it.
            return False
        return permission in principal_caps
