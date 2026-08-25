from __future__ import annotations

import time
import uuid
from typing import TYPE_CHECKING

import structlog
from fastmcp.exceptions import AuthorizationError
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext

from af_mcp_broker import metrics
from af_mcp_broker.audit import AuditRecord, write_audit
from af_mcp_broker.authorization import (
    EntitlementPolicy,
    check_entitlement,
    get_action_type,
)
from af_mcp_broker.mcp.registry import DIAGNOSTIC_TOOL_NAMES

if TYPE_CHECKING:
    import mcp.types as mt
    from fastmcp.tools.base import ToolResult

    from af_mcp_broker.identity import Principal
    from af_mcp_broker.mcp.registry import ServiceRegistry

logger = structlog.get_logger(__name__)

# on_call_tool middleware: authorizes every tool call and audits it -- both
# concerns live in one middleware (rather than two separate ones) because
# audit must record a denial, and a denial never calls call_next; a
# downstream audit middleware wrapped *inside* this one would simply never
# run for a denied call. Runs after identity_mw/entitlement_mw (registered
# last, so innermost among the three) and before any credential is minted --
# credential resolution happens inside the aggregator's client_factory,
# which call_next only reaches once this middleware has already allowed the
# call through. On allow, this middleware also stamps request-scoped state
# (see the comment above set_state() below) telling that client_factory this
# is a genuine tools/call for a specific service, not a tools/list
# schema-cache refresh sharing the same factory.
#
# Supersedes the old HTTP-loopback broker_mw.py: that module re-validated the
# same JWT per call over /v1/authorize and /v1/credential even when
# co-located with the broker. The /v1 route bodies (api/permissions.py's
# authorize(), api/credentials.py's issue_credential()) remain the canonical
# logic; this middleware and the client_factory call the same in-process
# functions/classes those routes call, rather than looping back over HTTP.


def _permission_grant_field(principal: Principal) -> list[str] | None:
    """Sorted ``AuditRecord.principal_permission_grant`` value for *principal* -- see that field's docstring for why a denied call needs this to tell "lacks it entirely" apart from "PAT is scoped away from it" (issue #144 step 4)."""
    if principal.permission_grant is None:
        return None
    return sorted(principal.permission_grant)


def _record_invocation(service_name: str, tool_name: str, action_type: str) -> None:
    """Increment the tool-invocation counter.

    No identity label -- per-identity counting was deliberately dropped in
    favor of the audit log (``write_audit()`` above already records the
    same call with the caller's identity attached, at full fidelity and
    behind access control); see metrics.py's cardinality policy.
    """
    metrics.tool_invocations_total.labels(
        service=service_name, tool=tool_name, action_type=action_type
    ).inc()


class AuthorizationMiddleware(Middleware):
    def __init__(self, registry: ServiceRegistry, policy: EntitlementPolicy) -> None:
        # Mutable on purpose: populate_aggregator() refreshes these in place
        # on every lifespan entry rather than constructing a new middleware
        # instance each time (mirrors EntitlementMiddleware).
        self.registry = registry
        self.policy = policy

    async def on_call_tool(
        self,
        context: MiddlewareContext[mt.CallToolRequestParams],
        call_next: CallNext[mt.CallToolRequestParams, ToolResult],
    ) -> ToolResult:
        tool_name = context.message.name
        tool_args = context.message.arguments or {}

        fastmcp_context = context.fastmcp_context
        principal = (
            await fastmcp_context.get_state("principal")
            if fastmcp_context is not None
            else None
        )
        if fastmcp_context is None or principal is None:
            # identity_mw should always have set this by now; fail closed
            # without writing an audit record for a principal we don't have
            # (mirrors entitlement_mw's identical defensive branch).
            raise AuthorizationError("No authenticated principal for this tool call")

        if tool_name in DIAGNOSTIC_TOOL_NAMES:
            # af_* diagnostic tools (issue #153) bypass entitlement
            # checking, credential minting, and per-service audit/metrics
            # entirely: they need no permission, touch no service, and
            # ProxyProvider never enters this call path for them at all
            # (they're registered directly on the aggregator -- see
            # mcp/diagnostics.py). They must keep answering precisely when
            # a service or its credential provider is broken, so gating
            # them behind the same machinery that call is meant to explain
            # would be circular. No registered service can claim this
            # prefix (ServiceRegistry.register() refuses it), so this can't
            # be used to route a real service's tool around authorization.
            return await call_next(context)

        service = self.registry.get_by_tool_prefix(tool_name)
        request_id = str(uuid.uuid4())
        args_summary = ", ".join(f"{k}=..." for k in list(tool_args.keys())[:10])

        if service is None:
            # tool_name is client-supplied and matches no configured
            # service prefix here, so it must never become a label value
            # (unbounded cardinality) -- count it in the label-free
            # unmapped counter instead. See metrics.py's cardinality policy.
            metrics.tool_invocations_unmapped_total.inc()
            await write_audit(
                AuditRecord(
                    principal_sub=principal.subject,
                    principal_uid=principal.uid,
                    permission="__unmapped__",
                    target=tool_name,
                    action=tool_name,
                    action_type="read",
                    args_summary=args_summary,
                    timestamp=time.time(),
                    request_id=request_id,
                    outcome="denied",
                    error=f"no service registered for tool '{tool_name}'",
                    principal_permission_grant=_permission_grant_field(principal),
                )
            )
            raise AuthorizationError(f"No service registered for tool '{tool_name}'")

        action_type = get_action_type(
            service.name, tool_name, service.required_permission, self.policy
        )
        allow, reason = check_entitlement(
            principal, service.required_permission, service.name, self.policy
        )
        if not allow:
            # A denial is still an attempted invocation for the coarse
            # counters, plus its own isolated denied counter -- see
            # metrics.py's cardinality policy for why outcome isn't a label
            # on tool_invocations_total itself.
            _record_invocation(service.name, tool_name, action_type)
            metrics.tool_invocations_denied_total.labels(
                service=service.name, action_type=action_type
            ).inc()
            await write_audit(
                AuditRecord(
                    principal_sub=principal.subject,
                    principal_uid=principal.uid,
                    permission=service.required_permission,
                    target=service.name,
                    action=tool_name,
                    action_type=action_type,
                    args_summary=args_summary,
                    timestamp=time.time(),
                    request_id=request_id,
                    mcp_service=service.name,
                    outcome="denied",
                    error=reason,
                    principal_permission_grant=_permission_grant_field(principal),
                )
            )
            raise AuthorizationError(f"Authorization denied: {reason}")

        # Signal to the aggregator's client_factory (aggregator.py) that this
        # in-flight request is a genuine, authorized tools/call targeting
        # this service -- credential minting is gated on this because
        # ProxyProvider shares the same client_factory for tools/list schema
        # caching (process-wide, up to 5 minutes, across all sessions), and
        # a factory invocation triggered by that cache refresh is otherwise
        # indistinguishable from one triggered by an actual call. Minting a
        # per-user credential during a shared schema listing would be both
        # wasteful and semantically wrong. Request-scoped state, so it never
        # leaks into a later, unrelated request.
        await fastmcp_context.set_state(
            "authorized_call_target", service.name, serializable=False
        )

        # Wall time of everything downstream of authorization -- credential
        # resolution plus the backend call itself. Metered on the success and
        # error paths alike (an error still spent this long); denied/unmapped
        # calls above never executed anything, so their audit records carry
        # duration_ms=None.
        started = time.perf_counter()
        try:
            result = await call_next(context)
        except Exception as exc:
            duration = time.perf_counter() - started
            # An error downstream of authorization (credential resolution,
            # the service call itself) is still an attempted invocation --
            # authorization allowed it, so it's not a denial, and gets no
            # separate error counter (the audit log is the source of truth
            # for exact per-outcome fidelity; see metrics.py's docstring).
            _record_invocation(service.name, tool_name, action_type)
            metrics.tool_duration_seconds.labels(
                service=service.name, tool=tool_name, action_type=action_type
            ).observe(duration)
            await write_audit(
                AuditRecord(
                    principal_sub=principal.subject,
                    principal_uid=principal.uid,
                    permission=service.required_permission,
                    target=service.name,
                    action=tool_name,
                    action_type=action_type,
                    args_summary=args_summary,
                    timestamp=time.time(),
                    request_id=request_id,
                    mcp_service=service.name,
                    outcome="error",
                    error=str(exc),
                    principal_permission_grant=_permission_grant_field(principal),
                    duration_ms=duration * 1000.0,
                )
            )
            raise
        duration = time.perf_counter() - started

        _record_invocation(service.name, tool_name, action_type)
        metrics.tool_duration_seconds.labels(
            service=service.name, tool=tool_name, action_type=action_type
        ).observe(duration)
        await write_audit(
            AuditRecord(
                principal_sub=principal.subject,
                principal_uid=principal.uid,
                permission=service.required_permission,
                target=service.name,
                action=tool_name,
                action_type=action_type,
                args_summary=args_summary,
                timestamp=time.time(),
                request_id=request_id,
                mcp_service=service.name,
                outcome="success",
                principal_permission_grant=_permission_grant_field(principal),
                duration_ms=duration * 1000.0,
            )
        )
        return result
