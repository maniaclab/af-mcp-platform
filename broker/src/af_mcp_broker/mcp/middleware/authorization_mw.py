from __future__ import annotations

import time
import uuid
from typing import TYPE_CHECKING

import structlog
from fastmcp.exceptions import AuthorizationError
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext
from opentelemetry.trace import SpanKind, Status, StatusCode

from af_mcp_broker import metrics
from af_mcp_broker.audit import AuditRecord, write_audit
from af_mcp_broker.audit.pipeline import submit_metered_audit
from af_mcp_broker.authorization import (
    EntitlementPolicy,
    check_entitlement,
    get_action_type,
)
from af_mcp_broker.tracing import (
    current_trace_id,
    get_tracer,
    parent_context_from_meta,
)

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
#
# Tracing (observability roadmap PR D): this middleware also opens the
# broker's per-tool-call server span, enriched with identity/outcome
# attributes on every path (success/denied/unmapped/error) and stamped into
# each AuditRecord as the trace_id join key -- see the comment above the
# span below for why fastmcp 3.4.4's own tools/call span can't serve that
# role. Propagation invariant: inbound trace context (the SEP-414 ``_meta``
# traceparent) is parsed as a REMOTE PARENT and never forwarded verbatim;
# outbound context toward backend MCP servers is broker-generated -- the
# aggregator's fastmcp Client injects the broker's then-current span context
# into the outbound request's ``_meta``, never into HTTP headers (see
# aggregator.py's no-header-forwarding invariant). All of this no-ops when
# tracing is disabled (tracing.py installs no provider).


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

        # The broker's own af_* methods (issue #153) take this same path:
        # the prefix maps to the builtin af-mcp service (issue #240), whose
        # "__none__" permission passes check_entitlement for any
        # authenticated principal -- they must keep answering precisely when
        # a service or its credential provider is broken, and an entitlement
        # check against "__none__" touches neither. Unlike issue #153's
        # name-based bypass, the calls are now audited and metered
        # (service=af-mcp) like everything else; the one builtin difference
        # is the authorized_call_target guard below.
        service = self.registry.get_by_tool_prefix(tool_name)
        request_id = str(uuid.uuid4())
        args_summary = ", ".join(f"{k}=..." for k in list(tool_args.keys())[:10])

        # The broker's per-tool-call server span (OTel MCP semconv name
        # "tools/call <name>"). fastmcp 3.4.4 opens a span of the same name
        # itself, but only inside call_next (FastMCP.call_tool's core logic,
        # downstream of every middleware), so that one (a) never exists for
        # the denied/unmapped paths below, which raise before call_next, and
        # (b) is already closed when call_next returns -- unreachable from
        # here for the identity/outcome enrichment and for the trace_id the
        # audit records capture. This span wraps it instead: fastmcp's
        # becomes a child, and the inbound SEP-414 ``_meta`` traceparent --
        # parsed here as a remote parent, exactly what fastmcp's own
        # extractor would have done had no span been active yet -- still
        # chains the client's trace through. Exception recording is explicit
        # on the error path below (a denial raises through this block too,
        # but is a policy outcome, not a span error), hence the two disabled
        # flags. Payload privacy: tool arguments/results never become span
        # attributes -- same keys-only posture as args_summary above.
        with get_tracer().start_as_current_span(
            f"tools/call {tool_name}",
            context=parent_context_from_meta(context.message.meta),
            kind=SpanKind.SERVER,
            record_exception=False,
            set_status_on_exception=False,
        ) as span:
            if span.is_recording():
                span.set_attributes(
                    {
                        "mcp.method.name": "tools/call",
                        "gen_ai.tool.name": tool_name,
                        # Semconv successor to enduser.id.
                        "user.id": principal.subject,
                    }
                )

            if service is None:
                # tool_name is client-supplied and matches no configured
                # service prefix here, so it must never become a label value
                # (unbounded cardinality) -- count it in the label-free
                # unmapped counter instead. See metrics.py's cardinality policy.
                metrics.tool_invocations_unmapped_total.inc()
                if span.is_recording():
                    # No af.service -- nothing mapped; mirror the audit
                    # record's "__unmapped__" permission sentinel instead.
                    span.set_attributes(
                        {
                            "af.permission": "__unmapped__",
                            "af.action_type": "read",
                            "af.outcome": "denied",
                        }
                    )
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
                        token_id=principal.token_id,
                        trace_id=current_trace_id(),
                    )
                )
                raise AuthorizationError(
                    f"No service registered for tool '{tool_name}'"
                )

            action_type = get_action_type(
                service.name, tool_name, service.required_permission, self.policy
            )
            allow, reason = check_entitlement(
                principal, service.required_permission, service.name, self.policy
            )
            if span.is_recording():
                span.set_attributes(
                    {"af.service": service.name, "af.action_type": action_type}
                )
                if service.required_permission is not None:
                    # None means the credential layer is the sole gate
                    # (issue #60) -- there is no permission name to record.
                    span.set_attribute("af.permission", service.required_permission)
            if not allow:
                # A denial is still an attempted invocation for the coarse
                # counters, plus its own isolated denied counter -- see
                # metrics.py's cardinality policy for why outcome isn't a label
                # on tool_invocations_total itself.
                _record_invocation(service.name, tool_name, action_type)
                metrics.tool_invocations_denied_total.labels(
                    service=service.name, action_type=action_type
                ).inc()
                span.set_attribute("af.outcome", "denied")
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
                        token_id=principal.token_id,
                        trace_id=current_trace_id(),
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
            # leaks into a later, unrelated request. Never stamped for the
            # builtin af-mcp service: its methods are the FastMCP server's own
            # local tools -- no credential to mint, nothing to forward -- so
            # there is no client_factory for this signal to reach (issue #240).
            if not service.builtin:
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
                if span.is_recording():
                    span.set_attribute("af.outcome", "error")
                    span.record_exception(exc)
                    span.set_status(Status(StatusCode.ERROR, str(exc)))
                # Routed through the metering pipeline (result=None -- an error
                # produced no result to measure) so the error response is not
                # held by audit I/O either.
                await submit_metered_audit(
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
                        token_id=principal.token_id,
                        duration_ms=duration * 1000.0,
                        trace_id=current_trace_id(),
                    ),
                    None,
                )
                raise
            duration = time.perf_counter() - started
            _record_invocation(service.name, tool_name, action_type)
            metrics.tool_duration_seconds.labels(
                service=service.name, tool=tool_name, action_type=action_type
            ).observe(duration)
            span.set_attribute("af.outcome", "success")
            # The result measurement -- an estimate of its context-injection
            # cost, not wire size; see measure_tool_result's docstring for
            # exactly what is serialized and counted -- happens on the metering
            # pipeline's background worker (audit/pipeline.py), never here:
            # serializing and tokenizing a large result can cost tens of ms,
            # and the tool call must not wait on it (nor on the audit write).
            # The record is handed over with result_bytes/result_tokens_est
            # still None for the worker to fill. Success path only: an error
            # produced no result to measure (result=None above).
            await submit_metered_audit(
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
                    token_id=principal.token_id,
                    duration_ms=duration * 1000.0,
                    trace_id=current_trace_id(),
                ),
                result,
            )
            return result
