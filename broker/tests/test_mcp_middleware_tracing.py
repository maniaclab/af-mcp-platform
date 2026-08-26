"""Span emission and the trace_id audit join key at the authorization seam.

The spans asserted here are the broker's own ``tools/call <tool>`` server
spans opened by ``AuthorizationMiddleware`` (see its module docstring for why
fastmcp's native span -- opened downstream of ``call_next`` -- cannot carry
the identity/outcome enrichment or cover the denied/unmapped paths). All
tests use a test-local ``TracerProvider`` injected through
``tracing._tracer_provider`` (see ``test_tracing.local_exporter``) so the
once-only OTel global is never touched.
"""
# ruff: noqa: F811 -- test parameters deliberately reuse the names of the
# fixtures re-exported from test_mcp_middleware_authorization/test_tracing;
# pyflakes reads that shadowing as a redefinition.

from __future__ import annotations

from typing import Any

import mcp.types as mt
import pytest
from fastmcp.exceptions import AuthorizationError
from fastmcp.tools.base import ToolResult
from opentelemetry.trace import SpanKind, StatusCode
from test_mcp_middleware_authorization import (
    _call_tool_context,
    _CallNextRecorder,
    _FakeFastMCPContext,
    _FakeMiddlewareContext,
    captured_audits,  # noqa: F401  -- fixture re-export
    policy,  # noqa: F401  -- fixture re-export
    registry,  # noqa: F401  -- fixture re-export
)
from test_tracing import (
    _TRACE_ID_HEX,
    _TRACEPARENT,
    local_exporter,  # noqa: F401  -- fixture re-export
)

from af_mcp_broker.mcp.middleware.authorization_mw import AuthorizationMiddleware


def _call_tool_context_with_meta(
    tool_name: str, arguments: dict[str, Any], principal: Any, meta: dict[str, Any]
) -> _FakeMiddlewareContext:
    """Like ``_call_tool_context`` but with an MCP ``_meta`` on the request --
    the SEP-414 carrier for the client's traceparent."""
    return _FakeMiddlewareContext(
        mt.CallToolRequestParams(name=tool_name, arguments=arguments, _meta=meta),
        _FakeFastMCPContext({"principal": principal}),
    )


async def test_success_call_emits_enriched_span(
    registry, policy, make_principal, captured_audits, local_exporter
) -> None:
    mw = AuthorizationMiddleware(registry, policy)
    principal = make_principal(groups=["atlas"])
    context = _call_tool_context("rucio_list_dids", {"scope": "x"}, principal)

    await mw.on_call_tool(context, _CallNextRecorder(result=ToolResult(content=[])))

    spans = local_exporter.get_finished_spans()
    assert len(spans) == 1
    span = spans[0]
    assert span.name == "tools/call rucio_list_dids"
    assert span.kind is SpanKind.SERVER
    attrs = dict(span.attributes)
    assert attrs["mcp.method.name"] == "tools/call"
    assert attrs["gen_ai.tool.name"] == "rucio_list_dids"
    assert attrs["user.id"] == principal.subject
    assert attrs["af.service"] == "rucio"
    assert attrs["af.permission"] == "read_data"
    assert attrs["af.action_type"] == "read"
    assert attrs["af.outcome"] == "success"
    assert span.status.status_code is StatusCode.UNSET
    # Payload privacy: arguments/results never become span attributes (same
    # keys-only posture as the audit log's args_summary).
    assert "gen_ai.tool.call.arguments" not in attrs
    assert "gen_ai.tool.call.result" not in attrs
    # Join key: the audit record carries the span's trace id.
    assert captured_audits[0].trace_id == format(span.context.trace_id, "032x")


async def test_denied_call_emits_denied_span(
    registry, policy, make_principal, captured_audits, local_exporter
) -> None:
    mw = AuthorizationMiddleware(registry, policy)
    principal = make_principal(groups=[])
    context = _call_tool_context("rucio_list_dids", {}, principal)

    with pytest.raises(AuthorizationError):
        await mw.on_call_tool(context, _CallNextRecorder())

    (span,) = local_exporter.get_finished_spans()
    attrs = dict(span.attributes)
    assert attrs["af.outcome"] == "denied"
    assert attrs["af.service"] == "rucio"
    assert attrs["af.permission"] == "read_data"
    # A denial is a policy outcome, not a system error.
    assert span.status.status_code is StatusCode.UNSET
    assert captured_audits[0].outcome == "denied"
    assert captured_audits[0].trace_id == format(span.context.trace_id, "032x")


async def test_unmapped_call_emits_denied_span(
    registry, policy, make_principal, captured_audits, local_exporter
) -> None:
    mw = AuthorizationMiddleware(registry, policy)
    principal = make_principal(groups=["atlas"])
    context = _call_tool_context("nosuch_tool", {}, principal)

    with pytest.raises(AuthorizationError):
        await mw.on_call_tool(context, _CallNextRecorder())

    (span,) = local_exporter.get_finished_spans()
    attrs = dict(span.attributes)
    assert attrs["af.outcome"] == "denied"
    assert attrs["af.permission"] == "__unmapped__"
    assert "af.service" not in attrs
    assert captured_audits[0].trace_id == format(span.context.trace_id, "032x")


async def test_error_call_emits_error_span_with_exception(
    registry, policy, make_principal, captured_audits, local_exporter
) -> None:
    mw = AuthorizationMiddleware(registry, policy)
    principal = make_principal(groups=["atlas"])
    context = _call_tool_context("rucio_list_dids", {}, principal)
    boom = RuntimeError("backend exploded")

    with pytest.raises(RuntimeError):
        await mw.on_call_tool(context, _CallNextRecorder(error=boom))

    (span,) = local_exporter.get_finished_spans()
    attrs = dict(span.attributes)
    assert attrs["af.outcome"] == "error"
    assert span.status.status_code is StatusCode.ERROR
    exception_events = [e for e in span.events if e.name == "exception"]
    assert len(exception_events) == 1
    assert exception_events[0].attributes["exception.message"] == "backend exploded"
    assert captured_audits[0].outcome == "error"
    assert captured_audits[0].trace_id == format(span.context.trace_id, "032x")


async def test_inbound_meta_traceparent_becomes_remote_parent(
    registry, policy, make_principal, captured_audits, local_exporter
) -> None:
    mw = AuthorizationMiddleware(registry, policy)
    principal = make_principal(groups=["atlas"])
    context = _call_tool_context_with_meta(
        "rucio_list_dids", {}, principal, {"traceparent": _TRACEPARENT}
    )

    await mw.on_call_tool(context, _CallNextRecorder(result=ToolResult(content=[])))

    (span,) = local_exporter.get_finished_spans()
    # The broker's span joins the client's trace (SEP-414): same trace id,
    # parented to the client's span, marked remote.
    assert format(span.context.trace_id, "032x") == _TRACE_ID_HEX
    assert span.parent is not None
    assert span.parent.is_remote
    assert format(span.parent.span_id, "016x") == "00f067aa0ba902b7"
    assert captured_audits[0].trace_id == _TRACE_ID_HEX


async def test_disabled_tracing_leaves_trace_id_none_on_every_path(
    registry, policy, make_principal, captured_audits
) -> None:
    """With no provider installed (default), every outcome path still works
    and its audit record carries trace_id=None."""
    mw = AuthorizationMiddleware(registry, policy)
    entitled = make_principal(groups=["atlas"])
    unentitled = make_principal(groups=[])

    await mw.on_call_tool(
        _call_tool_context("rucio_list_dids", {}, entitled),
        _CallNextRecorder(result=ToolResult(content=[])),
    )
    with pytest.raises(AuthorizationError):
        await mw.on_call_tool(
            _call_tool_context("rucio_list_dids", {}, unentitled),
            _CallNextRecorder(),
        )
    with pytest.raises(AuthorizationError):
        await mw.on_call_tool(
            _call_tool_context("nosuch_tool", {}, entitled), _CallNextRecorder()
        )
    with pytest.raises(RuntimeError):
        await mw.on_call_tool(
            _call_tool_context("rucio_list_dids", {}, entitled),
            _CallNextRecorder(error=RuntimeError("boom")),
        )

    assert [r.outcome for r in captured_audits] == [
        "success",
        "denied",
        "denied",
        "error",
    ]
    assert all(r.trace_id is None for r in captured_audits)
