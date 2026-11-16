from __future__ import annotations

import json
import uuid
from typing import TYPE_CHECKING, Any

import httpx2
import mcp.types as mt
import pytest
import structlog.testing
from broker_state_helpers import authorization_middleware
from fastmcp.exceptions import AuthorizationError, ToolError
from fastmcp.tools.base import ToolResult
from prometheus_client import REGISTRY
from test_request_logging import _capturing_info

from af_mcp_broker import metering as pipeline
from af_mcp_broker import retry_after as retry_after_module
from af_mcp_broker import shared_state
from af_mcp_broker.audit.measure import ContentMeasure, ToolMeasurement
from af_mcp_broker.authorization import EntitlementPolicy, RateLimitRule
from af_mcp_broker.authorization.errors import ToolRateLimitError
from af_mcp_broker.config import Settings
from af_mcp_broker.mcp.middleware import authorization_mw
from af_mcp_broker.mcp.middleware.authorization_mw import AuthorizationMiddleware
from af_mcp_broker.metering import InlineMeteringBackend, InProcessMeteringBackend
from af_mcp_broker.service_registry import (
    DIAGNOSTIC_TOOL_NAMES,
    ServiceRegistry,
    ServiceSpec,
)
from af_mcp_broker.shared_state import (
    InMemorySharedState,
    RedisSharedState,
    WindowCount,
)
from af_mcp_broker.usage import InMemoryUsageStore

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from af_mcp_broker.audit import AuditRecord
    from af_mcp_broker.principal import Principal


def _sample(name: str, labels: dict[str, str]) -> float:
    return REGISTRY.get_sample_value(name, labels) or 0.0


class _FakeFastMCPContext:
    def __init__(self, state: dict[str, Any]) -> None:
        self._state = state

    async def get_state(self, key: str) -> Any:
        return self._state.get(key)

    async def set_state(
        self, key: str, value: Any, *, serializable: bool = True
    ) -> None:
        self._state[key] = value


class _FakeMiddlewareContext:
    def __init__(
        self,
        message: mt.CallToolRequestParams,
        fastmcp_context: _FakeFastMCPContext | None,
    ) -> None:
        self.message = message
        self.fastmcp_context = fastmcp_context


def _call_tool_context(
    tool_name: str, arguments: dict[str, Any], principal: Any
) -> _FakeMiddlewareContext:
    fastmcp_ctx = (
        _FakeFastMCPContext({"principal": principal})
        if principal is not None
        else _FakeFastMCPContext({})
    )
    return _FakeMiddlewareContext(
        mt.CallToolRequestParams(name=tool_name, arguments=arguments),
        fastmcp_ctx,
    )


@pytest.fixture
def registry() -> ServiceRegistry:
    reg = ServiceRegistry()
    reg.register(
        ServiceSpec(
            name="rucio",
            prefix="rucio",
            url="http://rucio.invalid/mcp",
            transport="http",
            required_permission="read_data",
            apply_namespace=False,
        )
    )
    reg.register(
        ServiceSpec(
            name="docs",
            prefix="docs",
            url="http://docs.invalid/mcp",
            transport="http",
            required_permission="__none__",
        )
    )
    reg.register(
        ServiceSpec(
            name="credentialed",
            prefix="credentialed",
            url="http://credentialed.invalid/mcp",
            transport="http",
            # Omitted required_permission -- the credential layer is the
            # gate instead (issue #60).
        )
    )
    reg.register(
        ServiceSpec(
            name="condor_service",
            prefix="condor",
            url="http://condor.invalid/mcp",
            transport="http",
            required_permission={
                "__default__": "manage_jobs",
                "query_jobs": "read_monitoring",
            },
        )
    )
    return reg


@pytest.fixture
def policy() -> EntitlementPolicy:
    return EntitlementPolicy(
        group_permissions={
            "atlas": ["read_data", "read_monitoring"],
            "af-admins": ["read_monitoring", "manage_jobs"],
            "__authenticated__": [],
        },
        target_action_types={"rucio": {"rucio_list_dids": "read"}},
    )


class _CallNextRecorder:
    """Records whether call_next was invoked -- credential minting and the
    actual backend call both happen inside call_next (via the aggregator's
    client_factory), so asserting this was never reached is how a denial
    test proves the credential provider was never touched."""

    def __init__(self, result: Any = None, error: Exception | None = None) -> None:
        self.called = False
        self._result = result
        self._error = error

    async def __call__(self, context: Any) -> Any:
        self.called = True
        if self._error is not None:
            raise self._error
        return self._result


@pytest.fixture
def captured_audits(monkeypatch: pytest.MonkeyPatch) -> list[AuditRecord]:
    records: list[AuditRecord] = []

    async def _fake_write_audit(record: AuditRecord) -> None:
        records.append(record)

    monkeypatch.setattr(authorization_mw, "write_audit", _fake_write_audit)
    # Success/error records flow through the metering backend, whose inline
    # implementation (the one these tests build) measures and writes via
    # pipeline.write_audit -- patch that too so every audit path in the
    # middleware lands here.
    monkeypatch.setattr(pipeline, "write_audit", _fake_write_audit)
    return records


async def test_is_error_result_audits_as_error_not_success(
    registry, policy, make_principal, captured_audits
) -> None:
    """A tool that signals failure via the MCP isError result convention
    (e.g. a downstream backend's ToolError, which the MCP SDK converts to an
    isError=True result rather than propagating as an exception the client
    library re-raises here) must never be audited as a success just because
    call_next didn't raise -- see _tool_result_error_text's docstring for
    the real-world case this went undetected in."""
    mw = authorization_middleware(registry, policy)
    principal = make_principal(groups=["atlas"])
    context = _call_tool_context("rucio_list_dids", {"scope": "foo"}, principal)
    fake_result = ToolResult(
        content=[mt.TextContent(type="text", text="backend proxy redeem failed")],
        is_error=True,
    )
    call_next = _CallNextRecorder(result=fake_result)

    result = await mw.on_call_tool(context, call_next)

    assert result is fake_result
    assert call_next.called is True
    assert len(captured_audits) == 1
    record = captured_audits[0]
    assert record.outcome == "error"
    assert record.error == "backend proxy redeem failed"
    # Distinct from a raised exception's "backend_error" (see
    # ERROR_CLASS_TOOL_REPORTED's docstring): the RPC completed normally
    # here, unlike test_call_next_failure_audited_as_error_and_reraised's
    # own plumbing failure.
    assert record.error_class == "tool_reported"
    assert record.target == "rucio"
    assert record.action == "rucio_list_dids"


async def test_error_counter_by_service_and_error_class(
    registry, policy, make_principal, captured_audits
) -> None:
    """Every outcome="error" audit record also increments the error counter
    under the record's own error_class -- a raised backend failure, a
    transient connection drop, and an isError result each land in their own
    series, and the isError result is observed under outcome="error" on the
    latency histogram (it returned normally, so only is_error tells it apart)."""
    mw = authorization_middleware(registry, policy)
    principal = make_principal(groups=["atlas"])
    context = _call_tool_context("rucio_list_dids", {}, principal)

    def errors(error_class: str) -> float:
        return _sample(
            "af_mcp_tool_invocation_errors_total",
            {"service": "rucio", "error_class": error_class},
        )

    duration_labels = {
        "service": "rucio",
        "tool": "rucio_list_dids",
        "action_type": "read",
        "outcome": "error",
    }
    before = {c: errors(c) for c in ("backend_error", "transient_connection")}
    before_tool_reported = errors("tool_reported")
    before_hist = _sample("af_mcp_tool_duration_seconds_count", duration_labels)

    with pytest.raises(RuntimeError):
        await mw.on_call_tool(context, _CallNextRecorder(error=RuntimeError("boom")))
    with pytest.raises(ConnectionResetError):
        await mw.on_call_tool(
            context, _CallNextRecorder(error=ConnectionResetError("reset"))
        )
    await mw.on_call_tool(
        context,
        _CallNextRecorder(
            result=ToolResult(
                content=[mt.TextContent(type="text", text="nope")], is_error=True
            )
        ),
    )

    assert [r.error_class for r in captured_audits] == [
        "backend_error",
        "transient_connection",
        "tool_reported",
    ]
    assert errors("backend_error") == before["backend_error"] + 1
    assert errors("transient_connection") == before["transient_connection"] + 1
    assert errors("tool_reported") == before_tool_reported + 1
    assert (
        _sample("af_mcp_tool_duration_seconds_count", duration_labels)
        == before_hist + 3
    )


async def test_success_does_not_touch_error_counter(
    registry, policy, make_principal, captured_audits
) -> None:
    mw = authorization_middleware(registry, policy)
    principal = make_principal(groups=["atlas"])
    context = _call_tool_context("rucio_list_dids", {}, principal)
    before = sum(
        s.value
        for m in REGISTRY.collect()
        if m.name == "af_mcp_tool_invocation_errors"
        for s in m.samples
        if s.name.endswith("_total")
    )

    await mw.on_call_tool(context, _CallNextRecorder(result=ToolResult(content=[])))

    after = sum(
        s.value
        for m in REGISTRY.collect()
        if m.name == "af_mcp_tool_invocation_errors"
        for s in m.samples
        if s.name.endswith("_total")
    )
    assert after == before


async def test_entitled_call_proceeds_and_audits_success(
    registry, policy, make_principal, captured_audits
) -> None:
    mw = authorization_middleware(registry, policy)
    principal = make_principal(groups=["atlas"])
    context = _call_tool_context("rucio_list_dids", {"scope": "foo"}, principal)
    fake_result = ToolResult(content=[])
    call_next = _CallNextRecorder(result=fake_result)

    result = await mw.on_call_tool(context, call_next)

    assert result is fake_result
    assert call_next.called is True
    assert len(captured_audits) == 1
    record = captured_audits[0]
    assert record.outcome == "success"
    assert record.error is None
    assert record.permission == "read_data"
    assert record.target == "rucio"
    assert record.action == "rucio_list_dids"
    assert record.action_type == "read"
    assert record.mcp_service == "rucio"
    assert record.principal_uid == principal.uid
    assert record.principal_sub == principal.subject
    # The client_factory (aggregator.py) reads this to distinguish a genuine
    # tools/call from a tools/list schema-cache refresh sharing the same
    # client_factory -- it must be set before call_next() reaches the
    # factory.
    assert await context.fastmcp_context.get_state("authorized_call_target") == "rucio"


async def test_unentitled_call_denied_before_call_next(
    registry, policy, make_principal, captured_audits
) -> None:
    mw = authorization_middleware(registry, policy)
    principal = make_principal(groups=[])
    context = _call_tool_context("rucio_list_dids", {}, principal)
    call_next = _CallNextRecorder()

    with pytest.raises(AuthorizationError):
        await mw.on_call_tool(context, call_next)

    assert call_next.called is False
    assert len(captured_audits) == 1
    record = captured_audits[0]
    assert record.outcome == "denied"
    assert record.error is not None
    assert record.target == "rucio"


@pytest.mark.parametrize("tool_name", sorted(DIAGNOSTIC_TOOL_NAMES))
async def test_af_method_call_flows_through_the_builtin_service(
    registry, policy, make_principal, captured_audits, tool_name
) -> None:
    """Issue #240: an af_* call routes by prefix to the builtin af-mcp
    service like any other tool -- no name-based bypass. Its "__none__"
    permission passes for a principal with no groups at all (af_whoami/
    af_link_identity are the bootstrap methods a zero-permission caller
    needs), and unlike issue #153's bypass the call is audited and
    metered with service=af-mcp."""
    mw = authorization_middleware(registry, policy)
    principal = make_principal(groups=[])
    context = _call_tool_context(tool_name, {}, principal)
    fake_result = ToolResult(content=[])
    call_next = _CallNextRecorder(result=fake_result)

    result = await mw.on_call_tool(context, call_next)

    assert result is fake_result
    assert call_next.called is True
    assert len(captured_audits) == 1
    record = captured_audits[0]
    assert record.outcome == "success"
    assert record.mcp_service == "gateway_service"
    assert record.target == "gateway_service"
    assert record.action == tool_name
    assert record.permission == "__none__"
    assert record.duration_ms is not None


@pytest.mark.parametrize("tool_name", sorted(DIAGNOSTIC_TOOL_NAMES))
async def test_af_method_call_never_sets_authorized_call_target(
    registry, policy, make_principal, captured_audits, tool_name
) -> None:
    """A builtin call must not stamp authorized_call_target: that state
    exists solely to tell the aggregator's client_factory to mint a per-user
    credential for a proxied service, and the builtin af-mcp service has no
    credential and no forwarding -- the FastMCP server dispatches its own
    registered tools locally."""
    mw = authorization_middleware(registry, policy)
    principal = make_principal(groups=[])
    context = _call_tool_context(tool_name, {}, principal)
    call_next = _CallNextRecorder(result=ToolResult(content=[]))

    await mw.on_call_tool(context, call_next)

    state = await context.fastmcp_context.get_state("authorized_call_target")
    assert state is None


async def test_unentitled_call_denied_audit_carries_no_permission_grant_when_not_a_permission_pat(
    registry, policy, make_principal, captured_audits
) -> None:
    """The common case (a JWT, or an identity PAT -- permission_grant=None)
    must not fabricate a grant in the audit record."""
    mw = authorization_middleware(registry, policy)
    principal = make_principal(groups=[])
    context = _call_tool_context("rucio_list_dids", {}, principal)
    call_next = _CallNextRecorder()

    with pytest.raises(AuthorizationError):
        await mw.on_call_tool(context, call_next)

    assert captured_audits[0].principal_permission_grant is None


async def test_denied_call_audit_carries_the_scoped_pats_permission_grant(
    registry, policy, make_principal, captured_audits
) -> None:
    """Issue #144 step 4: a denied call from a permission PAT must record
    that PAT's effective permission_grant in the audit line, so an admin can
    tell "the principal doesn't hold read_data at all" apart from "the
    principal holds it, but this PAT is scoped away from it" -- the whole
    point of this field (see AuditRecord.principal_permission_grant's
    docstring)."""
    mw = authorization_middleware(registry, policy)
    # In the "atlas" group (which read_data below would normally grant), but
    # this particular PAT is scoped to submit_jobs only -- read_data is
    # denied even though the principal's groups would otherwise allow it.
    principal = make_principal(
        groups=["atlas"], permission_grant=frozenset({"submit_jobs"})
    )
    context = _call_tool_context("rucio_list_dids", {}, principal)
    call_next = _CallNextRecorder()

    with pytest.raises(AuthorizationError):
        await mw.on_call_tool(context, call_next)

    assert captured_audits[0].outcome == "denied"
    assert captured_audits[0].principal_permission_grant == ["submit_jobs"]


async def test_audit_token_id_copied_on_all_four_outcome_paths(
    registry, policy, make_principal, captured_audits
) -> None:
    """Issue #247: per-token attribution -- every audit outcome path
    (success, denied, unmapped, error) must copy the calling PAT's public
    lookup_id from Principal.token_id into the record, so a leaked PAT's
    calls can be isolated (and that one token revoked) without guessing
    among the owner's other tokens."""
    mw = authorization_middleware(registry, policy)
    principal = make_principal(groups=["atlas"], token_id="pat-lookup-1")

    # success
    await mw.on_call_tool(
        _call_tool_context("rucio_list_dids", {}, principal),
        _CallNextRecorder(result=ToolResult(content=[])),
    )
    # denied (same token, a principal whose groups grant nothing)
    unentitled = make_principal(groups=[], token_id="pat-lookup-1")
    with pytest.raises(AuthorizationError):
        await mw.on_call_tool(
            _call_tool_context("rucio_list_dids", {}, unentitled),
            _CallNextRecorder(),
        )
    # unmapped
    with pytest.raises(AuthorizationError):
        await mw.on_call_tool(
            _call_tool_context("mystery_tool", {}, principal), _CallNextRecorder()
        )
    # error downstream of authorization
    with pytest.raises(RuntimeError):
        await mw.on_call_tool(
            _call_tool_context("rucio_list_dids", {}, principal),
            _CallNextRecorder(error=RuntimeError("boom")),
        )

    assert [r.outcome for r in captured_audits] == [
        "success",
        "denied",
        "denied",
        "error",
    ]
    assert all(r.token_id == "pat-lookup-1" for r in captured_audits)


async def test_jwt_call_audit_token_id_is_none(
    registry, policy, make_principal, captured_audits
) -> None:
    """A session JWT resolves to Principal.token_id=None (the default), so
    its audit lines carry token_id null -- only a PAT ever attributes a call
    to a specific token (issue #247)."""
    mw = authorization_middleware(registry, policy)
    principal = make_principal(groups=["atlas"])
    await mw.on_call_tool(
        _call_tool_context("rucio_list_dids", {}, principal),
        _CallNextRecorder(result=ToolResult(content=[])),
    )

    assert captured_audits[0].token_id is None


async def test_unknown_tool_prefix_denied(
    registry, policy, make_principal, captured_audits
) -> None:
    mw = authorization_middleware(registry, policy)
    principal = make_principal(groups=["atlas"])
    context = _call_tool_context("mystery_tool", {}, principal)
    call_next = _CallNextRecorder()

    with pytest.raises(AuthorizationError):
        await mw.on_call_tool(context, call_next)

    assert call_next.called is False
    assert len(captured_audits) == 1
    assert captured_audits[0].outcome == "denied"


async def test_open_target_requires_no_permission(
    registry, policy, make_principal, captured_audits
) -> None:
    mw = authorization_middleware(registry, policy)
    principal = make_principal(groups=[])
    context = _call_tool_context("docs_search", {}, principal)
    fake_result = ToolResult(content=[])
    call_next = _CallNextRecorder(result=fake_result)

    result = await mw.on_call_tool(context, call_next)

    assert result is fake_result
    assert captured_audits[0].outcome == "success"


async def test_omitted_permission_target_requires_no_permission(
    registry, policy, make_principal, captured_audits
) -> None:
    """A backend that omits required_permission has no permission gate --
    the credential layer gates it instead (issue #60) -- so any
    authenticated principal, regardless of groups, must pass this check."""
    mw = authorization_middleware(registry, policy)
    principal = make_principal(groups=[])
    context = _call_tool_context("credentialed_ping", {}, principal)
    fake_result = ToolResult(content=[])
    call_next = _CallNextRecorder(result=fake_result)

    result = await mw.on_call_tool(context, call_next)

    assert result is fake_result
    assert captured_audits[0].outcome == "success"


async def test_missing_principal_fails_closed_without_audit(
    registry, policy, captured_audits
) -> None:
    """identity_mw (registered first / outermost) should always have set the
    principal by the time this runs; if it somehow didn't, fail closed --
    mirroring entitlement_mw's identical defensive branch -- without
    fabricating an audit record for a principal we don't have."""
    mw = authorization_middleware(registry, policy)
    context = _call_tool_context("rucio_list_dids", {}, None)
    call_next = _CallNextRecorder()

    with pytest.raises(AuthorizationError):
        await mw.on_call_tool(context, call_next)

    assert call_next.called is False
    assert captured_audits == []


async def test_missing_fastmcp_context_fails_closed(
    registry, policy, captured_audits
) -> None:
    mw = authorization_middleware(registry, policy)
    context = _FakeMiddlewareContext(
        mt.CallToolRequestParams(name="rucio_list_dids", arguments={}), None
    )
    call_next = _CallNextRecorder()

    with pytest.raises(AuthorizationError):
        await mw.on_call_tool(context, call_next)

    assert call_next.called is False
    assert captured_audits == []


async def test_call_next_failure_audited_as_error_and_reraised(
    registry, policy, make_principal, captured_audits
) -> None:
    """A failure downstream of authorization -- e.g. the client_factory's
    credential resolution, or the backend call itself -- must still produce
    exactly one audit line, recorded as an error rather than silently
    dropped, and the original exception must propagate unchanged."""
    mw = authorization_middleware(registry, policy)
    principal = make_principal(groups=["atlas"])
    context = _call_tool_context("rucio_list_dids", {}, principal)
    boom = RuntimeError("credential provider unreachable")
    call_next = _CallNextRecorder(error=boom)

    with pytest.raises(RuntimeError, match="credential provider unreachable"):
        await mw.on_call_tool(context, call_next)

    assert call_next.called is True
    assert len(captured_audits) == 1
    record = captured_audits[0]
    assert record.outcome == "error"
    assert record.error == "credential provider unreachable"
    # A plain downstream failure is a genuine backend/tool error, not a
    # transient connection drop (issue #216 A.3).
    assert record.error_class == "backend_error"


def _tool_error_from_transient() -> ToolError:
    """A ToolError chained from a transient connection exception, exactly as
    fastmcp's core call_tool re-raises one (``ToolError(...) from e``) when a
    broker->backend call's socket fails mid-response. Setting ``__cause__``
    directly is what ``raise ... from`` records."""
    err = ToolError("Error calling tool 'ami_get_dataset_info'")
    err.__cause__ = httpx2.RemoteProtocolError(
        "Server disconnected -- Closed Connection"
    )
    return err


async def test_transient_connection_failure_audited_with_error_class(
    registry, policy, make_principal, captured_audits
) -> None:
    """A backend call whose connection drops (reset / socket EOF / connect
    timeout) is audited outcome=error with error_class="transient_connection"
    -- observability only, the exception still propagates unchanged (issue
    #216 A.3)."""
    mw = authorization_middleware(registry, policy)
    principal = make_principal(groups=["atlas"])
    context = _call_tool_context("rucio_list_dids", {}, principal)
    call_next = _CallNextRecorder(error=_tool_error_from_transient())

    with pytest.raises(ToolError):
        await mw.on_call_tool(context, call_next)

    assert len(captured_audits) == 1
    record = captured_audits[0]
    assert record.outcome == "error"
    assert record.error_class == "transient_connection"


async def test_success_carries_no_error_class(
    registry, policy, make_principal, captured_audits
) -> None:
    """A success is not a failed call, so error_class stays None (issue #216
    A.3's two-value-plus-null shape)."""
    mw = authorization_middleware(registry, policy)
    principal = make_principal(groups=["atlas"])
    context = _call_tool_context("rucio_list_dids", {"scope": "foo"}, principal)
    call_next = _CallNextRecorder(result=ToolResult(content=[]))

    await mw.on_call_tool(context, call_next)

    assert captured_audits[0].outcome == "success"
    assert captured_audits[0].error_class is None


async def test_denied_call_carries_no_error_class(
    registry, policy, make_principal, captured_audits
) -> None:
    """A denial never executed a backend call, so error_class stays None --
    it is an authorization outcome, not a backend failure (issue #216 A.3)."""
    mw = authorization_middleware(registry, policy)
    principal = make_principal(groups=[])
    context = _call_tool_context("rucio_list_dids", {}, principal)
    call_next = _CallNextRecorder()

    with pytest.raises(AuthorizationError):
        await mw.on_call_tool(context, call_next)

    assert captured_audits[0].outcome == "denied"
    assert captured_audits[0].error_class is None


async def test_success_records_duration_and_observes_histogram(
    registry, policy, make_principal, captured_audits
) -> None:
    """A successful call must meter the downstream call's wall time into
    both the audit record (duration_ms) and the duration histogram."""
    mw = authorization_middleware(registry, policy)
    principal = make_principal(groups=["atlas"])
    context = _call_tool_context("rucio_list_dids", {"scope": "foo"}, principal)
    call_next = _CallNextRecorder(result=ToolResult(content=[]))

    labels = {
        "service": "rucio",
        "tool": "rucio_list_dids",
        "action_type": "read",
        "outcome": "success",
    }
    before_count = _sample("af_mcp_tool_duration_seconds_count", labels)

    await mw.on_call_tool(context, call_next)

    record = captured_audits[0]
    assert record.outcome == "success"
    assert record.duration_ms is not None
    assert record.duration_ms >= 0.0
    assert _sample("af_mcp_tool_duration_seconds_count", labels) == before_count + 1


async def test_success_records_result_bytes_and_tokens(
    registry, policy, make_principal, captured_audits, monkeypatch
) -> None:
    """The success path measures the result via audit.measure (in the
    metering pipeline -- metering.py -- not on the hot path) and
    records both fields; the measurement sees the very ToolResult call_next
    returned."""
    mw = authorization_middleware(registry, policy)
    principal = make_principal(groups=["atlas"])
    context = _call_tool_context("rucio_list_dids", {"scope": "foo"}, principal)
    fake_result = ToolResult(content=[mt.TextContent(type="text", text="hello")])
    call_next = _CallNextRecorder(result=fake_result)

    measured: list[Any] = []

    def _fake_measure(result: Any, _settings: Any) -> ToolMeasurement:
        measured.append(result)
        return ToolMeasurement(
            content={"text": ContentMeasure(blocks=1, bytes=5, tokens_est=2)}
        )

    monkeypatch.setattr(pipeline, "measure_tool_result", _fake_measure)

    await mw.on_call_tool(context, call_next)

    assert measured == [fake_result]
    record = captured_audits[0]
    assert record.result_bytes == 5
    assert record.result_tokens_est == 2
    assert record.result_content == {
        "text": ContentMeasure(blocks=1, bytes=5, tokens_est=2)
    }


async def test_call_next_failure_records_duration_but_no_result_fields(
    registry, policy, make_principal, captured_audits
) -> None:
    """An error downstream still has a measurable duration (the call ran and
    failed), but produced no result to measure."""
    mw = authorization_middleware(registry, policy)
    principal = make_principal(groups=["atlas"])
    context = _call_tool_context("rucio_list_dids", {}, principal)
    call_next = _CallNextRecorder(error=RuntimeError("boom"))

    labels = {
        "service": "rucio",
        "tool": "rucio_list_dids",
        "action_type": "read",
        "outcome": "error",
    }
    before_count = _sample("af_mcp_tool_duration_seconds_count", labels)

    with pytest.raises(RuntimeError):
        await mw.on_call_tool(context, call_next)

    record = captured_audits[0]
    assert record.outcome == "error"
    assert record.duration_ms is not None
    assert record.duration_ms >= 0.0
    assert record.result_bytes is None
    assert record.result_tokens_est is None
    # The histogram observes errors too, under outcome="error".
    assert _sample("af_mcp_tool_duration_seconds_count", labels) == before_count + 1


async def test_denied_call_leaves_metering_fields_none(
    registry, policy, make_principal, captured_audits
) -> None:
    """A denial never reaches call_next -- nothing executed, so there is no
    duration and no result to measure."""
    mw = authorization_middleware(registry, policy)
    principal = make_principal(groups=[])
    context = _call_tool_context("rucio_list_dids", {}, principal)
    call_next = _CallNextRecorder()

    with pytest.raises(AuthorizationError):
        await mw.on_call_tool(context, call_next)

    record = captured_audits[0]
    assert record.outcome == "denied"
    assert record.duration_ms is None
    assert record.result_bytes is None
    assert record.result_tokens_est is None


# ---------------------------------------------------------------------------
# Per-tool required_permission (dict form): different tools of the same
# service can require different permissions, with an optional "__default__"
# fallback -- an unlisted tool with no default is disabled for everyone.
# ---------------------------------------------------------------------------


async def test_dict_form_permission_allows_the_tool_it_names(
    registry, policy, make_principal, captured_audits
) -> None:
    mw = authorization_middleware(registry, policy)
    principal = make_principal(
        groups=["atlas"]
    )  # holds read_monitoring, not manage_jobs
    context = _call_tool_context("condor_query_jobs", {}, principal)
    fake_result = ToolResult(content=[])
    call_next = _CallNextRecorder(result=fake_result)

    result = await mw.on_call_tool(context, call_next)

    assert result is fake_result
    assert captured_audits[0].outcome == "success"
    assert captured_audits[0].permission == "read_monitoring"


async def test_dict_form_permission_falls_back_to_default_for_other_tools(
    registry, policy, make_principal, captured_audits
) -> None:
    """condor_submit_job isn't an explicit key -- it falls back to
    __default__ (manage_jobs), which this atlas principal doesn't hold."""
    mw = authorization_middleware(registry, policy)
    principal = make_principal(groups=["atlas"])
    context = _call_tool_context("condor_submit_job", {}, principal)
    call_next = _CallNextRecorder()

    with pytest.raises(AuthorizationError):
        await mw.on_call_tool(context, call_next)

    assert captured_audits[0].outcome == "denied"
    assert captured_audits[0].permission == "manage_jobs"


async def test_dict_form_permission_grants_default_to_a_holder(
    registry, policy, make_principal, captured_audits
) -> None:
    mw = authorization_middleware(registry, policy)
    principal = make_principal(groups=["af-admins"])
    context = _call_tool_context("condor_submit_job", {}, principal)
    fake_result = ToolResult(content=[])
    call_next = _CallNextRecorder(result=fake_result)

    result = await mw.on_call_tool(context, call_next)

    assert result is fake_result
    assert captured_audits[0].outcome == "success"


async def test_dict_form_permission_without_default_disables_unlisted_tool(
    registry, policy, make_principal, captured_audits
) -> None:
    """A separate dict-form service with no __default__: an admin holding
    every permission still can't call an unlisted tool -- opt-in only."""
    reg = ServiceRegistry()
    reg.register(
        ServiceSpec(
            name="strict_service",
            prefix="strict",
            url="http://strict.invalid/mcp",
            transport="http",
            required_permission={"read_thing": "read_monitoring"},
        )
    )
    mw = authorization_middleware(reg, policy)
    principal = make_principal(groups=["af-admins"])
    context = _call_tool_context("strict_unlisted_tool", {}, principal)
    call_next = _CallNextRecorder()

    with pytest.raises(AuthorizationError):
        await mw.on_call_tool(context, call_next)

    assert captured_audits[0].outcome == "denied"
    assert captured_audits[0].permission == "__disabled__"
    assert call_next.called is False


# ---------------------------------------------------------------------------
# Prometheus invocation counters (issue #83 asked for per-identity counters;
# Giordon declined that -- the audit log above already carries identity at
# full fidelity behind access control, so these counters are backend/tool
# only, incremented next to write_audit() above)
# ---------------------------------------------------------------------------


async def test_entitled_call_increments_invocation_counters(
    registry, policy, make_principal, captured_audits
) -> None:
    mw = authorization_middleware(registry, policy)
    principal = make_principal(groups=["atlas"])
    context = _call_tool_context("rucio_list_dids", {"scope": "foo"}, principal)
    call_next = _CallNextRecorder(result=ToolResult(content=[]))

    before_total = _sample(
        "af_mcp_tool_invocations_total",
        {"service": "rucio", "tool": "rucio_list_dids", "action_type": "read"},
    )
    before_denied = _sample(
        "af_mcp_tool_invocations_denied_total",
        {"service": "rucio", "action_type": "read"},
    )

    await mw.on_call_tool(context, call_next)

    assert (
        _sample(
            "af_mcp_tool_invocations_total",
            {"service": "rucio", "tool": "rucio_list_dids", "action_type": "read"},
        )
        == before_total + 1
    )
    # A successful call must not also count as a denial.
    assert (
        _sample(
            "af_mcp_tool_invocations_denied_total",
            {"service": "rucio", "action_type": "read"},
        )
        == before_denied
    )


async def test_unentitled_call_increments_invocation_and_denied_counters(
    registry, policy, make_principal, captured_audits
) -> None:
    mw = authorization_middleware(registry, policy)
    principal = make_principal(groups=[])
    context = _call_tool_context("rucio_list_dids", {}, principal)
    call_next = _CallNextRecorder()

    before_total = _sample(
        "af_mcp_tool_invocations_total",
        {"service": "rucio", "tool": "rucio_list_dids", "action_type": "read"},
    )
    before_denied = _sample(
        "af_mcp_tool_invocations_denied_total",
        {"service": "rucio", "action_type": "read"},
    )

    with pytest.raises(AuthorizationError):
        await mw.on_call_tool(context, call_next)

    # A denial still counts as an attempted invocation ...
    assert (
        _sample(
            "af_mcp_tool_invocations_total",
            {"service": "rucio", "tool": "rucio_list_dids", "action_type": "read"},
        )
        == before_total + 1
    )
    # ... and is additionally isolated in the denied-only counter.
    assert (
        _sample(
            "af_mcp_tool_invocations_denied_total",
            {"service": "rucio", "action_type": "read"},
        )
        == before_denied + 1
    )


async def test_unknown_tool_prefix_increments_unmapped_counter_only(
    registry, policy, make_principal, captured_audits
) -> None:
    """A tool name matching no registered backend prefix is client-supplied
    and unbounded -- it must land only in the label-free
    tool_invocations_unmapped_total, never in a per-tool or per-backend
    counter (see metrics.py's cardinality policy)."""
    mw = authorization_middleware(registry, policy)
    principal = make_principal(groups=["atlas"])
    context = _call_tool_context("mystery_tool", {}, principal)
    call_next = _CallNextRecorder()

    before_unmapped = _sample("af_mcp_tool_invocations_unmapped_total", {})

    with pytest.raises(AuthorizationError):
        await mw.on_call_tool(context, call_next)

    assert _sample("af_mcp_tool_invocations_unmapped_total", {}) == before_unmapped + 1


async def test_call_next_failure_increments_invocation_counters_not_denied(
    registry, policy, make_principal, captured_audits
) -> None:
    mw = authorization_middleware(registry, policy)
    principal = make_principal(groups=["atlas"])
    context = _call_tool_context("rucio_list_dids", {}, principal)
    call_next = _CallNextRecorder(error=RuntimeError("credential provider unreachable"))

    before_total = _sample(
        "af_mcp_tool_invocations_total",
        {"service": "rucio", "tool": "rucio_list_dids", "action_type": "read"},
    )
    before_denied = _sample(
        "af_mcp_tool_invocations_denied_total",
        {"service": "rucio", "action_type": "read"},
    )

    with pytest.raises(RuntimeError):
        await mw.on_call_tool(context, call_next)

    # An error downstream of authorization still counts as an attempted
    # invocation (the call was authorized, just failed afterwards) ...
    assert (
        _sample(
            "af_mcp_tool_invocations_total",
            {"service": "rucio", "tool": "rucio_list_dids", "action_type": "read"},
        )
        == before_total + 1
    )
    # ... but must not be miscounted as a denial -- denied_total is reserved
    # for AuthorizationMiddleware's own entitlement decision.
    assert (
        _sample(
            "af_mcp_tool_invocations_denied_total",
            {"service": "rucio", "action_type": "read"},
        )
        == before_denied
    )


# ---------------------------------------------------------------------------
# Metering pipeline integration (metering.py): with a real pipeline
# installed, success/error audit lines are measured and written by the
# background worker so the tool call never waits on them; denied lines stay
# synchronous inline (security-relevant, nothing to measure).
# ---------------------------------------------------------------------------


async def test_success_audit_flows_through_metering_pipeline(
    registry,
    policy,
    make_principal,
    audit_buffer,
) -> None:
    """With a real pipeline installed the success path hands the record
    over and returns without writing; after the pipeline drains, the line
    carries the same fields the inline path produces -- including the
    measurement the worker performed."""
    backend = InProcessMeteringBackend(Settings(), InMemoryUsageStore())
    await backend.start()
    try:
        mw = authorization_middleware(registry, policy, metering=backend)
        principal = make_principal(groups=["atlas"])
        context = _call_tool_context("rucio_list_dids", {"scope": "foo"}, principal)
        fake_result = ToolResult(
            content=[mt.TextContent(type="text", text="hellohello")]
        )

        result = await mw.on_call_tool(context, _CallNextRecorder(result=fake_result))

        assert result is fake_result
        # The tool call returned without waiting on measurement or audit
        # I/O: nothing has been written yet (put_nowait never yields, so
        # the worker cannot have run between enqueue and here).
        assert audit_buffer.getvalue() == ""
    finally:
        await backend.aclose()

    line = json.loads(audit_buffer.getvalue().strip())
    assert line["event"] == "audit"
    assert line["outcome"] == "success"
    assert line["error"] is None
    assert line["permission"] == "read_data"
    assert line["target"] == "rucio"
    assert line["action"] == "rucio_list_dids"
    assert line["action_type"] == "read"
    assert line["mcp_service"] == "rucio"
    assert line["principal_sub"] == principal.subject
    assert line["principal_uid"] == principal.uid
    assert line["duration_ms"] >= 0.0
    assert line["result_bytes"] == len(b"hellohello")
    # conftest's stub tiktoken encoder: one token per 4 characters.
    assert line["result_tokens_est"] == 2


async def test_denied_audit_written_inline_not_via_pipeline(
    registry,
    policy,
    make_principal,
    audit_buffer,
) -> None:
    """A denial is security-relevant and has nothing to measure: its audit
    line must be on disk before the AuthorizationError even propagates --
    no drain required."""
    backend = InProcessMeteringBackend(Settings(), InMemoryUsageStore())
    await backend.start()
    try:
        mw = authorization_middleware(registry, policy, metering=backend)
        principal = make_principal(groups=[])
        context = _call_tool_context("rucio_list_dids", {}, principal)

        with pytest.raises(AuthorizationError):
            await mw.on_call_tool(context, _CallNextRecorder())

        line = json.loads(audit_buffer.getvalue().strip())
        assert line["outcome"] == "denied"
        assert line["target"] == "rucio"
    finally:
        await backend.aclose()


async def test_audit_request_id_is_the_requests_correlation_id(
    registry, policy, make_principal, captured_audits
) -> None:
    """The record's request_id is the request's bound correlation_id, so
    the audit, request and usage lines of one tool call share one id."""
    structlog.contextvars.clear_contextvars()
    structlog.contextvars.bind_contextvars(correlation_id="corr-42")
    mw = authorization_middleware(registry, policy)
    principal = make_principal(groups=["atlas"])
    context = _call_tool_context("rucio_list_dids", {}, principal)

    await mw.on_call_tool(context, _CallNextRecorder(result=ToolResult(content=[])))
    structlog.contextvars.clear_contextvars()

    (record,) = captured_audits
    assert record.request_id == "corr-42"


# ---------------------------------------------------------------------------
# rate_limits (issue #165): enforced after the entitlement check, before
# call_next.
# ---------------------------------------------------------------------------


class _Clock:
    """Controllable replacement for ``time.monotonic``."""

    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> _Clock:
    fake = _Clock()
    monkeypatch.setattr(shared_state.time, "monotonic", fake)
    return fake


def _rate_limited_middleware(
    registry: ServiceRegistry,
    policy: EntitlementPolicy,
    *rules: RateLimitRule,
    store: shared_state.SharedState | None = None,
) -> AuthorizationMiddleware:
    policy.rate_limits = list(rules)
    return authorization_middleware(
        registry, policy, shared_state=store or InMemorySharedState()
    )


async def test_rate_limited_call_is_refused_before_call_next_with_retry_info(
    registry, policy, make_principal, captured_audits, clock
) -> None:
    mw = _rate_limited_middleware(
        registry, policy, RateLimitRule(1, 60, tool="rucio_*")
    )
    principal = make_principal(groups=["atlas"])
    context = _call_tool_context("rucio_list_dids", {}, principal)
    await mw.on_call_tool(context, _CallNextRecorder(result=ToolResult(content=[])))
    clock.now += 20
    call_next = _CallNextRecorder()

    with pytest.raises(ToolError) as excinfo:
        await mw.on_call_tool(context, call_next)

    assert call_next.called is False
    message = str(excinfo.value)
    assert "Rate limit of 1 calls per 60s exceeded for rucio_list_dids" in message
    assert "Retry-After: 40" in message
    assert "retry_at: " in message
    # Points an agent at where it can see every limit and its own usage.
    assert "af_rate_limits" in message
    assert isinstance(excinfo.value.__cause__, ToolRateLimitError)
    # The first, allowed call audited as success; the refused one as rate_limited.
    assert [r.outcome for r in captured_audits] == ["success", "rate_limited"]
    record = captured_audits[1]
    assert record.target == "rucio"
    assert record.action == "rucio_list_dids"
    assert record.action_type == "read"
    assert record.principal_sub == principal.subject
    assert record.error is not None
    assert "Rate limit of 1 calls per 60s" in record.error
    assert record.duration_ms is None


async def test_rate_limited_call_logs_the_dedicated_event(
    registry, policy, make_principal, captured_audits, monkeypatch
) -> None:
    mw = _rate_limited_middleware(
        registry, policy, RateLimitRule(1, 60, tool="rucio_*")
    )
    principal = make_principal(groups=["atlas"])
    context = _call_tool_context("rucio_list_dids", {}, principal)
    await mw.on_call_tool(context, _CallNextRecorder(result=ToolResult(content=[])))
    events = _capturing_info(monkeypatch, retry_after_module.logger)

    with pytest.raises(ToolError):
        await mw.on_call_tool(context, _CallNextRecorder())

    [event] = events
    assert event["event"] == "rate_limit_exceeded"
    assert event["subject"] == principal.subject
    assert event["limiter"] == "tool_rate_limit"
    assert event["rule"] == "1/60s"
    assert 0 < event["retry_after_seconds"] <= 60


async def test_rate_limited_call_increments_counter_without_identity_label(
    registry, policy, make_principal, captured_audits
) -> None:
    mw = _rate_limited_middleware(
        registry, policy, RateLimitRule(1, 60, action_type="read")
    )
    principal = make_principal(groups=["atlas"])
    context = _call_tool_context("rucio_list_dids", {}, principal)
    labels = {"service": "rucio", "action_type": "read"}
    before = _sample("af_mcp_tool_invocations_rate_limited_total", labels)
    await mw.on_call_tool(context, _CallNextRecorder(result=ToolResult(content=[])))

    with pytest.raises(ToolError):
        await mw.on_call_tool(context, _CallNextRecorder())

    assert _sample("af_mcp_tool_invocations_rate_limited_total", labels) == before + 1
    # No per-user label (metrics.py's cardinality policy).
    metric = next(
        m
        for m in REGISTRY.collect()
        if m.name == "af_mcp_tool_invocations_rate_limited"
    )
    assert all(
        set(sample.labels) == {"service", "action_type"} for sample in metric.samples
    )


async def test_entitlement_denial_comes_first_and_is_not_counted(
    registry, policy, make_principal, captured_audits
) -> None:
    mw = _rate_limited_middleware(
        registry, policy, RateLimitRule(1, 60, tool="rucio_*")
    )
    stranger = make_principal(groups=[])
    for _ in range(3):
        with pytest.raises(AuthorizationError):
            await mw.on_call_tool(
                _call_tool_context("rucio_list_dids", {}, stranger),
                _CallNextRecorder(),
            )

    assert {r.outcome for r in captured_audits} == {"denied"}
    # The denied calls consumed no budget: the same subject, once entitled,
    # still has it.
    entitled = make_principal(groups=["atlas"], subject=stranger.subject)
    await mw.on_call_tool(
        _call_tool_context("rucio_list_dids", {}, entitled),
        _CallNextRecorder(result=ToolResult(content=[])),
    )


async def test_rate_limit_budgets_are_per_principal(
    registry, policy, make_principal, captured_audits
) -> None:
    mw = _rate_limited_middleware(
        registry, policy, RateLimitRule(1, 60, tool="rucio_*")
    )
    for subject in ("alice", "bob"):
        principal = make_principal(groups=["atlas"], subject=subject)
        await mw.on_call_tool(
            _call_tool_context("rucio_list_dids", {}, principal),
            _CallNextRecorder(result=ToolResult(content=[])),
        )

    assert [r.outcome for r in captured_audits] == ["success", "success"]


class _SpyState(InMemorySharedState):
    """In-memory store that counts its increments."""

    def __init__(self) -> None:
        super().__init__()
        self.incr_calls = 0

    async def incr_window(self, key: str, window_seconds: int) -> WindowCount:
        self.incr_calls += 1
        return await super().incr_window(key, window_seconds)


async def test_no_rate_limits_never_refuses_and_leaves_counter_untouched(
    registry, policy, make_principal, captured_audits
) -> None:
    store = _SpyState()
    mw = authorization_middleware(registry, policy, shared_state=store)
    principal = make_principal(groups=["atlas"])
    for _ in range(5):
        await mw.on_call_tool(
            _call_tool_context("rucio_list_dids", {}, principal),
            _CallNextRecorder(result=ToolResult(content=[])),
        )

    assert {r.outcome for r in captured_audits} == {"success"}
    assert store.incr_calls == 0


# ---------------------------------------------------------------------------
# rate_limits across replicas: two middleware instances over one real redis
# server stand in for two broker replicas (see the ``shared_state_url``
# fixture); nothing is mocked.
# ---------------------------------------------------------------------------


@pytest.fixture
async def replica_stores(
    shared_state_url: str,
) -> AsyncIterator[list[RedisSharedState]]:
    stores = [RedisSharedState(shared_state_url) for _ in range(2)]
    yield stores
    for store in stores:
        await store.close()


async def _call_rucio(mw: AuthorizationMiddleware, principal: Principal) -> ToolResult:
    return await mw.on_call_tool(
        _call_tool_context("rucio_list_dids", {}, principal),
        _CallNextRecorder(result=ToolResult(content=[])),
    )


async def test_rate_limit_budget_is_shared_across_replicas(
    registry, policy, make_principal, captured_audits, replica_stores
) -> None:
    replica_a, replica_b = (
        _rate_limited_middleware(
            registry, policy, RateLimitRule(2, 60, tool="rucio_*"), store=store
        )
        for store in replica_stores
    )
    # A subject unique to this test: the server outlives each test.
    principal = make_principal(groups=["atlas"], subject=f"sub-{uuid.uuid4()}")
    # Neither replica sees more than its own limit's worth of calls.
    await _call_rucio(replica_a, principal)
    await _call_rucio(replica_b, principal)

    with pytest.raises(ToolError, match="Rate limit of 2 calls per 60s"):
        await _call_rucio(replica_a, principal)

    assert [r.outcome for r in captured_audits] == [
        "success",
        "success",
        "rate_limited",
    ]


async def test_rate_limit_store_outage_falls_back_to_a_per_replica_count(
    registry, policy, make_principal, captured_audits, unreachable_shared_state_url
) -> None:
    store = RedisSharedState(unreachable_shared_state_url)
    mw = _rate_limited_middleware(
        registry, policy, RateLimitRule(2, 60, tool="rucio_*"), store=store
    )
    principal = make_principal(groups=["atlas"])
    try:
        with structlog.testing.capture_logs() as logs:
            # Still limited, per replica, instead of failing open or erroring.
            await _call_rucio(mw, principal)
            await _call_rucio(mw, principal)
            with pytest.raises(ToolError, match="Rate limit of 2 calls per 60s"):
                await _call_rucio(mw, principal)
    finally:
        await store.close()

    unavailable = [
        log
        for log in logs
        if log["event"] == "tool_rate_limit.shared_state_unavailable"
    ]
    assert unavailable
    assert [r.outcome for r in captured_audits] == [
        "success",
        "success",
        "rate_limited",
    ]


# --- granting groups in the permission-denied error (issue #395) -------------


def _registry_with_rucio(**kwargs) -> ServiceRegistry:
    """A registry whose "rucio" service requires read_data."""
    reg = ServiceRegistry()
    reg.register(
        ServiceSpec(
            name="rucio",
            prefix="rucio",
            url="http://rucio.invalid/mcp",
            transport="http",
            required_permission="read_data",
            apply_namespace=False,
            **kwargs,
        )
    )
    return reg


async def test_denial_names_the_granting_groups(
    policy, make_principal, captured_audits
) -> None:
    registry = _registry_with_rucio(docs_url="https://docs.example.org/rucio")
    mw = authorization_middleware(registry, policy)
    context = _call_tool_context("rucio_list_dids", {}, make_principal(groups=[]))

    with pytest.raises(AuthorizationError) as excinfo:
        await mw.on_call_tool(context, _CallNextRecorder())

    message = str(excinfo.value)
    # The existing wording is kept ...
    assert message.startswith(
        "Authorization denied: target 'rucio' requires permission 'read_data'"
    )
    # ... and extended with who to ask. No access page is named.
    assert "Granted by membership in: atlas." in message
    assert "Request access" not in message
    assert "https://" not in message
    # The audit record keeps the bare reason: the guidance is for the caller,
    # not the log line.
    assert captured_audits[0].error == (
        "target 'rucio' requires permission 'read_data'"
    )


async def test_denial_without_groups_keeps_the_original_message(
    make_principal, captured_audits
) -> None:
    """No group grants read_data: nothing to add."""
    registry = _registry_with_rucio()
    policy = EntitlementPolicy(group_permissions={"__authenticated__": []})
    mw = authorization_middleware(registry, policy)
    context = _call_tool_context("rucio_list_dids", {}, make_principal(groups=[]))

    with pytest.raises(AuthorizationError) as excinfo:
        await mw.on_call_tool(context, _CallNextRecorder())

    assert str(excinfo.value) == (
        "Authorization denied: target 'rucio' requires permission 'read_data'"
    )


async def test_denial_for_a_per_tool_permission_names_that_tools_groups(
    policy, make_principal, captured_audits
) -> None:
    """Each tool's error names the groups for ITS permission, not the union
    across the service."""
    registry = ServiceRegistry()
    registry.register(
        ServiceSpec(
            name="condor",
            prefix="condor",
            url="http://condor.invalid/mcp",
            transport="http",
            required_permission={
                "__default__": "manage_jobs",
                "query_jobs": "read_data",
            },
            auth_type="none",
        )
    )
    mw = authorization_middleware(registry, policy)

    messages = {}
    for tool in ("condor_query_jobs", "condor_submit_job"):
        context = _call_tool_context(tool, {}, make_principal(groups=[]))
        with pytest.raises(AuthorizationError) as excinfo:
            await mw.on_call_tool(context, _CallNextRecorder())
        messages[tool] = str(excinfo.value)

    # policy fixture: atlas -> read_data; af-admins -> manage_jobs.
    assert "Granted by membership in: atlas." in messages["condor_query_jobs"]
    assert "Granted by membership in: af-admins." in messages["condor_submit_job"]


async def test_denial_of_an_unmapped_tool_names_no_groups(
    make_principal, captured_audits
) -> None:
    """A dict-form service with no __default__ disables unlisted tools for
    everyone: no group can fix that, so none is suggested."""
    registry = ServiceRegistry()
    registry.register(
        ServiceSpec(
            name="condor",
            prefix="condor",
            url="http://condor.invalid/mcp",
            transport="http",
            required_permission={"query_jobs": "read_data"},
            auth_type="none",
        )
    )
    policy = EntitlementPolicy(group_permissions={"atlas": ["read_data"]})
    mw = authorization_middleware(registry, policy)
    context = _call_tool_context("condor_submit_job", {}, make_principal(groups=[]))

    with pytest.raises(AuthorizationError) as excinfo:
        await mw.on_call_tool(context, _CallNextRecorder())

    assert str(excinfo.value) == (
        "Authorization denied: target 'condor' has no permission mapping for this tool"
    )


# ---------------------------------------------------------------------------
# Constructor-injected collaborators: the shared state and the metering
# backend are required arguments, and the middleware submits to the backend
# it was given rather than to anything process-wide.
# ---------------------------------------------------------------------------


class _RecordingMetering(InlineMeteringBackend):
    def __init__(self) -> None:
        super().__init__(Settings(), InMemoryUsageStore())
        self.submitted: list[AuditRecord] = []

    async def submit(self, record: AuditRecord, result: ToolResult | None) -> None:
        self.submitted.append(record)


def test_the_constructor_requires_shared_state_and_metering(registry, policy) -> None:
    with pytest.raises(TypeError):
        AuthorizationMiddleware(registry, policy)  # type: ignore[call-arg]


async def test_success_is_submitted_to_the_metering_backend_it_was_given(
    registry, policy, make_principal, captured_audits
) -> None:
    metering = _RecordingMetering()
    mw = authorization_middleware(registry, policy, metering=metering)
    context = _call_tool_context(
        "rucio_list_dids", {}, make_principal(groups=["atlas"])
    )

    await mw.on_call_tool(context, _CallNextRecorder(result=ToolResult(content=[])))

    assert [r.outcome for r in metering.submitted] == ["success"]
    assert captured_audits == []


async def test_a_failing_audit_write_raises_to_the_tool_caller(
    registry, policy, make_principal, monkeypatch
) -> None:
    async def _failing_write_audit(record: AuditRecord) -> None:
        raise RuntimeError("audit output unavailable")

    monkeypatch.setattr(pipeline, "write_audit", _failing_write_audit)
    mw = authorization_middleware(registry, policy)
    context = _call_tool_context(
        "rucio_list_dids", {}, make_principal(groups=["atlas"])
    )

    with pytest.raises(RuntimeError, match="audit output unavailable"):
        await mw.on_call_tool(context, _CallNextRecorder(result=ToolResult(content=[])))
