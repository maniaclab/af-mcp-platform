from __future__ import annotations

import io
import json
from typing import TYPE_CHECKING, Any

import mcp.types as mt
import pytest
from fastmcp.exceptions import AuthorizationError
from fastmcp.tools.base import ToolResult
from prometheus_client import REGISTRY

from af_mcp_broker.audit import pipeline
from af_mcp_broker.audit.logger import init_audit_logger
from af_mcp_broker.audit.pipeline import (
    aclose_metering_pipeline,
    init_metering_pipeline,
)
from af_mcp_broker.authorization import EntitlementPolicy
from af_mcp_broker.mcp.middleware import authorization_mw
from af_mcp_broker.mcp.middleware.authorization_mw import AuthorizationMiddleware
from af_mcp_broker.mcp.registry import (
    DIAGNOSTIC_TOOL_NAMES,
    ServiceRegistry,
    ServiceSpec,
)

if TYPE_CHECKING:
    from af_mcp_broker.audit import AuditRecord


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
    return reg


@pytest.fixture
def policy() -> EntitlementPolicy:
    return EntitlementPolicy(
        group_permissions={"atlas": ["read_data"], "__authenticated__": []},
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
    # Success/error records flow through the metering pipeline's helper,
    # whose uninitialized fallback (no pipeline installed in unit tests)
    # measures and writes via pipeline.write_audit -- patch that too so
    # every audit path in the middleware lands here.
    monkeypatch.setattr(pipeline, "write_audit", _fake_write_audit)
    return records


async def test_entitled_call_proceeds_and_audits_success(
    registry, policy, make_principal, captured_audits
) -> None:
    mw = AuthorizationMiddleware(registry, policy)
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
    mw = AuthorizationMiddleware(registry, policy)
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
async def test_diagnostic_tool_call_bypasses_backend_lookup_and_audit(
    registry, policy, make_principal, captured_audits, tool_name
) -> None:
    """Requirement (issue #153): an af_* diagnostic tool call must reach
    call_next directly -- no backend lookup (there is none to look up: no
    registered backend can claim this prefix, see registry.py), no
    entitlement check, no credential minting, and no audit/metrics record,
    since it never touches a backend and needs no permission. A principal
    with no groups at all (so no permissions) proves this isn't gated on
    entitlement the way every other tool here is."""
    mw = AuthorizationMiddleware(registry, policy)
    principal = make_principal(groups=[])
    context = _call_tool_context(tool_name, {}, principal)
    fake_result = ToolResult(content=[])
    call_next = _CallNextRecorder(result=fake_result)

    result = await mw.on_call_tool(context, call_next)

    assert result is fake_result
    assert call_next.called is True
    assert captured_audits == []


async def test_unentitled_call_denied_audit_carries_no_permission_grant_when_not_a_permission_pat(
    registry, policy, make_principal, captured_audits
) -> None:
    """The common case (a JWT, or an identity PAT -- permission_grant=None)
    must not fabricate a grant in the audit record."""
    mw = AuthorizationMiddleware(registry, policy)
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
    mw = AuthorizationMiddleware(registry, policy)
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


async def test_unknown_tool_prefix_denied(
    registry, policy, make_principal, captured_audits
) -> None:
    mw = AuthorizationMiddleware(registry, policy)
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
    mw = AuthorizationMiddleware(registry, policy)
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
    mw = AuthorizationMiddleware(registry, policy)
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
    mw = AuthorizationMiddleware(registry, policy)
    context = _call_tool_context("rucio_list_dids", {}, None)
    call_next = _CallNextRecorder()

    with pytest.raises(AuthorizationError):
        await mw.on_call_tool(context, call_next)

    assert call_next.called is False
    assert captured_audits == []


async def test_missing_fastmcp_context_fails_closed(
    registry, policy, captured_audits
) -> None:
    mw = AuthorizationMiddleware(registry, policy)
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
    mw = AuthorizationMiddleware(registry, policy)
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


async def test_success_records_duration_and_observes_histogram(
    registry, policy, make_principal, captured_audits
) -> None:
    """A successful call must meter the downstream call's wall time into
    both the audit record (duration_ms) and the duration histogram."""
    mw = AuthorizationMiddleware(registry, policy)
    principal = make_principal(groups=["atlas"])
    context = _call_tool_context("rucio_list_dids", {"scope": "foo"}, principal)
    call_next = _CallNextRecorder(result=ToolResult(content=[]))

    before_count = _sample(
        "af_mcp_tool_duration_seconds_count",
        {"service": "rucio", "tool": "rucio_list_dids", "action_type": "read"},
    )

    await mw.on_call_tool(context, call_next)

    record = captured_audits[0]
    assert record.outcome == "success"
    assert record.duration_ms is not None
    assert record.duration_ms >= 0.0
    assert (
        _sample(
            "af_mcp_tool_duration_seconds_count",
            {"service": "rucio", "tool": "rucio_list_dids", "action_type": "read"},
        )
        == before_count + 1
    )


async def test_success_records_result_bytes_and_tokens(
    registry, policy, make_principal, captured_audits, monkeypatch
) -> None:
    """The success path measures the result via audit.measure (in the
    metering pipeline -- audit/pipeline.py -- not on the hot path) and
    records both fields; the measurement sees the very ToolResult call_next
    returned."""
    mw = AuthorizationMiddleware(registry, policy)
    principal = make_principal(groups=["atlas"])
    context = _call_tool_context("rucio_list_dids", {"scope": "foo"}, principal)
    fake_result = ToolResult(content=[mt.TextContent(type="text", text="hello")])
    call_next = _CallNextRecorder(result=fake_result)

    measured: list[Any] = []

    def _fake_measure(result: Any) -> tuple[int | None, int | None]:
        measured.append(result)
        return (5, 2)

    monkeypatch.setattr(pipeline, "measure_tool_result", _fake_measure)

    await mw.on_call_tool(context, call_next)

    assert measured == [fake_result]
    record = captured_audits[0]
    assert record.result_bytes == 5
    assert record.result_tokens_est == 2


async def test_call_next_failure_records_duration_but_no_result_fields(
    registry, policy, make_principal, captured_audits
) -> None:
    """An error downstream still has a measurable duration (the call ran and
    failed), but produced no result to measure."""
    mw = AuthorizationMiddleware(registry, policy)
    principal = make_principal(groups=["atlas"])
    context = _call_tool_context("rucio_list_dids", {}, principal)
    call_next = _CallNextRecorder(error=RuntimeError("boom"))

    before_count = _sample(
        "af_mcp_tool_duration_seconds_count",
        {"service": "rucio", "tool": "rucio_list_dids", "action_type": "read"},
    )

    with pytest.raises(RuntimeError):
        await mw.on_call_tool(context, call_next)

    record = captured_audits[0]
    assert record.outcome == "error"
    assert record.duration_ms is not None
    assert record.duration_ms >= 0.0
    assert record.result_bytes is None
    assert record.result_tokens_est is None
    # The histogram observes errors too -- outcome is deliberately not a
    # label (the audit log is the per-outcome source of truth).
    assert (
        _sample(
            "af_mcp_tool_duration_seconds_count",
            {"service": "rucio", "tool": "rucio_list_dids", "action_type": "read"},
        )
        == before_count + 1
    )


async def test_denied_call_leaves_metering_fields_none(
    registry, policy, make_principal, captured_audits
) -> None:
    """A denial never reaches call_next -- nothing executed, so there is no
    duration and no result to measure."""
    mw = AuthorizationMiddleware(registry, policy)
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


async def test_registry_and_policy_are_mutable_attributes(
    registry, policy, make_principal, captured_audits
) -> None:
    """populate_aggregator() refreshes these in place on every lifespan
    entry rather than constructing a new middleware instance."""
    mw = AuthorizationMiddleware(ServiceRegistry(), EntitlementPolicy())
    mw.registry = registry
    mw.policy = policy

    principal = make_principal(groups=["atlas"])
    context = _call_tool_context("rucio_list_dids", {}, principal)
    call_next = _CallNextRecorder(result=ToolResult(content=[]))

    await mw.on_call_tool(context, call_next)

    assert captured_audits[0].outcome == "success"


# ---------------------------------------------------------------------------
# Prometheus invocation counters (issue #83 asked for per-identity counters;
# Giordon declined that -- the audit log above already carries identity at
# full fidelity behind access control, so these counters are backend/tool
# only, incremented next to write_audit() above)
# ---------------------------------------------------------------------------


async def test_entitled_call_increments_invocation_counters(
    registry, policy, make_principal, captured_audits
) -> None:
    mw = AuthorizationMiddleware(registry, policy)
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
    mw = AuthorizationMiddleware(registry, policy)
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
    mw = AuthorizationMiddleware(registry, policy)
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
    mw = AuthorizationMiddleware(registry, policy)
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
# Metering pipeline integration (audit/pipeline.py): with a real pipeline
# installed, success/error audit lines are measured and written by the
# background worker so the tool call never waits on them; denied lines stay
# synchronous inline (security-relevant, nothing to measure).
# ---------------------------------------------------------------------------


async def test_success_audit_flows_through_metering_pipeline(
    registry, policy, make_principal
) -> None:
    """With a real pipeline installed the success path hands the record
    over and returns without writing; after the pipeline drains, the line
    carries the same fields the old inline path produced -- including the
    measurement the worker performed."""
    buffer = io.StringIO()
    init_audit_logger(buffer)
    await init_metering_pipeline()
    try:
        mw = AuthorizationMiddleware(registry, policy)
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
        assert buffer.getvalue() == ""
    finally:
        await aclose_metering_pipeline()

    line = json.loads(buffer.getvalue().strip())
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
    registry, policy, make_principal
) -> None:
    """A denial is security-relevant and has nothing to measure: its audit
    line must be on disk before the AuthorizationError even propagates --
    no drain required."""
    buffer = io.StringIO()
    init_audit_logger(buffer)
    await init_metering_pipeline()
    try:
        mw = AuthorizationMiddleware(registry, policy)
        principal = make_principal(groups=[])
        context = _call_tool_context("rucio_list_dids", {}, principal)

        with pytest.raises(AuthorizationError):
            await mw.on_call_tool(context, _CallNextRecorder())

        line = json.loads(buffer.getvalue().strip())
        assert line["outcome"] == "denied"
        assert line["target"] == "rucio"
    finally:
        await aclose_metering_pipeline()
