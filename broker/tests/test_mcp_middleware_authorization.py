from __future__ import annotations

from typing import TYPE_CHECKING, Any

import mcp.types as mt
import pytest
from fastmcp.exceptions import AuthorizationError
from fastmcp.tools.base import ToolResult
from prometheus_client import REGISTRY

from af_mcp_broker.authorization import EntitlementPolicy
from af_mcp_broker.mcp.middleware import authorization_mw
from af_mcp_broker.mcp.middleware.authorization_mw import AuthorizationMiddleware
from af_mcp_broker.mcp.registry import BackendRegistry, BackendSpec

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
def registry() -> BackendRegistry:
    reg = BackendRegistry()
    reg.register(
        BackendSpec(
            name="rucio",
            prefix="rucio",
            url="http://rucio.invalid/mcp",
            transport="http",
            required_capability="read_data",
            apply_namespace=False,
        )
    )
    reg.register(
        BackendSpec(
            name="docs",
            prefix="docs",
            url="http://docs.invalid/mcp",
            transport="http",
            required_capability="__none__",
        )
    )
    reg.register(
        BackendSpec(
            name="credentialed",
            prefix="credentialed",
            url="http://credentialed.invalid/mcp",
            transport="http",
            # Omitted required_capability -- the credential layer is the
            # gate instead (issue #60).
        )
    )
    return reg


@pytest.fixture
def policy() -> EntitlementPolicy:
    return EntitlementPolicy(
        group_capabilities={"atlas": ["read_data"], "__authenticated__": []},
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
    assert record.capability == "read_data"
    assert record.target == "rucio"
    assert record.action == "rucio_list_dids"
    assert record.action_type == "read"
    assert record.mcp_backend == "rucio"
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


async def test_open_target_requires_no_capability(
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


async def test_omitted_capability_target_requires_no_capability(
    registry, policy, make_principal, captured_audits
) -> None:
    """A backend that omits required_capability has no capability gate --
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


async def test_registry_and_policy_are_mutable_attributes(
    registry, policy, make_principal, captured_audits
) -> None:
    """populate_aggregator() refreshes these in place on every lifespan
    entry rather than constructing a new middleware instance."""
    mw = AuthorizationMiddleware(BackendRegistry(), EntitlementPolicy())
    mw.registry = registry
    mw.policy = policy

    principal = make_principal(groups=["atlas"])
    context = _call_tool_context("rucio_list_dids", {}, principal)
    call_next = _CallNextRecorder(result=ToolResult(content=[]))

    await mw.on_call_tool(context, call_next)

    assert captured_audits[0].outcome == "success"


# ---------------------------------------------------------------------------
# Prometheus invocation counters (issue #83 -- per-identity tool-invocation
# counters from the /mcp aggregator, incremented next to write_audit() above)
# ---------------------------------------------------------------------------


async def test_entitled_call_increments_invocation_counters(
    registry, policy, make_principal, captured_audits
) -> None:
    mw = AuthorizationMiddleware(registry, policy)
    principal = make_principal(groups=["atlas"], unixname="alice")
    context = _call_tool_context("rucio_list_dids", {"scope": "foo"}, principal)
    call_next = _CallNextRecorder(result=ToolResult(content=[]))

    before_total = _sample(
        "af_mcp_tool_invocations_total",
        {"identity": "alice", "backend": "rucio", "action_type": "read"},
    )
    before_by_tool = _sample(
        "af_mcp_tool_invocations_by_tool_total",
        {"backend": "rucio", "tool": "rucio_list_dids", "action_type": "read"},
    )
    before_denied = _sample(
        "af_mcp_tool_invocations_denied_total",
        {"backend": "rucio", "action_type": "read"},
    )

    await mw.on_call_tool(context, call_next)

    assert (
        _sample(
            "af_mcp_tool_invocations_total",
            {"identity": "alice", "backend": "rucio", "action_type": "read"},
        )
        == before_total + 1
    )
    assert (
        _sample(
            "af_mcp_tool_invocations_by_tool_total",
            {"backend": "rucio", "tool": "rucio_list_dids", "action_type": "read"},
        )
        == before_by_tool + 1
    )
    # A successful call must not also count as a denial.
    assert (
        _sample(
            "af_mcp_tool_invocations_denied_total",
            {"backend": "rucio", "action_type": "read"},
        )
        == before_denied
    )


async def test_unentitled_call_increments_invocation_and_denied_counters(
    registry, policy, make_principal, captured_audits
) -> None:
    mw = AuthorizationMiddleware(registry, policy)
    principal = make_principal(groups=[], unixname="bob")
    context = _call_tool_context("rucio_list_dids", {}, principal)
    call_next = _CallNextRecorder()

    before_total = _sample(
        "af_mcp_tool_invocations_total",
        {"identity": "bob", "backend": "rucio", "action_type": "read"},
    )
    before_by_tool = _sample(
        "af_mcp_tool_invocations_by_tool_total",
        {"backend": "rucio", "tool": "rucio_list_dids", "action_type": "read"},
    )
    before_denied = _sample(
        "af_mcp_tool_invocations_denied_total",
        {"backend": "rucio", "action_type": "read"},
    )

    with pytest.raises(AuthorizationError):
        await mw.on_call_tool(context, call_next)

    # A denial still counts as an attempted invocation ...
    assert (
        _sample(
            "af_mcp_tool_invocations_total",
            {"identity": "bob", "backend": "rucio", "action_type": "read"},
        )
        == before_total + 1
    )
    assert (
        _sample(
            "af_mcp_tool_invocations_by_tool_total",
            {"backend": "rucio", "tool": "rucio_list_dids", "action_type": "read"},
        )
        == before_by_tool + 1
    )
    # ... and is additionally isolated in the denied-only counter.
    assert (
        _sample(
            "af_mcp_tool_invocations_denied_total",
            {"backend": "rucio", "action_type": "read"},
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
    principal = make_principal(groups=["atlas"], unixname="carol")
    context = _call_tool_context("rucio_list_dids", {}, principal)
    call_next = _CallNextRecorder(error=RuntimeError("credential provider unreachable"))

    before_total = _sample(
        "af_mcp_tool_invocations_total",
        {"identity": "carol", "backend": "rucio", "action_type": "read"},
    )
    before_denied = _sample(
        "af_mcp_tool_invocations_denied_total",
        {"backend": "rucio", "action_type": "read"},
    )

    with pytest.raises(RuntimeError):
        await mw.on_call_tool(context, call_next)

    # An error downstream of authorization still counts as an attempted
    # invocation (the call was authorized, just failed afterwards) ...
    assert (
        _sample(
            "af_mcp_tool_invocations_total",
            {"identity": "carol", "backend": "rucio", "action_type": "read"},
        )
        == before_total + 1
    )
    # ... but must not be miscounted as a denial -- denied_total is reserved
    # for AuthorizationMiddleware's own entitlement decision.
    assert (
        _sample(
            "af_mcp_tool_invocations_denied_total",
            {"backend": "rucio", "action_type": "read"},
        )
        == before_denied
    )
