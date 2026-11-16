"""Fixtures and helpers shared by the unit and integration tests of ``test_mcp_middleware_authorization``."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import mcp.types as mt
import pytest
from broker_state_helpers import authorization_middleware
from fastmcp.tools.base import ToolResult

from af_mcp_broker import metering as pipeline
from af_mcp_broker import shared_state
from af_mcp_broker.authorization import EntitlementPolicy, RateLimitRule
from af_mcp_broker.mcp.middleware import authorization_mw
from af_mcp_broker.service_registry import (
    ServiceRegistry,
    ServiceSpec,
)
from af_mcp_broker.shared_state import (
    InMemorySharedState,
)

if TYPE_CHECKING:
    from af_mcp_broker.audit import AuditRecord
    from af_mcp_broker.mcp.middleware.authorization_mw import AuthorizationMiddleware
    from af_mcp_broker.principal import Principal


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


@pytest.fixture(name="registry")
def registry_fixture() -> ServiceRegistry:
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


@pytest.fixture(name="policy")
def policy_fixture() -> EntitlementPolicy:
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


@pytest.fixture(name="captured_audits")
def captured_audits_fixture(monkeypatch: pytest.MonkeyPatch) -> list[AuditRecord]:
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


async def _call_rucio(mw: AuthorizationMiddleware, principal: Principal) -> ToolResult:
    return await mw.on_call_tool(
        _call_tool_context("rucio_list_dids", {}, principal),
        _CallNextRecorder(result=ToolResult(content=[])),
    )
