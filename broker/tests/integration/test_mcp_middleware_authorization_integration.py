from __future__ import annotations

import uuid
from typing import TYPE_CHECKING

import pytest
from fastmcp.exceptions import ToolError
from test_mcp_middleware_authorization import (
    _call_rucio,
    _rate_limited_middleware,
)

from af_mcp_broker import metering as pipeline
from af_mcp_broker.authorization import EntitlementPolicy, RateLimitRule
from af_mcp_broker.mcp.middleware import authorization_mw
from af_mcp_broker.service_registry import (
    ServiceRegistry,
    ServiceSpec,
)
from af_mcp_broker.shared_state import (
    RedisSharedState,
)

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from af_mcp_broker.audit import AuditRecord


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
