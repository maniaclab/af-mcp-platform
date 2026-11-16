from __future__ import annotations

import uuid
from typing import TYPE_CHECKING

import pytest
from fastmcp.exceptions import ToolError
from mcp_middleware_authorization_support import (  # noqa: F401
    _call_rucio,
    _call_tool_context,
    _CallNextRecorder,
    _FakeFastMCPContext,
    _FakeMiddlewareContext,
    _rate_limited_middleware,
    captured_audits_fixture,
    policy_fixture,
    registry_fixture,
)

from af_mcp_broker.authorization import RateLimitRule
from af_mcp_broker.shared_state import (
    RedisSharedState,
)

if TYPE_CHECKING:
    from collections.abc import AsyncIterator


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
