"""Integration tests: lint observations are shared across replicas via a real redis server (see the ``shared_state_url`` fixture)."""

from __future__ import annotations

import asyncio
import uuid
from typing import TYPE_CHECKING

import pytest
import structlog.testing

from af_mcp_broker.mcp.lint_observations import LintObservationStore
from af_mcp_broker.mcp.registry import AnnotationMismatch
from af_mcp_broker.shared_state import RedisSharedState

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

pytestmark = pytest.mark.usefixtures("unpinned_loggers")


@pytest.fixture
def service() -> str:
    # The server outlives each test, so every test gets its own service.
    return f"svc-{uuid.uuid4()}"


def _mismatch(service: str) -> AnnotationMismatch:
    return AnnotationMismatch(
        service=service,
        tool=f"{service}_tool",
        declared_read_only_hint=True,
        resolved_action_type="write",
        resolved_via="default",
        permission="read_data",
    )


@pytest.fixture
async def replicas(shared_state_url: str) -> AsyncIterator[list[LintObservationStore]]:
    states = [RedisSharedState(shared_state_url) for _ in range(2)]
    yield [LintObservationStore(state) for state in states]
    for state in states:
        await state.close()


async def test_an_observation_made_on_one_replica_is_read_on_the_other(
    replicas: list[LintObservationStore], service: str
) -> None:
    replica_a, replica_b = replicas
    assert await replica_b.get(service) is None

    await replica_a.observe(service, (_mismatch(service),), None)

    observation = await replica_b.get(service)
    assert observation is not None
    assert observation.annotation_mismatches == (_mismatch(service),)


async def test_an_observation_expires_in_the_store(
    shared_state_url: str, service: str
) -> None:
    state = RedisSharedState(shared_state_url)
    try:
        store = LintObservationStore(state, ttl_seconds=1)
        await store.observe(service, (), None)
        assert await store.get(service) is not None
        await asyncio.sleep(1.2)
        assert await store.get(service) is None
    finally:
        await state.close()


async def test_store_down_falls_back_to_what_this_replica_observed(
    unreachable_shared_state_url: str, service: str
) -> None:
    state = RedisSharedState(unreachable_shared_state_url)
    store = LintObservationStore(state)
    try:
        with structlog.testing.capture_logs() as logs:
            await store.observe(service, (_mismatch(service),), None)
            observation = await store.get(service)
    finally:
        await state.close()

    assert observation is not None
    assert observation.annotation_mismatches == (_mismatch(service),)
    events = {e["event"] for e in logs}
    assert "lint_observations.shared_state_unavailable" in events
