"""Integration tests: lint observations are shared across replicas via a real redis server (see the ``shared_state_url`` fixture)."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

import pytest
from lint_observations_redis_support import (  # noqa: F401
    _mismatch,
    service_fixture,
)

from af_mcp_broker.lint_observations import LintObservationStore
from af_mcp_broker.shared_state import RedisSharedState

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

pytestmark = pytest.mark.usefixtures("unpinned_loggers")


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
