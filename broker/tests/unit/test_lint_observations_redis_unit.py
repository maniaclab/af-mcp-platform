"""Unit tests for the area ``test_lint_observations_redis.py`` covers; the integration tests live in ``integration/test_lint_observations_redis.py``."""

from __future__ import annotations

import pytest
import structlog.testing
from lint_observations_redis_support import (  # noqa: F401
    _mismatch,
    service_fixture,
)

from af_mcp_broker.lint_observations import LintObservationStore
from af_mcp_broker.shared_state import RedisSharedState

pytestmark = pytest.mark.usefixtures("unpinned_loggers")


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
