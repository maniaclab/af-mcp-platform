"""Unit tests for ``LintObservationStore`` on the in-memory store."""

from __future__ import annotations

import pytest
import structlog.testing

from af_mcp_broker import shared_state
from af_mcp_broker.mcp.lint_observations import LintObservationStore
from af_mcp_broker.mcp.registry import AnnotationMismatch, ToolMappingDrift
from af_mcp_broker.shared_state import InMemorySharedState

pytestmark = pytest.mark.usefixtures("unpinned_loggers")

MISMATCH = AnnotationMismatch(
    service="rucio",
    tool="rucio_list_dids",
    declared_read_only_hint=False,
    resolved_action_type="read",
    resolved_via="permission",
    permission="read_data",
)
DRIFT = ToolMappingDrift(
    service="rucio",
    prefix="rucio",
    advertised=3,
    routable=2,
    unmapped=("rucio_new",),
    stale=("rucio_old",),
    unroutable=("other_tool",),
)


class _Clock:
    def __init__(self) -> None:
        self.now = 1_700_000_000.0

    def __call__(self) -> float:
        return self.now


class _CountingState(InMemorySharedState):
    def __init__(self) -> None:
        super().__init__()
        self.writes = 0

    async def set(self, key: str, value: str, ttl_seconds: float) -> None:
        self.writes += 1
        await super().set(key, value, ttl_seconds)


@pytest.fixture
def clock() -> _Clock:
    return _Clock()


@pytest.fixture
def state() -> _CountingState:
    return _CountingState()


@pytest.fixture
def store(state: _CountingState, clock: _Clock) -> LintObservationStore:
    return LintObservationStore(
        state, ttl_seconds=3600, refresh_seconds=60, clock=clock
    )


async def test_an_unobserved_service_reads_as_none(store: LintObservationStore) -> None:
    assert await store.get("rucio") is None


async def test_an_observation_round_trips_with_its_timestamp(
    store: LintObservationStore, clock: _Clock
) -> None:
    await store.observe("rucio", (MISMATCH,), DRIFT)

    observation = await store.get("rucio")

    assert observation is not None
    assert observation.service == "rucio"
    assert observation.observed_at == clock.now
    assert observation.annotation_mismatches == (MISMATCH,)
    assert observation.tool_mapping_drift == DRIFT


async def test_a_clean_observation_is_distinct_from_no_observation(
    store: LintObservationStore,
) -> None:
    await store.observe("rucio", (), None)

    observation = await store.get("rucio")

    assert observation is not None
    assert observation.annotation_mismatches == ()
    assert observation.tool_mapping_drift is None


async def test_services_are_independent(store: LintObservationStore) -> None:
    await store.observe("rucio", (MISMATCH,), None)
    assert await store.get("panda") is None


async def test_an_unchanged_observation_is_not_rewritten_within_the_refresh_interval(
    store: LintObservationStore, state: _CountingState, clock: _Clock
) -> None:
    await store.observe("rucio", (MISMATCH,), DRIFT)
    clock.now += 59
    await store.observe("rucio", (MISMATCH,), DRIFT)
    assert state.writes == 1


async def test_an_unchanged_observation_is_refreshed_after_the_interval(
    store: LintObservationStore, state: _CountingState, clock: _Clock
) -> None:
    await store.observe("rucio", (MISMATCH,), DRIFT)
    clock.now += 61
    await store.observe("rucio", (MISMATCH,), DRIFT)

    assert state.writes == 2
    observation = await store.get("rucio")
    assert observation is not None
    assert observation.observed_at == clock.now


async def test_a_changed_observation_is_written_at_once(
    store: LintObservationStore, state: _CountingState
) -> None:
    await store.observe("rucio", (MISMATCH,), None)
    await store.observe("rucio", (), None)

    assert state.writes == 2
    observation = await store.get("rucio")
    assert observation is not None
    assert observation.annotation_mismatches == ()


async def test_an_observation_expires_after_its_ttl(
    clock: _Clock, monkeypatch: pytest.MonkeyPatch
) -> None:
    monotonic = [1000.0]
    monkeypatch.setattr(shared_state.time, "monotonic", lambda: monotonic[0])
    store = LintObservationStore(
        InMemorySharedState(), ttl_seconds=3600, refresh_seconds=60, clock=clock
    )
    await store.observe("rucio", (), None)
    monotonic[0] += 3601
    assert await store.get("rucio") is None


async def test_the_retention_is_exposed_for_the_admin_page(
    store: LintObservationStore,
) -> None:
    assert store.retention_seconds == 3600


async def test_an_unreadable_record_reads_as_unobserved_and_is_logged(
    store: LintObservationStore, state: _CountingState
) -> None:
    await state.set("lint-observation:rucio", "not json", 60)
    with structlog.testing.capture_logs() as logs:
        assert await store.get("rucio") is None
    assert [e["event"] for e in logs] == ["lint_observations.bad_record"]
