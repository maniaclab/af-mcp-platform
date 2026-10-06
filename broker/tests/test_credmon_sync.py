"""Tests for ``CredmonSyncService`` -- the in-broker credmon loop (docs/credmon.md).

Each replica ticks every ``poll_seconds``; a timer cycle runs only when the
shared status record says one is due (``now - last finished >= interval``)
AND this replica wins the short per-cycle lease. A manual run (``POST
/v1/admin/credmon/sync``) skips the due check but still needs the lease.
The lease holder writes the status record and every outcome is counted in
Prometheus, so a stalled loop is visible without reading logs.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from prometheus_client import REGISTRY

from af_mcp_broker.credmon.state import InMemoryCredmonSyncState
from af_mcp_broker.credmon.storer import SyncReport
from af_mcp_broker.credmon.sync import CredmonSyncService

_INTERVAL = 4 * 3600.0


def _sample(name: str, labels: dict[str, str] | None = None) -> float:
    return REGISTRY.get_sample_value(name, labels or {}) or 0.0


class _FakeStorer:
    def __init__(
        self, report: SyncReport | None = None, error: Exception | None = None
    ) -> None:
        self.calls = 0
        self.report = report
        self.error = error

    async def run_once(self) -> SyncReport:
        self.calls += 1
        if self.error is not None:
            raise self.error
        assert self.report is not None
        return self.report


class _Clock:
    def __init__(self, now: float) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


def _report(**kwargs: Any) -> SyncReport:
    report = SyncReport(started_at=1000.0, finished_at=1002.0)
    for key, value in kwargs.items():
        setattr(report, key, value)
    return report


def _service(
    storer: _FakeStorer,
    state: InMemoryCredmonSyncState,
    clock: _Clock,
    holder: str = "pod-a",
) -> CredmonSyncService:
    return CredmonSyncService(
        storer=storer,  # type: ignore[arg-type]
        state=state,
        holder=holder,
        interval_seconds=_INTERVAL,
        lease_ttl_seconds=600.0,
        poll_seconds=60.0,
        clock=clock,
    )


async def test_first_tick_runs_a_cycle_and_records_status() -> None:
    state = InMemoryCredmonSyncState()
    storer = _FakeStorer(_report(stored={"krb5": 3}))
    service = _service(storer, state, _Clock(1000.0))

    status = await service.tick()

    assert storer.calls == 1
    assert status is not None
    recorded = await state.read_status()
    assert recorded is not None
    assert recorded["outcome"] == "success"
    assert recorded["trigger"] == "timer"
    assert recorded["holder"] == "pod-a"
    assert recorded["stored"] == {"krb5": 3}
    assert recorded["last_success_at"] == 1002.0


async def test_tick_skips_when_last_cycle_is_recent() -> None:
    state = InMemoryCredmonSyncState()
    storer = _FakeStorer(_report())
    clock = _Clock(1000.0)
    service = _service(storer, state, clock)
    await service.tick()

    clock.now = 1000.0 + _INTERVAL / 2
    assert await service.tick() is None
    assert storer.calls == 1

    clock.now = 1002.0 + _INTERVAL
    assert await service.tick() is not None
    assert storer.calls == 2


async def test_cycle_is_skipped_when_another_replica_holds_the_lease() -> None:
    state = InMemoryCredmonSyncState()
    await state.try_acquire_lease("pod-b", ttl_seconds=600.0, now=1000.0)
    storer = _FakeStorer(_report())
    before = _sample(
        "af_mcp_credmon_sync_runs_total",
        {"outcome": "skipped_lease", "trigger": "timer"},
    )
    service = _service(storer, state, _Clock(1000.0))

    assert await service.tick() is None
    assert storer.calls == 0
    assert (
        _sample(
            "af_mcp_credmon_sync_runs_total",
            {"outcome": "skipped_lease", "trigger": "timer"},
        )
        == before + 1
    )


async def test_manual_run_ignores_due_check() -> None:
    state = InMemoryCredmonSyncState()
    storer = _FakeStorer(_report())
    clock = _Clock(1000.0)
    service = _service(storer, state, clock)
    await service.tick()

    clock.now = 1100.0
    status = await service.run_now()

    assert storer.calls == 2
    assert status is not None
    assert status["trigger"] == "manual"


async def test_partial_failure_counts_as_partial_but_updates_last_success() -> None:
    """A few users failing (e.g. one rejected store) is not a stalled loop --
    it must not page the stale-success alert, but it must be visible."""
    state = InMemoryCredmonSyncState()
    storer = _FakeStorer(
        _report(stored={"krb5": 2}, failed={"krb5": 1}, errors=["krb5: store failed"])
    )
    service = _service(storer, state, _Clock(1000.0))

    status = await service.tick()

    assert status is not None
    assert status["outcome"] == "partial"
    assert status["errors"] == ["krb5: store failed"]
    assert status["last_success_at"] == 1002.0
    assert _sample("af_mcp_credmon_sync_last_success_timestamp_seconds") == 1002.0


async def test_cycle_exception_is_recorded_as_failed_and_keeps_last_success() -> None:
    state = InMemoryCredmonSyncState()
    clock = _Clock(1000.0)
    await _service(_FakeStorer(_report()), state, clock).tick()

    clock.now = 1002.0 + _INTERVAL
    failing = _FakeStorer(error=RuntimeError("vault list failed"))
    before = _sample(
        "af_mcp_credmon_sync_runs_total", {"outcome": "failed", "trigger": "timer"}
    )

    status = await _service(failing, state, clock).tick()

    assert status is not None
    assert status["outcome"] == "failed"
    assert "vault list failed" in status["errors"][0]
    # A failed cycle never moves last_success_at forward.
    assert status["last_success_at"] == 1002.0
    assert (
        _sample(
            "af_mcp_credmon_sync_runs_total", {"outcome": "failed", "trigger": "timer"}
        )
        == before + 1
    )


async def test_errors_in_status_are_capped() -> None:
    state = InMemoryCredmonSyncState()
    storer = _FakeStorer(
        _report(failed={"krb5": 50}, errors=[f"krb5: e{i}" for i in range(50)])
    )
    service = _service(storer, state, _Clock(1000.0))

    status = await service.tick()

    assert status is not None
    assert len(status["errors"]) == 20
    assert status["errors_truncated"] == 30


async def test_per_kind_outcomes_are_counted() -> None:
    labels = {"kind": "x509", "outcome": "stored"}
    before = _sample("af_mcp_credmon_sync_credentials_total", labels)
    state = InMemoryCredmonSyncState()
    service = _service(_FakeStorer(_report(stored={"x509": 4})), state, _Clock(1000.0))

    await service.tick()

    assert _sample("af_mcp_credmon_sync_credentials_total", labels) == before + 4


@pytest.mark.parametrize("trigger", ["timer", "manual"])
async def test_duration_is_observed(trigger: str) -> None:
    before = _sample("af_mcp_credmon_sync_duration_seconds_count")
    state = InMemoryCredmonSyncState()
    service = _service(_FakeStorer(_report()), state, _Clock(1000.0))

    if trigger == "timer":
        await service.tick()
    else:
        await service.run_now()

    assert _sample("af_mcp_credmon_sync_duration_seconds_count") == before + 1


async def test_background_loop_runs_and_survives_storage_errors() -> None:
    """start() keeps ticking even when the state store raises, and stop()
    cancels cleanly -- a dead loop task would silently end all syncing."""

    class _FlakyState(InMemoryCredmonSyncState):
        def __init__(self) -> None:
            super().__init__()
            self.reads = 0

        async def read_status(self) -> dict[str, Any] | None:
            self.reads += 1
            if self.reads == 1:
                raise RuntimeError("vault unavailable (test)")
            return await super().read_status()

    state = _FlakyState()
    storer = _FakeStorer(_report())
    service = CredmonSyncService(
        storer=storer,  # type: ignore[arg-type]
        state=state,
        holder="pod-a",
        interval_seconds=_INTERVAL,
        lease_ttl_seconds=600.0,
        poll_seconds=0.01,
    )

    service.start()
    for _ in range(200):
        if storer.calls:
            break
        await asyncio.sleep(0.01)
    await service.stop()

    assert state.reads >= 2
    assert storer.calls == 1


async def test_tick_publishes_shared_last_success_even_when_not_due() -> None:
    """After a restart no cycle may be due for hours; every replica must still
    report the shared last success, or a stale-sync alert on max() across
    replicas would fire on every rollout."""
    state = InMemoryCredmonSyncState()
    await state.write_status(
        {"finished_at": 5000.0, "last_success_at": 4990.0, "outcome": "success"}
    )
    credmon_sync_gauge = "af_mcp_credmon_sync_last_success_timestamp_seconds"
    service = _service(_FakeStorer(_report()), state, _Clock(5100.0), holder="pod-z")

    assert await service.tick() is None
    assert _sample(credmon_sync_gauge) == 4990.0


async def test_background_loop_waits_one_poll_before_first_tick() -> None:
    """A freshly started broker must not touch Vault/htcondor-api at the
    instant of boot -- the first tick comes one poll interval later."""

    class _CountingState(InMemoryCredmonSyncState):
        def __init__(self) -> None:
            super().__init__()
            self.reads = 0

        async def read_status(self) -> dict[str, Any] | None:
            self.reads += 1
            return await super().read_status()

    state = _CountingState()
    service = CredmonSyncService(
        storer=_FakeStorer(_report()),  # type: ignore[arg-type]
        state=state,
        holder="pod-a",
        interval_seconds=_INTERVAL,
        lease_ttl_seconds=600.0,
        poll_seconds=60.0,
    )

    service.start()
    await asyncio.sleep(0.05)
    await service.stop()

    assert state.reads == 0
