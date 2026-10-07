"""Tests for ``InMemoryCredmonSyncState`` -- the no-Vault (local dev) lease/status store."""

from __future__ import annotations

from af_mcp_broker.credmon.state import InMemoryCredmonSyncState


async def test_lease_refused_to_other_holder_until_expiry() -> None:
    state = InMemoryCredmonSyncState()

    assert await state.try_acquire_lease("pod-a", ttl_seconds=60, now=1000.0)
    assert not await state.try_acquire_lease("pod-b", ttl_seconds=60, now=1030.0)
    assert await state.try_acquire_lease("pod-a", ttl_seconds=60, now=1030.0)
    assert await state.try_acquire_lease("pod-b", ttl_seconds=60, now=1100.0)


async def test_status_round_trips_as_a_copy() -> None:
    state = InMemoryCredmonSyncState()
    assert await state.read_status() is None

    status = {"outcome": "success"}
    await state.write_status(status)
    status["outcome"] = "mutated"

    assert await state.read_status() == {"outcome": "success"}
