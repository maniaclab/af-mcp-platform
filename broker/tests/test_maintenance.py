"""Tests for maintenance.py -- the maintenance-mode store."""

from __future__ import annotations

import time

from af_mcp_broker.maintenance import InMemoryMaintenanceModeStore, MaintenanceState


async def test_default_state_is_disabled():
    store = InMemoryMaintenanceModeStore()
    state = await store.get()
    assert state == MaintenanceState(
        enabled=False, reason=None, enabled_by=None, enabled_at=None
    )


async def test_set_then_get_roundtrips():
    store = InMemoryMaintenanceModeStore()
    written = MaintenanceState(
        enabled=True, reason="upgrading", enabled_by="admin-sub", enabled_at=time.time()
    )
    await store.set(written)
    assert await store.get() == written


async def test_set_overwrites_previous_non_default_state():
    store = InMemoryMaintenanceModeStore()
    await store.set(
        MaintenanceState(enabled=True, reason="a", enabled_by="x", enabled_at=1.0)
    )
    second = MaintenanceState(
        enabled=False, reason=None, enabled_by=None, enabled_at=None
    )
    await store.set(second)
    assert await store.get() == second
