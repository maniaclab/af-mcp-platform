"""Tests for PostgresMaintenanceModeStore against a REAL ephemeral postgres (no mocks -- see conftest.py's postgres_dsn fixture)."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from af_mcp_broker.maintenance import MaintenanceState, PostgresMaintenanceModeStore

if TYPE_CHECKING:
    from collections.abc import AsyncIterator


@pytest.fixture
async def store(postgres_dsn: str) -> AsyncIterator[PostgresMaintenanceModeStore]:
    s = PostgresMaintenanceModeStore(postgres_dsn)
    await s.start()
    yield s
    await s.aclose()


async def test_default_state_is_disabled(store: PostgresMaintenanceModeStore) -> None:
    state = await store.get()
    assert state.enabled is False


async def test_set_then_get_roundtrips(store: PostgresMaintenanceModeStore) -> None:
    written = MaintenanceState(
        enabled=True, reason="upgrading", enabled_by="admin-sub", enabled_at=1234.0
    )
    await store.set(written)
    assert await store.get() == written


async def test_set_overwrites_previous_non_default_state(
    store: PostgresMaintenanceModeStore,
) -> None:
    await store.set(
        MaintenanceState(enabled=True, reason="a", enabled_by="x", enabled_at=1.0)
    )
    second = MaintenanceState(
        enabled=False, reason=None, enabled_by=None, enabled_at=None
    )
    await store.set(second)
    assert await store.get() == second


async def test_start_ddl_is_idempotent(postgres_dsn: str) -> None:
    first = PostgresMaintenanceModeStore(postgres_dsn)
    await first.start()
    second = PostgresMaintenanceModeStore(postgres_dsn)
    await second.start()  # must not raise
    await first.aclose()
    await second.aclose()
