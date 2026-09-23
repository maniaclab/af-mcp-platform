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


async def test_start_bounds_the_pool_instead_of_asyncpgs_defaults(
    postgres_dsn: str,
) -> None:
    """asyncpg.create_pool()'s own defaults (min_size=10, max_size=10) eagerly
    open 10 connections per replica regardless of load -- with this store's
    DSN commonly sharing a small Postgres instance with the usage store and a
    second broker deployment, that exhausted the instance's max_connections
    during a routine rolling restart (2026-09-19 production incident).
    start() must request a much smaller pool."""
    s = PostgresMaintenanceModeStore(postgres_dsn)
    await s.start()
    try:
        assert s._pool is not None
        assert s._pool.get_min_size() <= 2
        assert s._pool.get_max_size() <= 5
    finally:
        await s.aclose()


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
