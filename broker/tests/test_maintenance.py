"""Tests for maintenance.py -- the maintenance-mode store."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

import pytest
from vault_fakes import FakeVault, make_vault_kv

from af_mcp_broker.config import Settings
from af_mcp_broker.maintenance import (
    InMemoryMaintenanceModeStore,
    MaintenanceModeError,
    MaintenanceModeStore,
    MaintenanceState,
    MaintenanceStateConflictError,
    VaultMaintenanceModeStore,
    check_not_maintenance,
)

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from af_mcp_broker.vault_kv import VaultKV


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


KV_PATH_PREFIX = "mcp/maintenance-mode"


@pytest.fixture
def fake_vault() -> FakeVault:
    return FakeVault()


@pytest.fixture
def vault_kv(fake_vault: FakeVault, sa_token_path: Path) -> VaultKV:
    return make_vault_kv(fake_vault, sa_token_path)


async def test_vault_default_state_is_disabled(vault_kv: VaultKV):
    store = VaultMaintenanceModeStore(vault_kv=vault_kv, kv_path_prefix=KV_PATH_PREFIX)
    assert (await store.get()).enabled is False


async def test_vault_set_then_get_roundtrips(vault_kv: VaultKV):
    store = VaultMaintenanceModeStore(vault_kv=vault_kv, kv_path_prefix=KV_PATH_PREFIX)
    state = MaintenanceState(
        enabled=True, reason="r", enabled_by="admin", enabled_at=1.0
    )
    await store.set(state)
    assert await store.get() == state


async def test_vault_set_overwrites_previous_non_default_state(vault_kv: VaultKV):
    store = VaultMaintenanceModeStore(vault_kv=vault_kv, kv_path_prefix=KV_PATH_PREFIX)
    await store.set(
        MaintenanceState(enabled=True, reason="a", enabled_by="x", enabled_at=1.0)
    )
    second = MaintenanceState(
        enabled=False, reason=None, enabled_by=None, enabled_at=None
    )
    await store.set(second)
    assert await store.get() == second


async def test_vault_set_raises_conflict_on_concurrent_write(
    vault_kv: VaultKV, fake_vault: FakeVault
):
    store = VaultMaintenanceModeStore(vault_kv=vault_kv, kv_path_prefix=KV_PATH_PREFIX)
    # Seed an initial state so set()'s internal get() has an existing
    # version to race against.
    await store.set(
        MaintenanceState(enabled=True, reason="a", enabled_by="x", enabled_at=1.0)
    )

    key = f"{KV_PATH_PREFIX}/state"
    real_get = vault_kv.get

    async def get_then_concurrent_write(path: str):
        # Simulate another replica's write_cas() landing in between this
        # set()'s internal get() and its own write_cas() -- by the time
        # write_cas() fires, the version it read is already stale.
        result = await real_get(path)
        fake_vault.entries[key]["version"] += 1
        return result

    vault_kv.get = get_then_concurrent_write  # type: ignore[method-assign]

    with pytest.raises(MaintenanceStateConflictError):
        await store.set(
            MaintenanceState(
                enabled=False, reason=None, enabled_by=None, enabled_at=None
            )
        )


# ---------------------------------------------------------------------------
# check_not_maintenance() -- the gate helper
# ---------------------------------------------------------------------------


async def test_admin_bypasses_maintenance(make_principal: Callable[..., object]):
    settings = Settings(admin_group="af-admins")
    principal = make_principal(groups=["af-admins"])
    store = InMemoryMaintenanceModeStore()
    await store.set(
        MaintenanceState(enabled=True, reason="r", enabled_by="x", enabled_at=1.0)
    )

    await check_not_maintenance(principal, settings, store)  # must not raise


async def test_non_admin_blocked_with_reason(make_principal: Callable[..., object]):
    settings = Settings(admin_group="af-admins")
    principal = make_principal(groups=["atlas"])
    store = InMemoryMaintenanceModeStore()
    await store.set(
        MaintenanceState(
            enabled=True, reason="upgrading", enabled_by="x", enabled_at=1.0
        )
    )

    with pytest.raises(MaintenanceModeError) as exc_info:
        await check_not_maintenance(principal, settings, store)
    assert "upgrading" in str(exc_info.value.detail)


async def test_disabled_maintenance_never_raises(make_principal: Callable[..., object]):
    settings = Settings(admin_group="af-admins")
    principal = make_principal(groups=["atlas"])
    store = InMemoryMaintenanceModeStore()

    await check_not_maintenance(principal, settings, store)  # must not raise


async def test_reason_none_produces_clean_detail_with_no_suffix(
    make_principal: Callable[..., object],
):
    settings = Settings(admin_group="af-admins")
    principal = make_principal(groups=["atlas"])
    store = InMemoryMaintenanceModeStore()
    await store.set(
        MaintenanceState(enabled=True, reason=None, enabled_by="x", enabled_at=1.0)
    )

    with pytest.raises(MaintenanceModeError) as exc_info:
        await check_not_maintenance(principal, settings, store)
    assert exc_info.value.detail == "The broker is in maintenance mode."


class _ExplodingMaintenanceModeStore(MaintenanceModeStore):
    """A store whose ``get()`` always raises -- proves an admin never reaches it."""

    async def start(self) -> None:
        raise NotImplementedError

    async def aclose(self) -> None:
        raise NotImplementedError

    async def get(self) -> MaintenanceState:
        raise RuntimeError("store should never be read for an admin")

    async def set(self, state: MaintenanceState) -> None:
        raise NotImplementedError


async def test_admin_bypass_never_calls_store_get(
    make_principal: Callable[..., object],
):
    settings = Settings(admin_group="af-admins")
    principal = make_principal(groups=["af-admins"])

    await check_not_maintenance(
        principal, settings, _ExplodingMaintenanceModeStore()
    )  # must not raise
