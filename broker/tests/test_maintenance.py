"""Tests for maintenance.py -- the maintenance-mode store."""

from __future__ import annotations

import json
import time
from typing import TYPE_CHECKING, Any

import httpx
import pytest

from af_mcp_broker.maintenance import (
    InMemoryMaintenanceModeStore,
    MaintenanceState,
    MaintenanceStateConflict,
    VaultMaintenanceModeStore,
)
from af_mcp_broker.vault_kv import VaultKV

if TYPE_CHECKING:
    from pathlib import Path


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


# ---------------------------------------------------------------------------
# Fake Vault KV-v2 HTTP API for VaultMaintenanceModeStore -- get/write_cas
# only, same technique as test_principal_cache.py's _FakePrincipalCacheVault
# (pared down like that one, since this store needs no LIST/DELETE either).
# ---------------------------------------------------------------------------

ADDR = "https://vault.invalid"
AUTH_MOUNT = "kubernetes"
AUTH_ROLE = "af-mcp-broker"
KV_MOUNT = "secret"
KV_PATH_PREFIX = "mcp/maintenance-mode"


class _FakeMaintenanceVault:
    def __init__(self, *, login_lease_duration: int = 3600) -> None:
        self.entries: dict[str, dict[str, Any]] = {}
        self.login_lease_duration = login_lease_duration

    def handle(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path.removeprefix("/v1/")

        if path == f"auth/{AUTH_MOUNT}/login" and request.method == "POST":
            return httpx.Response(
                200,
                json={
                    "auth": {
                        "client_token": "vault-test-token",
                        "lease_duration": self.login_lease_duration,
                        "renewable": True,
                    }
                },
                request=request,
            )

        data_prefix = f"{KV_MOUNT}/data/"
        if not path.startswith(data_prefix):
            return httpx.Response(
                404, json={"errors": ["unknown path"]}, request=request
            )
        key = path[len(data_prefix) :]

        if request.method == "GET":
            entry = self.entries.get(key)
            if entry is None:
                return httpx.Response(404, json={"errors": []}, request=request)
            return httpx.Response(
                200,
                json={
                    "data": {
                        "data": entry["data"],
                        "metadata": {"version": entry["version"]},
                    }
                },
                request=request,
            )

        if request.method == "POST":
            body = json.loads(request.content.decode())
            cas = body["options"]["cas"]
            current_version = self.entries.get(key, {}).get("version", 0)
            if cas != current_version:
                return httpx.Response(
                    400,
                    json={
                        "errors": [
                            "check-and-set parameter did not match the current version"
                        ]
                    },
                    request=request,
                )
            new_version = current_version + 1
            self.entries[key] = {"data": body["data"], "version": new_version}
            return httpx.Response(
                200, json={"data": {"version": new_version}}, request=request
            )

        return httpx.Response(
            404, json={"errors": ["unhandled"]}, request=request
        )  # pragma: no cover


@pytest.fixture
def sa_token_path(tmp_path: Path) -> Path:
    path = tmp_path / "sa-token"
    path.write_text("fake-sa-jwt\n")
    return path


@pytest.fixture
def fake_vault() -> _FakeMaintenanceVault:
    return _FakeMaintenanceVault()


@pytest.fixture
def vault_kv(fake_vault: _FakeMaintenanceVault, sa_token_path: Path) -> VaultKV:
    return VaultKV(
        addr=ADDR,
        auth_mount=AUTH_MOUNT,
        auth_role=AUTH_ROLE,
        kv_mount=KV_MOUNT,
        sa_token_path=str(sa_token_path),
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(fake_vault.handle)),
    )


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
    vault_kv: VaultKV, fake_vault: _FakeMaintenanceVault
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

    with pytest.raises(MaintenanceStateConflict):
        await store.set(
            MaintenanceState(
                enabled=False, reason=None, enabled_by=None, enabled_at=None
            )
        )
