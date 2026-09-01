"""Tests for the admin API -- POST/GET /v1/admin/maintenance."""

from __future__ import annotations

import pytest

from af_mcp_broker.maintenance import (
    InMemoryMaintenanceModeStore,
    MaintenanceModeStore,
    MaintenanceState,
    MaintenanceStateConflict,
)


@pytest.fixture
def maintenance_client(app_client_factory, monkeypatch):
    monkeypatch.setenv("ADMIN_GROUP", "af-admins")
    with app_client_factory() as (client, state):
        client.app.state.maintenance_mode_store = InMemoryMaintenanceModeStore()
        yield client, state


def test_get_status_requires_no_auth_at_all(maintenance_client):
    client, _state = maintenance_client
    client.app.dependency_overrides.clear()  # simulate a genuinely unauthenticated caller
    resp = client.get("/v1/admin/maintenance")
    assert resp.status_code == 200
    assert resp.json()["enabled"] is False


def test_post_requires_admin(maintenance_client):
    client, _state = maintenance_client
    resp = client.post("/v1/admin/maintenance", json={"enabled": True, "reason": "r"})
    assert resp.status_code == 403


def test_admin_can_enable_and_it_shows_up_on_get(maintenance_client, make_principal):
    client, state = maintenance_client
    state["principal"] = make_principal(groups=["af-admins"], subject="admin-sub")

    resp = client.post(
        "/v1/admin/maintenance", json={"enabled": True, "reason": "upgrading"}
    )
    assert resp.status_code == 200

    status_resp = client.get("/v1/admin/maintenance")
    body = status_resp.json()
    assert body["enabled"] is True
    assert body["reason"] == "upgrading"
    assert body["enabled_by"] == "admin-sub"
    assert body["enabled_at"] is not None


def test_enabled_by_resolves_to_unixname_when_principal_cache_can(
    maintenance_client, make_principal, static_principal_cache
):
    client, state = maintenance_client
    cache, directory = static_principal_cache
    directory.groups_by_subject["admin-sub"] = ["af-admins"]
    directory.posix_by_subject["admin-sub"] = {"unixname": "gstark"}
    client.app.state.principal_cache = cache
    state["principal"] = make_principal(groups=["af-admins"], subject="admin-sub")

    post_resp = client.post(
        "/v1/admin/maintenance", json={"enabled": True, "reason": "upgrading"}
    )
    assert post_resp.json()["enabled_by_unixname"] == "gstark"

    get_resp = client.get("/v1/admin/maintenance")
    body = get_resp.json()
    assert body["enabled_by"] == "admin-sub"
    assert body["enabled_by_unixname"] == "gstark"


def test_enabled_by_falls_back_to_bare_subject_when_unresolvable(
    maintenance_client, make_principal, static_principal_cache
):
    client, state = maintenance_client
    cache, directory = static_principal_cache
    directory.unavailable_subjects.add("admin-sub")
    client.app.state.principal_cache = cache
    state["principal"] = make_principal(groups=["af-admins"], subject="admin-sub")

    client.post("/v1/admin/maintenance", json={"enabled": True, "reason": "upgrading"})

    resp = client.get("/v1/admin/maintenance")
    body = resp.json()
    assert body["enabled_by"] == "admin-sub"
    assert body["enabled_by_unixname"] is None
    assert body["enabled_by_email"] == ""


def test_enabled_by_resolution_fields_are_null_when_disabled(maintenance_client):
    client, _state = maintenance_client
    resp = client.get("/v1/admin/maintenance")
    body = resp.json()
    assert body["enabled_by"] is None
    assert body["enabled_by_unixname"] is None
    assert body["enabled_by_email"] == ""


def test_admin_can_disable_and_enabled_by_at_are_cleared(
    maintenance_client, make_principal
):
    client, state = maintenance_client
    state["principal"] = make_principal(groups=["af-admins"], subject="admin-sub")
    client.post("/v1/admin/maintenance", json={"enabled": True, "reason": "upgrading"})

    resp = client.post("/v1/admin/maintenance", json={"enabled": False})
    assert resp.status_code == 200
    body = resp.json()
    assert body["enabled"] is False
    assert body["reason"] is None
    assert body["enabled_by"] is None
    assert body["enabled_at"] is None


def test_disable_clears_reason_too(maintenance_client, make_principal):
    client, state = maintenance_client
    state["principal"] = make_principal(groups=["af-admins"], subject="admin-sub")
    client.post("/v1/admin/maintenance", json={"enabled": True, "reason": "upgrading"})

    # A reason passed alongside enabled=False must not persist -- otherwise
    # it would linger, unauthenticated, until the next POST overwrites it.
    resp = client.post(
        "/v1/admin/maintenance", json={"enabled": False, "reason": "ignored"}
    )
    assert resp.status_code == 200
    assert resp.json()["reason"] is None


def test_disable_persists_and_is_readable_back_via_get(
    maintenance_client, make_principal
):
    client, state = maintenance_client
    state["principal"] = make_principal(groups=["af-admins"], subject="admin-sub")
    client.post("/v1/admin/maintenance", json={"enabled": True, "reason": "upgrading"})

    disable_resp = client.post("/v1/admin/maintenance", json={"enabled": False})
    assert disable_resp.status_code == 200

    status_resp = client.get("/v1/admin/maintenance")
    assert status_resp.status_code == 200
    body = status_resp.json()
    assert body["enabled"] is False
    assert body["reason"] is None
    assert body["enabled_by"] is None
    assert body["enabled_at"] is None


class _ConflictingStore(MaintenanceModeStore):
    """Stub store whose set() always loses the compare-and-set race, to verify the endpoint translates MaintenanceStateConflict into a client-actionable response rather than a bare 500."""

    async def start(self) -> None:
        pass

    async def aclose(self) -> None:
        pass

    async def get(self) -> MaintenanceState:
        return MaintenanceState(
            enabled=False, reason=None, enabled_by=None, enabled_at=None
        )

    async def set(self, state: MaintenanceState) -> None:
        raise MaintenanceStateConflict("simulated concurrent writer")


def test_post_conflict_from_store_returns_409(maintenance_client, make_principal):
    client, state = maintenance_client
    state["principal"] = make_principal(groups=["af-admins"], subject="admin-sub")
    client.app.state.maintenance_mode_store = _ConflictingStore()

    resp = client.post("/v1/admin/maintenance", json={"enabled": True, "reason": "r"})
    assert resp.status_code == 409
    assert "retry" in resp.json()["detail"].lower()


class _BrokenGetStore(MaintenanceModeStore):
    """Stub store whose get() always raises, simulating a Vault/Postgres outage -- verifies GET fails open (200, disabled) rather than 500ing."""

    async def start(self) -> None:
        pass

    async def aclose(self) -> None:
        pass

    async def get(self) -> MaintenanceState:
        raise RuntimeError("simulated store outage")

    async def set(self, state: MaintenanceState) -> None:
        raise AssertionError("not exercised by this test")


def test_get_fails_open_when_store_is_unreachable(maintenance_client):
    client, _state = maintenance_client
    client.app.dependency_overrides.clear()  # GET requires no auth at all
    client.app.state.maintenance_mode_store = _BrokenGetStore()

    resp = client.get("/v1/admin/maintenance")
    assert resp.status_code == 200
    body = resp.json()
    assert body["enabled"] is False
    assert body["reason"] is None
