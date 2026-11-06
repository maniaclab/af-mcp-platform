"""Tests for the admin API -- POST/GET /v1/admin/maintenance."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
import structlog
from fastmcp.server.providers.proxy import ProxyTool
from mcp.types import Tool as McpTool

from af_mcp_broker.maintenance import (
    InMemoryMaintenanceModeStore,
    MaintenanceModeStore,
    MaintenanceState,
    MaintenanceStateConflict,
)
from af_mcp_broker.mcp import aggregator
from af_mcp_broker.mcp.middleware import entitlement_mw
from af_mcp_broker.mcp.middleware.entitlement_mw import EntitlementMiddleware
from af_mcp_broker.mcp.registry import ServiceSpec


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


# ---------------------------------------------------------------------------
# GET /v1/admin/annotation-mismatches (issue #238 B.8)
# ---------------------------------------------------------------------------


def test_annotation_mismatches_requires_admin(maintenance_client):
    client, _state = maintenance_client  # default principal has no admin group
    resp = client.get("/v1/admin/annotation-mismatches")
    assert resp.status_code == 403


def test_annotation_mismatches_empty_by_default(maintenance_client, make_principal):
    client, state = maintenance_client
    state["principal"] = make_principal(groups=["af-admins"])

    resp = client.get("/v1/admin/annotation-mismatches")
    assert resp.status_code == 200
    assert resp.json() == []


def test_annotation_mismatches_reflects_registry_state(
    maintenance_client, make_principal
):
    """The endpoint exposes exactly what EntitlementMiddleware's lint
    already recorded (mcp/registry.py's ServiceRegistry.record_annotation_
    mismatch) -- no second, separately-probed comparison."""
    from af_mcp_broker.mcp.registry import AnnotationMismatch

    client, state = maintenance_client
    state["principal"] = make_principal(groups=["af-admins"])
    client.app.state.service_registry.record_annotation_mismatch(
        AnnotationMismatch(
            service="rucio",
            tool="rucio_list_dids",
            declared_read_only_hint=False,
            resolved_action_type="read",
            resolved_via="permission",
            permission="read_data",
        )
    )

    resp = client.get("/v1/admin/annotation-mismatches")
    assert resp.status_code == 200
    assert resp.json() == [
        {
            "service": "rucio",
            "tool": "rucio_list_dids",
            "declared_read_only_hint": False,
            "resolved_action_type": "read",
            "resolved_via": "permission",
            "permission": "read_data",
        }
    ]


# ---------------------------------------------------------------------------
# GET /v1/admin/tool-mapping-drift (issue #330)
# ---------------------------------------------------------------------------


def test_tool_mapping_drift_requires_admin(maintenance_client):
    client, _state = maintenance_client
    resp = client.get("/v1/admin/tool-mapping-drift")
    assert resp.status_code == 403


def test_tool_mapping_drift_empty_by_default(maintenance_client, make_principal):
    client, state = maintenance_client
    state["principal"] = make_principal(groups=["af-admins"])

    resp = client.get("/v1/admin/tool-mapping-drift")
    assert resp.status_code == 200
    assert resp.json() == []


def test_tool_mapping_drift_reflects_registry_state(maintenance_client, make_principal):
    from af_mcp_broker.mcp.registry import ToolMappingDrift

    client, state = maintenance_client
    state["principal"] = make_principal(groups=["af-admins"])
    client.app.state.service_registry.record_tool_mapping_drift(
        ToolMappingDrift(
            service="condor_service",
            prefix="condor",
            advertised=2,
            routable=2,
            unmapped=("condor_submit_job",),
            stale=("condor_old_tool",),
            unroutable=(),
        )
    )

    resp = client.get("/v1/admin/tool-mapping-drift")
    assert resp.status_code == 200
    assert resp.json() == [
        {
            "service": "condor_service",
            "prefix": "condor",
            "advertised": 2,
            "routable": 2,
            "unmapped": ["condor_submit_job"],
            "stale": ["condor_old_tool"],
            "unroutable": [],
        }
    ]


# ---------------------------------------------------------------------------
# A backend renamed its tools away from an apply_namespace: false service's
# prefix (atlas-search-mcp-bridge's atlas_opensearch_* -> aos_*, twice in
# production). Driven through the real provider and middleware rather than
# by seeding registry state, so the test fails if either stops recording.
# ---------------------------------------------------------------------------

_AOS_TOOLS = ("aos_aggregate", "aos_describe", "aos_inspect", "aos_query", "aos_search")
_OLD_AOS_KEYS = (
    "atlas_opensearch_aggregate",
    "atlas_opensearch_describe",
    "atlas_opensearch_inspect",
    "atlas_opensearch_query",
    "atlas_opensearch_search",
)


def _list_renamed_backend(
    client, monkeypatch, advertised: tuple[str, ...]
) -> list[dict]:
    """Register the old atlas_search_service config, then list its backend
    (advertising *advertised*) through its provider and EntitlementMiddleware.

    Returns the captured log events. Both modules' loggers are swapped for
    throwaway ones: the booted app configures structlog with
    cache_logger_on_first_use, so the real module loggers' first use here
    would pin them to this app boot's processor list, which the next boot
    replaces -- and capture_logs in every later test (test_mcp_aggregator.py)
    would then stop seeing their events.
    """
    monkeypatch.setattr(aggregator, "logger", structlog.get_logger(aggregator.__name__))
    monkeypatch.setattr(
        entitlement_mw, "logger", structlog.get_logger(entitlement_mw.__name__)
    )
    registry = client.app.state.service_registry
    registry.register(
        ServiceSpec(
            name="atlas_search_service",
            prefix="atlas_opensearch",
            url="http://atlas-search.invalid/mcp",
            transport="http",
            required_permission=dict.fromkeys(_OLD_AOS_KEYS, "read_data"),
            # No credential needed, so nothing but routing can make this
            # service anything other than "available".
            auth_type="none",
            apply_namespace=False,
        )
    )
    upstream = [
        ProxyTool.from_mcp_tool(
            lambda: None, McpTool(name=name, input_schema={"type": "object"})
        )
        for name in advertised
    ]
    monkeypatch.setattr(
        aggregator.ProxyProvider, "_list_tools", AsyncMock(return_value=upstream)
    )

    async def _factory():
        raise AssertionError("ProxyProvider._list_tools is stubbed above")

    provider = aggregator._ObservableProxyProvider(
        "atlas_search_service",
        _factory,
        registry=registry,
        route_prefix="atlas_opensearch",
    )
    mw = EntitlementMiddleware(registry, client.app.state.entitlement_policy)

    async def _run() -> None:
        tools = await provider._list_tools()

        async def _call_next(_context):
            return tools

        # No fastmcp context: the lint still runs on the full listing, and
        # the (fail-closed) filtered result is irrelevant here.
        await mw.on_list_tools(SimpleNamespace(fastmcp_context=None), _call_next)

    with structlog.testing.capture_logs() as logs:
        asyncio.run(_run())
    return logs


def test_renamed_backend_is_drift_and_not_available(
    maintenance_client, make_principal, monkeypatch
):
    client, state = maintenance_client
    state["principal"] = make_principal(groups=["af-admins", "atlas"])

    logs = _list_renamed_backend(client, monkeypatch, _AOS_TOOLS)

    mismatch_events = [
        e for e in logs if e["event"] == "aggregator.tool_prefix_mismatch"
    ]
    assert len(mismatch_events) == 1
    assert mismatch_events[0]["count"] == 5

    drift = {d["service"]: d for d in client.get("/v1/admin/tool-mapping-drift").json()}
    assert drift["atlas_search_service"] == {
        "service": "atlas_search_service",
        "prefix": "atlas_opensearch",
        "advertised": 5,
        "routable": 0,
        "unmapped": [],
        "stale": list(_OLD_AOS_KEYS),
        "unroutable": list(_AOS_TOOLS),
    }

    servers = {s["name"]: s for s in client.get("/v1/catalog").json()["servers"]}
    service = servers["atlas_search_service"]
    assert service["status"] == "misconfigured"
    assert "5 advertised, 0 routable" in service["status_detail"]
    assert service["correlation_id"]


def test_matching_backend_has_no_drift_and_is_available(
    maintenance_client, make_principal, monkeypatch
):
    client, state = maintenance_client
    state["principal"] = make_principal(groups=["af-admins", "atlas"])

    logs = _list_renamed_backend(client, monkeypatch, _OLD_AOS_KEYS)

    assert not [e for e in logs if e["event"] == "aggregator.tool_prefix_mismatch"]
    assert client.get("/v1/admin/tool-mapping-drift").json() == []
    servers = {s["name"]: s for s in client.get("/v1/catalog").json()["servers"]}
    assert servers["atlas_search_service"]["status"] == "available"
