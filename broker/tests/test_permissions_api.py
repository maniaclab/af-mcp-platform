"""Tests for GET /v1/permissions (caller's groups + grants) and
GET /v1/entitlements (the static group->permission reference table).

Both help a signed-in-but-denied user see *why*: /v1/permissions answers
"what am I in, and what does that grant me", /v1/entitlements answers "what
would grant me X" -- see docs/plans/2026-09-01-ops-platform-usability.md.
"""

from __future__ import annotations

import pytest

from af_mcp_broker.authorization import PERMISSIONS, EntitlementPolicy


def test_permissions_includes_callers_raw_groups(app_client, make_principal) -> None:
    client, state = app_client
    client.app.state.entitlement_policy = EntitlementPolicy(
        group_permissions={"atlas": ["read_data"], "admins": ["admin"]}
    )
    state["principal"] = make_principal(groups=["atlas", "some-other-group"])

    resp = client.get("/v1/permissions")

    assert resp.status_code == 200
    body = resp.json()
    assert set(body["groups"]) == {"atlas", "some-other-group"}


def test_permissions_groups_empty_for_no_group_membership(
    app_client, make_principal
) -> None:
    client, state = app_client
    state["principal"] = make_principal(groups=[])
    resp = client.get("/v1/permissions")
    assert resp.status_code == 200
    assert resp.json()["groups"] == []


def test_entitlements_returns_the_full_policy_table(app_client) -> None:
    client, _state = app_client
    client.app.state.entitlement_policy = EntitlementPolicy(
        group_permissions={
            "atlas": ["read_data", "submit_jobs"],
            "admins": ["admin"],
        }
    )

    resp = client.get("/v1/entitlements")

    assert resp.status_code == 200
    assert resp.json()["group_permissions"] == {
        "atlas": ["read_data", "submit_jobs"],
        "admins": ["admin"],
    }


def _entitlement_catalog(client) -> list[dict]:
    resp = client.get("/v1/entitlements")
    assert resp.status_code == 200
    return resp.json()["permissions"]


@pytest.mark.parametrize("name", list(PERMISSIONS))
def test_entitlements_catalog_lists_each_builtin_with_its_kind_and_description(
    app_client, name
) -> None:
    client, _state = app_client
    client.app.state.entitlement_policy = EntitlementPolicy()

    by_name = {entry["name"]: entry for entry in _entitlement_catalog(client)}

    assert by_name[name] == {
        "name": name,
        "action_type": PERMISSIONS[name].action_type,
        "description": PERMISSIONS[name].description,
    }


def test_entitlements_catalog_carries_custom_permissions_without_a_description(
    app_client,
) -> None:
    client, _state = app_client
    client.app.state.entitlement_policy = EntitlementPolicy(
        group_permissions={"atlas": ["exec_jobs"]},
        custom_permissions={"exec_jobs": "state_change", "peek_logs": "read"},
    )

    by_name = {entry["name"]: entry for entry in _entitlement_catalog(client)}

    assert by_name["exec_jobs"] == {
        "name": "exec_jobs",
        "action_type": "state_change",
        "description": None,
    }
    assert by_name["peek_logs"] == {
        "name": "peek_logs",
        "action_type": "read",
        "description": None,
    }


def test_entitlements_catalog_orders_builtins_then_customs_in_policy_order(
    app_client,
) -> None:
    client, _state = app_client
    client.app.state.entitlement_policy = EntitlementPolicy(
        custom_permissions={"zeta": "read", "alpha": "state_change"},
    )

    names = [entry["name"] for entry in _entitlement_catalog(client)]

    assert names == [*PERMISSIONS, "zeta", "alpha"]


def test_entitlements_catalog_includes_an_undeclared_name_a_group_grants(
    app_client,
) -> None:
    """Startup validation only checks services' required permissions, so a
    group can grant a name that is neither built-in nor custom. It is listed
    last, with the action type the shared resolver yields ("read")."""
    client, _state = app_client
    client.app.state.entitlement_policy = EntitlementPolicy(
        group_permissions={"atlas": ["read_data", "typo_perm"], "ops": ["typo_perm"]},
        custom_permissions={"exec_jobs": "state_change"},
    )

    catalog = _entitlement_catalog(client)

    assert [entry["name"] for entry in catalog] == [
        *PERMISSIONS,
        "exec_jobs",
        "typo_perm",
    ]
    assert catalog[-1] == {
        "name": "typo_perm",
        "action_type": "read",
        "description": None,
    }


def test_entitlements_catalog_leaves_group_permissions_unchanged(app_client) -> None:
    client, _state = app_client
    group_permissions = {"atlas": ["read_data", "exec_jobs"], "admins": ["admin"]}
    client.app.state.entitlement_policy = EntitlementPolicy(
        group_permissions=group_permissions,
        custom_permissions={"exec_jobs": "state_change"},
    )

    resp = client.get("/v1/entitlements")

    assert resp.json()["group_permissions"] == group_permissions


def test_grants_report_a_custom_permissions_declared_action_type(
    app_client, make_principal
) -> None:
    """The portal's token picker groups by a grant's action_types, so a custom
    state_change permission must not be reported as "read"."""
    client, state = app_client
    client.app.state.entitlement_policy = EntitlementPolicy(
        group_permissions={"atlas": ["exec_jobs", "read_data"]},
        custom_permissions={"exec_jobs": "state_change"},
    )
    state["principal"] = make_principal(groups=["atlas"])

    resp = client.get("/v1/permissions")

    action_types = {g["permission"]: g["action_types"] for g in resp.json()["grants"]}
    assert action_types == {"exec_jobs": ["state_change"], "read_data": ["read"]}


def test_grants_reflect_every_permission_a_dict_form_service_can_require(
    app_client, make_principal
) -> None:
    """A caller holding both of a dict-form service's declared permissions
    must see that service listed as a target under BOTH grants -- not just
    the one matching some single top-level value (issue: per-tool
    required_permission, condor_service's query_jobs/manage_jobs split)."""
    from af_mcp_broker.mcp.registry import ServiceSpec

    client, state = app_client
    client.app.state.entitlement_policy = EntitlementPolicy(
        group_permissions={"atlas": ["read_monitoring", "manage_jobs"]}
    )
    client.app.state.service_registry.register(
        ServiceSpec(
            name="condor_service",
            prefix="condor",
            url="http://condor.invalid/mcp",
            transport="http",
            required_permission={
                "__default__": "manage_jobs",
                "query_jobs": "read_monitoring",
            },
        )
    )
    state["principal"] = make_principal(groups=["atlas"])

    resp = client.get("/v1/permissions")

    assert resp.status_code == 200
    grants = {g["permission"]: g["targets"] for g in resp.json()["grants"]}
    assert "condor_service" in grants["read_monitoring"]
    assert "condor_service" in grants["manage_jobs"]


def test_entitlements_requires_authentication(app_client_factory) -> None:
    """Reference table or not, this still goes through keycloak_dependency
    like every other /v1 route -- an unauthenticated caller gets the same
    401 as anywhere else, not a special-cased public route."""
    from af_mcp_broker.identity import keycloak_dependency

    with app_client_factory() as (client, _state):
        client.app.dependency_overrides.pop(keycloak_dependency, None)
        resp = client.get("/v1/entitlements")
    assert resp.status_code == 401
