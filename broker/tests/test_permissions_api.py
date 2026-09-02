"""Tests for GET /v1/permissions (caller's groups + grants) and
GET /v1/entitlements (the static group->permission reference table).

Both help a signed-in-but-denied user see *why*: /v1/permissions answers
"what am I in, and what does that grant me", /v1/entitlements answers "what
would grant me X" -- see docs/plans/2026-09-01-ops-platform-usability.md.
"""

from __future__ import annotations

from af_mcp_broker.authorization import EntitlementPolicy


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


def test_entitlements_requires_authentication(app_client_factory) -> None:
    """Reference table or not, this still goes through keycloak_dependency
    like every other /v1 route -- an unauthenticated caller gets the same
    401 as anywhere else, not a special-cased public route."""
    from af_mcp_broker.identity import keycloak_dependency

    with app_client_factory() as (client, _state):
        client.app.dependency_overrides.pop(keycloak_dependency, None)
        resp = client.get("/v1/entitlements")
    assert resp.status_code == 401
