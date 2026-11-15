"""What a request sees when the app has no entitlement policy published."""

from __future__ import annotations


def test_absent_policy_answers_with_an_empty_policy(app_client) -> None:
    client, _state = app_client
    del client.app.state.entitlement_policy

    resp = client.get("/v1/entitlements")

    assert resp.status_code == 200
    assert resp.json()["group_permissions"] == {}
