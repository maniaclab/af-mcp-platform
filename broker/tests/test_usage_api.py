"""Tests for ``GET /v1/usage`` -- self-service usage accounting.

The endpoint is self-scoped by default (a caller sees only their own
subject's aggregates) with one override: a caller in ``settings.admin_group``
may pass ``?subject=`` to view another subject's usage instead of their own
(see the admin-override tests below). It reports stored token ESTIMATES
(counts only; the broker attaches no monetary figure to them).
"""

from __future__ import annotations

import asyncio
import time
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

import pytest
from broker_state_helpers import set_broker_state

from af_mcp_broker.api.auth import keycloak_dependency
from af_mcp_broker.app import app
from af_mcp_broker.audit import AuditRecord
from af_mcp_broker.audit.measure import ContentMeasure

if TYPE_CHECKING:
    from collections.abc import Callable

    from fastapi.testclient import TestClient


def _record(**overrides: Any) -> AuditRecord:
    fields: dict[str, Any] = {
        "principal_sub": "sub-abc",
        "principal_uid": 1000,
        "permission": "read_data",
        "target": "rucio",
        "action": "rucio_list_dids",
        "action_type": "read",
        "args_summary": "scope=...",
        "timestamp": time.time(),
        "request_id": "req-1",
        "mcp_service": "rucio",
        "outcome": "success",
        "duration_ms": 10.0,
        "result_bytes": 100,
        "result_tokens_est": 1000,
    }
    fields.update(overrides)
    return AuditRecord(**fields)


def _seed(client: TestClient, *records: AuditRecord) -> None:
    """Seed the app's installed (in-memory) usage store directly."""
    store = client.app.state.broker.usage_store  # type: ignore[attr-defined]

    async def _fill() -> None:
        for record in records:
            await store.record(record)

    asyncio.run(_fill())


def test_usage_response_has_no_cost_fields(app_client) -> None:
    """Token counts are the only size measure the API exposes: no price,
    dollar, or model-selection field appears anywhere in the response."""
    client, _ = app_client
    _seed(client, _record())

    body = client.get("/v1/usage").json()

    def _keys(node: Any) -> set[str]:
        if isinstance(node, dict):
            return set(node) | {k for v in node.values() for k in _keys(v)}
        if isinstance(node, list):
            return {k for v in node for k in _keys(v)}
        return set()

    forbidden = ("cost", "price", "usd", "model")
    assert not [k for k in _keys(body) if any(f in k.lower() for f in forbidden)]


def test_usage_ignores_a_model_query_parameter(app_client) -> None:
    """``model`` is not a parameter of this endpoint: it is ignored and does
    not change the response."""
    client, _ = app_client
    _seed(client, _record())

    plain = client.get("/v1/usage").json()
    with_model = client.get("/v1/usage", params={"model": "anything"})
    assert with_model.status_code == 200, with_model.text
    assert with_model.json() == plain


def test_usage_empty_store_returns_zeroed_window(app_client) -> None:
    client, _ = app_client
    resp = client.get("/v1/usage")
    assert resp.status_code == 200, resp.text

    body = resp.json()
    assert body["subject"] == "sub-abc"
    assert body["window_days"] == 30
    assert body["totals"] == {
        "calls": 0,
        "errors": 0,
        "duration_ms": 0.0,
        "result_bytes": 0,
        "result_tokens_est": 0,
    }
    assert body["by_service"] == []
    assert body["by_day"] == []
    assert body["by_content_type"] == []


def test_usage_by_content_type_lists_the_breakdown(app_client) -> None:
    """The response carries the totals AND the per-content-type breakdown; a
    record with no breakdown adds to the totals but to no content type."""
    client, _ = app_client
    _seed(
        client,
        _record(
            result_bytes=32_029,
            result_tokens_est=428,
            result_content={
                "text": ContentMeasure(blocks=1, bytes=29, tokens_est=14),
                "image": ContentMeasure(blocks=1, bytes=32_000, tokens_est=414),
            },
        ),
        _record(
            result_content={"image": ContentMeasure(blocks=1, bytes=10, tokens_est=64)},
            result_bytes=10,
            result_tokens_est=64,
        ),
        _record(result_content=None),
    )

    body = client.get("/v1/usage").json()

    assert body["totals"]["result_bytes"] == 32_029 + 10 + 100
    assert body["by_content_type"] == [
        {"content_type": "image", "blocks": 2, "bytes": 32_010, "tokens_est": 478},
        {"content_type": "text", "blocks": 1, "bytes": 29, "tokens_est": 14},
    ]


def test_usage_totals_by_service_and_by_day(app_client) -> None:
    client, _ = app_client
    _seed(
        client,
        _record(),
        _record(outcome="error", result_bytes=10, result_tokens_est=None),
        _record(mcp_service="ami", action="ami_list_datasets", result_tokens_est=500),
    )

    resp = client.get("/v1/usage")
    assert resp.status_code == 200, resp.text
    body = resp.json()

    assert body["totals"] == {
        "calls": 3,
        "errors": 1,
        "duration_ms": pytest.approx(30.0),
        "result_bytes": 210,
        # The unmeasured (None) record counts its call and bytes but adds no
        # tokens.
        "result_tokens_est": 1500,
    }

    by_service = {entry["service"]: entry for entry in body["by_service"]}
    assert set(by_service) == {"rucio", "ami"}
    assert by_service["rucio"]["calls"] == 2
    assert by_service["rucio"]["errors"] == 1
    assert by_service["rucio"]["result_tokens_est"] == 1000
    assert by_service["ami"]["calls"] == 1
    assert by_service["ami"]["errors"] == 0

    today = datetime.now(tz=UTC).date().isoformat()
    assert body["by_day"] == [{"date": today, "calls": 3, "result_tokens_est": 1500}]


@pytest.mark.parametrize("days", [0, 366, -1])
def test_usage_days_out_of_bounds_is_422(app_client, days: int) -> None:
    client, _ = app_client
    resp = client.get("/v1/usage", params={"days": days})
    assert resp.status_code == 422, resp.text
    assert resp.json()["detail"][0]["loc"] == ["query", "days"]


def test_usage_is_scoped_to_the_calling_subject(app_client, make_principal) -> None:
    """Seed two subjects; each caller sees only their own usage -- there is
    no parameter that reaches anyone else's."""
    client, state = app_client
    _seed(client, _record(), _record(principal_sub="sub-other", result_tokens_est=7))

    resp = client.get("/v1/usage")
    assert resp.json()["totals"]["calls"] == 1
    assert resp.json()["totals"]["result_tokens_est"] == 1000

    state["principal"] = make_principal(subject="sub-other")
    resp = client.get("/v1/usage")
    body = resp.json()
    assert body["subject"] == "sub-other"
    assert body["totals"]["calls"] == 1
    assert body["totals"]["result_tokens_est"] == 7


def test_usage_subject_override_requires_admin(
    monkeypatch: pytest.MonkeyPatch,
    app_client_factory: Callable[..., object],
    make_principal: Callable[..., object],
) -> None:
    """A non-admin caller passing ?subject= is rejected -- it never silently
    falls back to serving their own usage instead."""
    monkeypatch.setenv("ADMIN_GROUP", "af-admins")

    with app_client_factory() as (client, state):
        state["principal"] = make_principal(groups=["atlas"])
        resp = client.get("/v1/usage", params={"subject": "sub-other"})

    assert resp.status_code == 403, resp.text
    assert "admin" in resp.json()["detail"].lower()


def test_usage_subject_override_for_admin_returns_that_subjects_usage(
    monkeypatch: pytest.MonkeyPatch,
    app_client_factory: Callable[..., object],
    make_principal: Callable[..., object],
) -> None:
    monkeypatch.setenv("ADMIN_GROUP", "af-admins")

    with app_client_factory() as (client, state):
        state["principal"] = make_principal(groups=["atlas", "af-admins"])
        _seed(
            client,
            _record(),
            _record(principal_sub="sub-other", result_tokens_est=7),
        )

        resp = client.get("/v1/usage", params={"subject": "sub-other"})

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["subject"] == "sub-other"
    assert body["totals"]["calls"] == 1
    assert body["totals"]["result_tokens_est"] == 7


def test_usage_subject_override_for_admin_matching_own_subject_is_a_noop(
    monkeypatch: pytest.MonkeyPatch,
    app_client_factory: Callable[..., object],
    make_principal: Callable[..., object],
) -> None:
    """An admin passing their own subject back gets the same result as
    omitting the parameter entirely -- the override is not a special path
    when it happens to match the caller."""
    monkeypatch.setenv("ADMIN_GROUP", "af-admins")

    with app_client_factory() as (client, state):
        state["principal"] = make_principal(groups=["atlas", "af-admins"])
        _seed(client, _record())

        resp = client.get("/v1/usage", params={"subject": "sub-abc"})

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["subject"] == "sub-abc"
    assert body["totals"]["calls"] == 1
    assert body["totals"]["result_tokens_est"] == 1000


def test_usage_requires_authentication(app_client) -> None:
    """Missing bearer is a 401 from the real keycloak_dependency (the
    override-removal technique test_tokens_api.py uses)."""
    client, _ = app_client

    saved = app.dependency_overrides.pop(keycloak_dependency, None)
    try:
        resp = client.get("/v1/usage")
    finally:
        if saved is not None:
            app.dependency_overrides[keycloak_dependency] = saved

    assert resp.status_code == 401, resp.text
    assert resp.json()["detail"] == "Not authenticated"


def test_usage_subjects_requires_admin(app_client_factory) -> None:
    with app_client_factory() as (client, _state):
        resp = client.get("/v1/usage/subjects")
        assert resp.status_code == 403
        assert (
            resp.json()["detail"]
            == "This action requires membership in the admin group."
        )


def test_usage_subjects_resolves_unixname(
    app_client_factory, monkeypatch, make_principal, static_principal_cache
) -> None:
    monkeypatch.setenv("ADMIN_GROUP", "af-admins")
    cache, directory = static_principal_cache
    directory.groups_by_subject["someone-else"] = ["atlas"]
    directory.posix_by_subject["someone-else"] = {"unixname": "sperson"}

    with app_client_factory() as (client, state):
        state["principal"] = make_principal(groups=["atlas", "af-admins"])
        set_broker_state(client.app, principal_cache=cache)
        _seed(client, _record(principal_sub="someone-else"))

        resp = client.get("/v1/usage/subjects")

    assert resp.status_code == 200, resp.text
    assert {
        "subject": "someone-else",
        "unixname": "sperson",
        "email": "",
    } in resp.json()["subjects"]


def test_usage_subjects_falls_back_to_bare_subject_when_unresolvable(
    app_client_factory, monkeypatch, make_principal, static_principal_cache
) -> None:
    """A subject the principal directory no longer knows about (e.g. a
    deleted user) still appears in the list -- with no unixname/email,
    rather than 500ing or silently dropping them from the response."""
    monkeypatch.setenv("ADMIN_GROUP", "af-admins")
    cache, directory = static_principal_cache
    directory.unavailable_subjects.add("ghost")

    with app_client_factory() as (client, state):
        state["principal"] = make_principal(groups=["atlas", "af-admins"])
        set_broker_state(client.app, principal_cache=cache)
        _seed(client, _record(principal_sub="ghost"))

        resp = client.get("/v1/usage/subjects")

    assert resp.status_code == 200, resp.text
    assert {"subject": "ghost", "unixname": None, "email": ""} in resp.json()[
        "subjects"
    ]
