"""Tests for ``GET /v1/usage`` -- self-service usage with read-time cost.

The endpoint is self-scoped by default (a caller sees only their own
subject's aggregates) with one override: a caller in ``settings.admin_group``
may pass ``?subject=`` to view another subject's usage instead of their own
(see the admin-override tests below). It prices stored token ESTIMATES at
read time via tokencost's bundled static price table -- dollars are never
stored, and no network is ever touched (the pod is egress-deny; see the
socket-disabled test). ``PINNED_MODEL`` must stay a key of the installed
tokencost's TOKEN_COSTS so the expected costs below are plain Decimal math
against the bundled table.
"""

from __future__ import annotations

import asyncio
import socket
import time
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

import pytest
from tokencost import (  # type: ignore[import-untyped]
    TOKEN_COSTS,
    calculate_cost_by_tokens,
)

from af_mcp_broker.audit import AuditRecord

if TYPE_CHECKING:
    from collections.abc import Callable

    from fastapi.testclient import TestClient

# The broker's default cost_reference_model (config.py) -- pinned here so a
# tokencost upgrade that drops the key fails these tests loudly instead of
# silently 422ing every default-model /v1/usage call in production.
PINNED_MODEL = "claude-sonnet-4-20250514"


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
    store = client.app.state.usage_store  # type: ignore[attr-defined]

    async def _fill() -> None:
        for record in records:
            await store.record(record)

    asyncio.run(_fill())


def test_default_model_is_in_the_bundled_price_table() -> None:
    """The proof behind the config default: the key must exist in the
    installed tokencost's static table, with an input price to bill at."""
    assert PINNED_MODEL in TOKEN_COSTS
    assert TOKEN_COSTS[PINNED_MODEL]["input_cost_per_token"] > 0


def test_cost_estimation_requires_no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """tokencost loads only its bundled static price JSON at import; pricing
    must keep working with sockets disabled entirely (egress-deny pod).
    update_token_costs/refresh_prices, which do fetch, are never called."""

    def _no_network(*args: Any, **kwargs: Any) -> None:
        raise RuntimeError("network disabled in this test")

    monkeypatch.setattr(socket, "socket", _no_network)
    cost = calculate_cost_by_tokens(1000, PINNED_MODEL, token_type="input")
    assert float(cost) > 0


def test_usage_empty_store_returns_zeroed_window(app_client) -> None:
    client, _ = app_client
    resp = client.get("/v1/usage")
    assert resp.status_code == 200, resp.text

    body = resp.json()
    assert body["subject"] == "sub-abc"
    assert body["window_days"] == 30
    assert body["cost_model"] == PINNED_MODEL
    assert body["totals"] == {
        "calls": 0,
        "errors": 0,
        "duration_ms": 0.0,
        "result_bytes": 0,
        "result_tokens_est": 0,
        "estimated_cost_usd": 0.0,
    }
    assert body["by_service"] == []
    assert body["by_day"] == []


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

    expected_total_cost = float(
        calculate_cost_by_tokens(1500, PINNED_MODEL, token_type="input")
    )
    assert body["totals"] == {
        "calls": 3,
        "errors": 1,
        "duration_ms": pytest.approx(30.0),
        "result_bytes": 210,
        # The unmeasured (None) record counts its call and bytes but adds no
        # tokens and no cost.
        "result_tokens_est": 1500,
        "estimated_cost_usd": pytest.approx(expected_total_cost),
    }

    by_service = {entry["service"]: entry for entry in body["by_service"]}
    assert set(by_service) == {"rucio", "ami"}
    assert by_service["rucio"]["calls"] == 2
    assert by_service["rucio"]["errors"] == 1
    assert by_service["rucio"]["result_tokens_est"] == 1000
    assert by_service["rucio"]["estimated_cost_usd"] == pytest.approx(
        float(calculate_cost_by_tokens(1000, PINNED_MODEL, token_type="input"))
    )
    assert by_service["ami"]["calls"] == 1
    assert by_service["ami"]["errors"] == 0

    today = datetime.now(tz=UTC).date().isoformat()
    assert body["by_day"] == [{"date": today, "calls": 3, "result_tokens_est": 1500}]


def test_usage_model_override_reprices_the_window(app_client) -> None:
    client, _ = app_client
    _seed(client, _record())

    # Any second Claude key from the bundled table works; this one is pinned
    # for the same fail-loudly reason as PINNED_MODEL.
    other = "claude-3-5-sonnet-20241022"
    resp = client.get("/v1/usage", params={"model": other})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["cost_model"] == other
    assert body["totals"]["estimated_cost_usd"] == pytest.approx(
        float(calculate_cost_by_tokens(1000, other, token_type="input"))
    )


def test_usage_unknown_model_is_422_without_dumping_the_table(app_client) -> None:
    client, _ = app_client
    resp = client.get("/v1/usage", params={"model": "not-a-real-model"})
    assert resp.status_code == 422, resp.text
    detail = resp.json()["detail"]
    assert "not-a-real-model" in detail
    # The table has thousands of keys -- the error must not enumerate them.
    assert PINNED_MODEL not in detail


@pytest.mark.parametrize("days", [0, 366, -1])
def test_usage_days_out_of_bounds_is_422(app_client, days: int) -> None:
    client, _ = app_client
    resp = client.get("/v1/usage", params={"days": days})
    assert resp.status_code == 422, resp.text


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

    from af_mcp_broker.app import app
    from af_mcp_broker.identity import keycloak_dependency

    saved = app.dependency_overrides.pop(keycloak_dependency, None)
    try:
        resp = client.get("/v1/usage")
    finally:
        if saved is not None:
            app.dependency_overrides[keycloak_dependency] = saved

    assert resp.status_code == 401, resp.text
