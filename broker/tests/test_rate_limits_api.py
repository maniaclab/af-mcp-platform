"""Tests for GET /v1/rate-limits: the configured ``rate_limits`` rules plus the caller's own usage of each (issue #165 follow-up).

Usage is read from a real redis server (the ``shared_state_url`` fixture)
through the limiter's own key function; nothing is mocked.
"""

from __future__ import annotations

import asyncio
import uuid

import structlog

from af_mcp_broker.authorization import EntitlementPolicy, RateLimitRule
from af_mcp_broker.authorization.rate_limit import tool_rate_limit_key
from af_mcp_broker.shared_state import RedisSharedState

STATE_CHANGE_RULE = RateLimitRule(60, 300, action_type="state_change")
CONDOR_RULE = RateLimitRule(30, 300, tool="condor_submit_*")


def _seed(url: str, rule: RateLimitRule, subject: str, calls: int) -> None:
    """Count *calls* against *rule* for *subject*, as the limiter would."""

    async def _run() -> None:
        store = RedisSharedState(url)
        try:
            for _ in range(calls):
                await store.incr_window(
                    tool_rate_limit_key(rule, subject), rule.window_seconds
                )
        finally:
            await store.close()

    asyncio.run(_run())


def _install(client, url: str | None, *rules: RateLimitRule) -> None:
    policy = EntitlementPolicy()
    policy.rate_limits = list(rules)
    client.app.state.entitlement_policy = policy
    client.app.state.shared_state = RedisSharedState(url) if url else None


def test_returns_rules_with_the_callers_usage(
    app_client, make_principal, shared_state_url
) -> None:
    client, state = app_client
    subject = f"sub-{uuid.uuid4()}"
    state["principal"] = make_principal(subject=subject)
    _install(client, shared_state_url, STATE_CHANGE_RULE, CONDOR_RULE)
    _seed(shared_state_url, STATE_CHANGE_RULE, subject, calls=12)

    resp = client.get("/v1/rate-limits")

    assert resp.status_code == 200
    body = resp.json()
    assert body["usage_available"] is True
    first, second = body["rate_limits"]
    assert 0 < first.pop("resets_in_seconds") <= 300
    assert first == {
        "action_type": "state_change",
        "tool": None,
        "limit": 60,
        "window_seconds": 300,
        "used": 12,
    }
    # No window is open for a rule the caller never matched.
    assert second == {
        "action_type": None,
        "tool": "condor_submit_*",
        "limit": 30,
        "window_seconds": 300,
        "used": 0,
        "resets_in_seconds": None,
    }


def test_usage_never_includes_another_users_count(
    app_client, make_principal, shared_state_url
) -> None:
    client, state = app_client
    me, other = f"sub-{uuid.uuid4()}", f"sub-{uuid.uuid4()}"
    state["principal"] = make_principal(subject=me)
    _install(client, shared_state_url, CONDOR_RULE)
    _seed(shared_state_url, CONDOR_RULE, other, calls=29)
    _seed(shared_state_url, CONDOR_RULE, me, calls=2)

    [rule] = client.get("/v1/rate-limits").json()["rate_limits"]

    assert rule["used"] == 2


def test_unreachable_store_returns_rules_with_unknown_usage(
    app_client, make_principal, unreachable_shared_state_url
) -> None:
    client, state = app_client
    state["principal"] = make_principal(subject=f"sub-{uuid.uuid4()}")
    _install(client, unreachable_shared_state_url, STATE_CHANGE_RULE)

    with structlog.testing.capture_logs() as logs:
        resp = client.get("/v1/rate-limits")

    assert resp.status_code == 200
    body = resp.json()
    assert body["usage_available"] is False
    [rule] = body["rate_limits"]
    assert (rule["limit"], rule["window_seconds"]) == (60, 300)
    assert rule["used"] is None
    assert rule["resets_in_seconds"] is None
    assert "rate_limits.shared_state_unavailable" in [log["event"] for log in logs]


def test_no_store_installed_marks_usage_unknown(app_client, make_principal) -> None:
    client, state = app_client
    state["principal"] = make_principal(subject=f"sub-{uuid.uuid4()}")
    _install(client, None, STATE_CHANGE_RULE)

    body = client.get("/v1/rate-limits").json()

    assert body["usage_available"] is False
    assert body["rate_limits"][0]["used"] is None


def test_no_rules_configured_returns_an_empty_list(
    app_client, make_principal, unreachable_shared_state_url
) -> None:
    client, state = app_client
    state["principal"] = make_principal(subject=f"sub-{uuid.uuid4()}")
    # An unreachable store proves it is never touched: no rules, no read.
    _install(client, unreachable_shared_state_url)

    resp = client.get("/v1/rate-limits")

    assert resp.json() == {"rate_limits": [], "usage_available": True}
