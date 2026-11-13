"""Unit tests for policy.yaml's ``rate_limits`` block (issue #165): rule parsing and validation, rule matching, the fixed-window counter, and rule precedence."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from af_mcp_broker.authorization import (
    EntitlementPolicy,
    RateLimitRule,
    load_policy,
)
from af_mcp_broker.authorization.errors import ToolRateLimitError
from af_mcp_broker.authorization.rate_limit import (
    InMemoryWindowCounter,
    WindowCount,
    check_rate_limits,
)
from af_mcp_broker.errors import BrokerError

if TYPE_CHECKING:
    from pathlib import Path


class _Clock:
    """Settable monotonic clock injected into the counter."""

    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def _write_policy(tmp_path: Path, body: str) -> str:
    path = tmp_path / "policy.yaml"
    path.write_text(body)
    return str(path)


# ---------------------------------------------------------------------------
# Parsing and fail-closed validation
# ---------------------------------------------------------------------------


def test_policy_without_rate_limits_has_no_rules(tmp_path: Path) -> None:
    path = _write_policy(tmp_path, "group_permissions: {}\n")
    assert load_policy(path).rate_limits == []
    assert EntitlementPolicy().rate_limits == []


def test_load_policy_reads_rate_limits(tmp_path: Path) -> None:
    path = _write_policy(
        tmp_path,
        """
rate_limits:
  - action_type: state_change
    limit: 20
    window_seconds: 60
  - tool: "condor_submit_*"
    action_type: state_change
    limit: 5
    window_seconds: 3600
""",
    )
    assert load_policy(path).rate_limits == [
        RateLimitRule(limit=20, window_seconds=60, action_type="state_change"),
        RateLimitRule(
            limit=5,
            window_seconds=3600,
            action_type="state_change",
            tool="condor_submit_*",
        ),
    ]


@pytest.mark.parametrize(
    ("rule", "needle"),
    [
        ("{action_type: write, limit: 1, window_seconds: 60}", "action_type"),
        ("{limit: 1, window_seconds: 60}", "action_type"),
        ("{tool: 'a_*', limit: 1}", "window_seconds"),
        ("{tool: 'a_*', window_seconds: 60}", "limit"),
        ("{tool: 'a_*', limit: 1, window_seconds: 0}", "window_seconds"),
        ("{tool: 'a_*', limit: 1, window_seconds: -5}", "window_seconds"),
        ("{tool: 'a_*', limit: 1, window_seconds: 1m}", "window_seconds"),
        ("{tool: 'a_*', limit: 1, window_seconds: 1.5}", "window_seconds"),
        ("{tool: 'a_*', limit: 1, window_seconds: true}", "window_seconds"),
        ("{tool: 'a_*', limit: 0, window_seconds: 60}", "limit"),
        ("{tool: 'a_*', limit: many, window_seconds: 60}", "limit"),
        ("{tool: '', limit: 1, window_seconds: 60}", "tool"),
        ("{tool: 'a_[b', limit: 1, window_seconds: 60}", "tool"),
        ("{tool: 5, limit: 1, window_seconds: 60}", "tool"),
        ("{tool: 'a_*', limit: 1, window_seconds: 60, burst: 3}", "burst"),
        ("not-a-mapping", "mapping"),
    ],
)
def test_load_policy_rejects_bad_rate_limit_rule(
    tmp_path: Path, rule: str, needle: str
) -> None:
    path = _write_policy(tmp_path, f"rate_limits:\n  - {rule}\n")
    with pytest.raises(ValueError, match=needle):
        load_policy(path)


def test_load_policy_rejects_non_list_rate_limits(tmp_path: Path) -> None:
    path = _write_policy(tmp_path, "rate_limits:\n  limit: 1\n")
    with pytest.raises(ValueError, match="list"):
        load_policy(path)


def test_rate_limit_validation_names_the_offending_rule(tmp_path: Path) -> None:
    path = _write_policy(
        tmp_path,
        "rate_limits:\n"
        "  - {tool: 'a_*', limit: 1, window_seconds: 60}\n"
        "  - {tool: 'b_*', limit: 1, window_seconds: 0}\n",
    )
    with pytest.raises(ValueError, match=r"rate_limits\[1\]"):
        load_policy(path)


# ---------------------------------------------------------------------------
# Matching
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("rule", "tool", "action_type", "expected"),
    [
        (RateLimitRule(1, 60, action_type="state_change"), "x_a", "state_change", True),
        (RateLimitRule(1, 60, action_type="state_change"), "x_a", "read", False),
        (
            RateLimitRule(1, 60, tool="condor_submit_*"),
            "condor_submit_job",
            "read",
            True,
        ),
        (
            RateLimitRule(1, 60, tool="condor_submit_*"),
            "condor_query_jobs",
            "read",
            False,
        ),
        # Both set: both must match.
        (
            RateLimitRule(1, 60, tool="condor_*", action_type="state_change"),
            "condor_submit_job",
            "state_change",
            True,
        ),
        (
            RateLimitRule(1, 60, tool="condor_*", action_type="state_change"),
            "condor_query_jobs",
            "read",
            False,
        ),
        (
            RateLimitRule(1, 60, tool="condor_*", action_type="state_change"),
            "rucio_add_rule",
            "state_change",
            False,
        ),
    ],
)
def test_rule_matching(
    rule: RateLimitRule, tool: str, action_type: str, expected: bool
) -> None:
    assert rule.matches(tool, action_type) is expected


# ---------------------------------------------------------------------------
# Windowing (injected clock)
# ---------------------------------------------------------------------------


async def test_counter_counts_within_a_window() -> None:
    counter = InMemoryWindowCounter(clock=_Clock())
    counts = [(await counter.incr_window("k", 60)).count for _ in range(3)]
    assert counts == [1, 2, 3]


async def test_counter_window_opens_at_first_increment_and_is_not_extended() -> None:
    clock = _Clock()
    counter = InMemoryWindowCounter(clock=clock)
    first = await counter.incr_window("k", 60)
    assert first == WindowCount(count=1, ttl_seconds=60.0)
    clock.now += 45
    later = await counter.incr_window("k", 60)
    assert later.count == 2
    assert later.ttl_seconds == pytest.approx(15.0)


async def test_counter_resets_once_the_window_closes() -> None:
    clock = _Clock()
    counter = InMemoryWindowCounter(clock=clock)
    await counter.incr_window("k", 60)
    await counter.incr_window("k", 60)
    clock.now += 60
    assert (await counter.incr_window("k", 60)) == WindowCount(1, 60.0)


async def test_counter_keys_are_independent() -> None:
    counter = InMemoryWindowCounter(clock=_Clock())
    await counter.incr_window("a", 60)
    assert (await counter.incr_window("b", 60)).count == 1


async def test_counter_drops_expired_keys() -> None:
    clock = _Clock()
    counter = InMemoryWindowCounter(clock=clock)
    for i in range(10):
        await counter.incr_window(f"k{i}", 10)
    clock.now += 3600
    await counter.incr_window("fresh", 10)
    assert counter.tracked_keys == 1


# ---------------------------------------------------------------------------
# Enforcement and precedence
# ---------------------------------------------------------------------------


async def test_no_rules_never_touches_the_counter() -> None:
    class _Exploding(InMemoryWindowCounter):
        async def incr_window(self, key: str, window_seconds: int) -> WindowCount:
            raise AssertionError("counter must not be used without rules")

    await check_rate_limits([], _Exploding(), "sub", "x_a", "read")


async def test_calls_up_to_the_limit_pass_and_the_next_is_denied() -> None:
    clock = _Clock()
    counter = InMemoryWindowCounter(clock=clock)
    rules = [RateLimitRule(2, 60, tool="x_*")]
    await check_rate_limits(rules, counter, "sub", "x_a", "read")
    await check_rate_limits(rules, counter, "sub", "x_a", "read")
    clock.now += 10
    with pytest.raises(ToolRateLimitError) as excinfo:
        await check_rate_limits(rules, counter, "sub", "x_a", "read")
    assert excinfo.value.retry_after_seconds == 50
    assert excinfo.value.limit == 2
    assert excinfo.value.window_seconds == 60
    assert isinstance(excinfo.value, BrokerError)


async def test_allowed_again_after_the_window_closes() -> None:
    clock = _Clock()
    counter = InMemoryWindowCounter(clock=clock)
    rules = [RateLimitRule(1, 60, tool="x_*")]
    await check_rate_limits(rules, counter, "sub", "x_a", "read")
    with pytest.raises(ToolRateLimitError):
        await check_rate_limits(rules, counter, "sub", "x_a", "read")
    clock.now += 60
    await check_rate_limits(rules, counter, "sub", "x_a", "read")


async def test_counting_is_per_subject_never_global() -> None:
    counter = InMemoryWindowCounter(clock=_Clock())
    rules = [RateLimitRule(1, 60, tool="x_*")]
    await check_rate_limits(rules, counter, "alice", "x_a", "read")
    await check_rate_limits(rules, counter, "bob", "x_a", "read")
    with pytest.raises(ToolRateLimitError):
        await check_rate_limits(rules, counter, "alice", "x_a", "read")


async def test_a_rule_counts_every_tool_it_matches_together() -> None:
    counter = InMemoryWindowCounter(clock=_Clock())
    rules = [RateLimitRule(2, 60, action_type="state_change")]
    await check_rate_limits(rules, counter, "sub", "x_a", "state_change")
    await check_rate_limits(rules, counter, "sub", "y_b", "state_change")
    with pytest.raises(ToolRateLimitError):
        await check_rate_limits(rules, counter, "sub", "z_c", "state_change")
    # A read matches no rule and is never limited.
    await check_rate_limits(rules, counter, "sub", "x_a", "read")


async def test_every_matching_rule_must_pass() -> None:
    """Precedence: all matching rules apply, the strictest one denies."""
    counter = InMemoryWindowCounter(clock=_Clock())
    rules = [
        RateLimitRule(100, 60, action_type="state_change"),
        RateLimitRule(1, 60, tool="condor_submit_*"),
    ]
    await check_rate_limits(rules, counter, "sub", "condor_submit_job", "state_change")
    with pytest.raises(ToolRateLimitError) as excinfo:
        await check_rate_limits(
            rules, counter, "sub", "condor_submit_job", "state_change"
        )
    assert excinfo.value.limit == 1
    # The broad rule has headroom, so a different state_change tool still passes.
    await check_rate_limits(rules, counter, "sub", "rucio_add_rule", "state_change")


async def test_retry_after_is_the_longest_wait_among_exceeded_rules() -> None:
    clock = _Clock()
    counter = InMemoryWindowCounter(clock=clock)
    rules = [
        RateLimitRule(1, 60, tool="x_*"),
        RateLimitRule(1, 3600, action_type="read"),
    ]
    await check_rate_limits(rules, counter, "sub", "x_a", "read")
    with pytest.raises(ToolRateLimitError) as excinfo:
        await check_rate_limits(rules, counter, "sub", "x_a", "read")
    # Retrying after the short window would still hit the hourly rule.
    assert excinfo.value.retry_after_seconds == 3600
    assert excinfo.value.window_seconds == 3600


async def test_rules_keep_separate_counters_even_with_identical_matching() -> None:
    counter = InMemoryWindowCounter(clock=_Clock())
    rules = [RateLimitRule(1, 60, tool="x_*"), RateLimitRule(5, 60, tool="x_*")]
    await check_rate_limits(rules, counter, "sub", "x_a", "read")
    with pytest.raises(ToolRateLimitError) as excinfo:
        await check_rate_limits(rules, counter, "sub", "x_a", "read")
    assert excinfo.value.limit == 1
