"""Per-principal tool-call rate limits (``rate_limits`` in policy.yaml, issue #165).

Counters live in the broker's ``SharedState`` (see docs/architecture.md,
"Replica consistency"), so with a store configured a budget is cluster-wide.

Every rule matching a call applies, each with its own counter per principal.
"""

from __future__ import annotations

import hashlib
import json
import math
from typing import TYPE_CHECKING

import structlog
from pydantic import BaseModel, ConfigDict

from af_mcp_broker.authorization.errors import ToolRateLimitError
from af_mcp_broker.shared_state import SharedStateUnavailableError

if TYPE_CHECKING:
    from collections.abc import Iterable

    from af_mcp_broker.authorization.base import RateLimitRule
    from af_mcp_broker.shared_state import SharedState, WindowCount

logger = structlog.get_logger(__name__)


def tool_rate_limit_key(rule: RateLimitRule, subject: str) -> str:
    """Shared-state key of the counter for *subject* under *rule*.

    Keyed on the rule's content, not its position in ``rate_limits``: a store
    fixes a counter's window at its first increment, so a counter reused by an
    edited or shifted rule would keep the old rule's count and window. An
    edited rule gets a fresh counter; a reordered one keeps its own.
    """
    canonical = json.dumps(
        [rule.action_type, rule.tool, rule.limit, rule.window_seconds]
    )
    fingerprint = hashlib.sha256(canonical.encode()).hexdigest()[:12]
    return f"tool-rate-limit:{fingerprint}:{subject}"


def covered_tool_names(
    rule: RateLimitRule, tools: Iterable[tuple[str, str]]
) -> list[str]:
    """Names, sorted, of the *tools* (``(wire name, action type)`` pairs) that *rule* covers.

    Uses ``RateLimitRule.matches``, the matcher ``check_rate_limits`` counts
    calls with, so a listing cannot disagree with enforcement.
    """
    return sorted(
        name for name, action_type in tools if rule.matches(name, action_type)
    )


async def check_rate_limits(
    rules: list[RateLimitRule],
    shared_state: SharedState,
    subject: str,
    tool_name: str,
    action_type: str,
) -> None:
    """Count this call against every matching rule; raise if any budget is exceeded.

    Every matching rule counts the attempt, including one another rule
    denies, so a client cannot spend one budget while probing another.
    Counting is keyed by *subject*, never global. With no rules the store
    is never touched.
    """
    exceeded: list[tuple[RateLimitRule, WindowCount]] = []
    # Identical rules share one counter, so each is counted once per call.
    for rule in dict.fromkeys(rules):
        if not rule.matches(tool_name, action_type):
            continue
        window = await shared_state.incr_window(
            tool_rate_limit_key(rule, subject), rule.window_seconds
        )
        if window.count > rule.limit:
            exceeded.append((rule, window))
    if not exceeded:
        return
    # Retrying before the last exceeded window closes would hit it again.
    rule, window = max(exceeded, key=lambda pair: pair[1].ttl_seconds)
    raise ToolRateLimitError(
        f"Rate limit of {rule.limit} calls per {rule.window_seconds}s "
        f"exceeded for {tool_name}",
        limit=rule.limit,
        window_seconds=rule.window_seconds,
        retry_after_seconds=math.ceil(window.ttl_seconds),
    )


async def read_rate_limit_usage(
    rules: list[RateLimitRule],
    shared_state: SharedState,
    subject: str,
) -> list[WindowCount | None] | None:
    """Read *subject*'s counter under each of *rules*, without counting anything.

    Returns one entry per rule, in order: its ``WindowCount``, or ``None``
    when no window is open (nothing counted yet, or the window closed).
    Returns ``None`` instead of a list when usage cannot be known: the store
    is unreachable (logged as ``rate_limits.shared_state_unavailable``).
    Reading the store directly, never through the limiter's per-replica
    fallback, keeps "unknown" from being reported as one replica's partial
    count. With no rules the store is never touched.
    """
    if not rules:
        return []
    try:
        return [
            await shared_state.get_window(tool_rate_limit_key(rule, subject))
            for rule in rules
        ]
    except SharedStateUnavailableError as exc:
        logger.warning("rate_limits.shared_state_unavailable", error=str(exc))
        return None


class RateLimitStatus(BaseModel):
    """One configured rule and the caller's usage of it.

    A rule's selector is *action_type* and/or *tool* (an fnmatch glob over the
    wire tool name); a call is covered when every selector the rule sets
    matches. *used* and *resets_in_seconds* are ``None`` when usage could not
    be read; with a readable store, *used* is 0 and *resets_in_seconds*
    ``None`` while the caller has no open window.
    """

    model_config = ConfigDict(frozen=True)

    action_type: str | None
    tool: str | None
    limit: int
    window_seconds: int
    # Calls counted in the open window, which includes calls the limiter
    # refused, so it can exceed *limit*.
    used: int | None
    # Whole seconds (rounded up, as ``Retry-After`` is) until the window
    # closes and the count starts over.
    resets_in_seconds: int | None


def rate_limit_statuses(
    rules: list[RateLimitRule], usage: list[WindowCount | None] | None
) -> list[RateLimitStatus]:
    """Pair *rules* with *usage* as ``read_rate_limit_usage`` returns it (``None`` meaning usage unknown)."""
    windows = usage if usage is not None else [None] * len(rules)
    return [
        RateLimitStatus(
            action_type=rule.action_type,
            tool=rule.tool,
            limit=rule.limit,
            window_seconds=rule.window_seconds,
            used=None if usage is None else (window.count if window else 0),
            resets_in_seconds=math.ceil(window.ttl_seconds) if window else None,
        )
        for rule, window in zip(rules, windows, strict=True)
    ]
