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

from af_mcp_broker.authorization.errors import ToolRateLimitError

if TYPE_CHECKING:
    from af_mcp_broker.authorization.base import RateLimitRule
    from af_mcp_broker.shared_state import SharedState, WindowCount


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
