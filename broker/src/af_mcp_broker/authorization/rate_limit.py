"""Per-principal tool-call rate limits (``rate_limits`` in policy.yaml, issue #165).

Counters sit behind ``WindowCounter`` so a store shared across broker
replicas can replace the in-process one without touching the rules or the
middleware. ``incr_window`` deliberately has the signature and semantics of
``SharedState.incr_window`` (the cross-replica store described in
docs/architecture.md, "Replica consistency").

Every rule matching a call applies, each with its own counter per principal.
"""

from __future__ import annotations

import math
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import TYPE_CHECKING

from af_mcp_broker.authorization.errors import ToolRateLimitError

if TYPE_CHECKING:
    from collections.abc import Callable

    from af_mcp_broker.authorization.base import RateLimitRule

# Minimum clock seconds between sweeps that drop expired windows, so the
# in-process counter's memory is bounded by the principals active within a
# window rather than every principal ever seen.
_SWEEP_INTERVAL_SECONDS = 60.0


@dataclass(frozen=True)
class WindowCount:
    """A fixed-window counter's value and the time left in its window."""

    count: int
    ttl_seconds: float


class WindowCounter(ABC):
    """Fixed-window counters keyed by string."""

    @abstractmethod
    async def incr_window(self, key: str, window_seconds: int) -> WindowCount:
        """Atomically add one to *key*'s counter and return its new value.

        The window opens at the first increment and lasts *window_seconds*;
        once it closes the counter is gone and the next increment starts a
        new window at 1. Later increments do not extend the window.
        """


class InMemoryWindowCounter(WindowCounter):
    """Process-local counters: each broker replica counts on its own.

    With N replicas the effective limit is up to ``limit x N``. *clock* is
    injectable for tests and must be monotonic.
    """

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        # key -> (count, clock time the window closes). No await between
        # reading and writing an entry, so increments are atomic on the
        # event loop.
        self._windows: dict[str, tuple[int, float]] = {}
        self._last_sweep = clock()

    @property
    def tracked_keys(self) -> int:
        return len(self._windows)

    async def incr_window(self, key: str, window_seconds: int) -> WindowCount:
        now = self._clock()
        self._sweep(now)
        count, closes_at = self._windows.get(key, (0, 0.0))
        if closes_at <= now:
            count, closes_at = 0, now + window_seconds
        count += 1
        self._windows[key] = (count, closes_at)
        return WindowCount(count=count, ttl_seconds=closes_at - now)

    def _sweep(self, now: float) -> None:
        if now - self._last_sweep < _SWEEP_INTERVAL_SECONDS:
            return
        self._last_sweep = now
        self._windows = {k: v for k, v in self._windows.items() if v[1] > now}


async def check_rate_limits(
    rules: list[RateLimitRule],
    counter: WindowCounter,
    subject: str,
    tool_name: str,
    action_type: str,
) -> None:
    """Count this call against every matching rule; raise if any budget is exceeded.

    Every matching rule counts the attempt, including one another rule
    denies, so a client cannot spend one budget while probing another.
    Counting is keyed by *subject*, never global. With no rules the counter
    is never touched.
    """
    exceeded: list[tuple[RateLimitRule, WindowCount]] = []
    for index, rule in enumerate(rules):
        if not rule.matches(tool_name, action_type):
            continue
        window = await counter.incr_window(
            f"tool_rate_limit:{index}:{subject}", rule.window_seconds
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
