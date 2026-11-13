"""Cross-replica shared state behind an operator-supplied store URL.

Some broker state is only correct when every replica sees the same value --
a brute-force limiter whose budget is multiplied by the replica count is not
a limiter. ``SharedState`` is the narrow primitive set that state needs, with
two backends:

* ``InMemorySharedState`` -- process-local, the default. Correct for exactly
  one replica; chart and startup guards (see ``Settings``) refuse more than
  one replica on it unless the operator opts in explicitly.
* ``RedisSharedState`` -- any server speaking the redis protocol (Redis is
  the recommended store; Valkey, Dragonfly and KeyDB also work),
  reached through a ``redis://`` or ``rediss://`` URL the operator supplies.

See docs/architecture.md ("Replica consistency") for which broker state lives
here and how each item behaves when the store is down.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass

import redis.asyncio as aioredis
from redis.exceptions import RedisError

# Seconds a store call may block before it counts as the store being down.
# Short on purpose: every caller sits on a request path.
_SOCKET_TIMEOUT_SECONDS = 2.0

# Namespaces this broker's keys on a store an operator may share with others.
_DEFAULT_KEY_PREFIX = "af-mcp:"

# Atomic fixed-window increment. The window starts at the first increment (the
# key's TTL *is* the window), matching the in-memory backend. KEYS[1] = counter
# key, ARGV[1] = window in milliseconds. Returns {count, ttl_ms}. The
# ``ttl < 0`` branch repairs a counter that somehow lost its expiry, which
# would otherwise be a permanent lockout.
_INCR_WINDOW_LUA = """
local count = redis.call('INCR', KEYS[1])
if count == 1 then
    redis.call('PEXPIRE', KEYS[1], ARGV[1])
end
local ttl = redis.call('PTTL', KEYS[1])
if ttl < 0 then
    redis.call('PEXPIRE', KEYS[1], ARGV[1])
    ttl = tonumber(ARGV[1])
end
return {count, ttl}
"""


class SharedStateUnavailableError(Exception):
    """The shared store could not be reached or did not answer in time.

    Each caller decides its own failure policy (fail open, or fall back to
    per-replica behaviour) -- the store does not.
    """


@dataclass(frozen=True)
class WindowCount:
    """A fixed-window counter's value and the time left in its window."""

    count: int
    ttl_seconds: float


class SharedState(ABC):
    """Primitives for state that must agree across broker replicas."""

    @abstractmethod
    async def incr_window(self, key: str, window_seconds: int) -> WindowCount:
        """Atomically add one to *key*'s counter and return its new value.

        The window opens at the first increment and lasts *window_seconds*;
        once it closes the counter is gone and the next increment starts a
        new window at 1. Later increments do not extend the window.
        """

    @abstractmethod
    async def get_window(self, key: str) -> WindowCount | None:
        """Return *key*'s counter without changing it, or None if no window is open."""

    @abstractmethod
    async def delete(self, key: str) -> None:
        """Drop *key*'s counter. Deleting an absent key is not an error."""

    async def close(self) -> None:  # noqa: B027 -- optional hook, not abstract
        """Release any connection held by the backend."""


class InMemorySharedState(SharedState):
    """Process-local backend: one replica's view, lost on restart."""

    def __init__(self) -> None:
        # key -> (count, window end on the monotonic clock)
        self._windows: dict[str, tuple[int, float]] = {}

    async def incr_window(self, key: str, window_seconds: int) -> WindowCount:
        now = time.monotonic()
        current = self._windows.get(key)
        if current is None or current[1] <= now:
            current = (0, now + window_seconds)
        count = current[0] + 1
        self._windows[key] = (count, current[1])
        return WindowCount(count=count, ttl_seconds=current[1] - now)

    async def get_window(self, key: str) -> WindowCount | None:
        now = time.monotonic()
        current = self._windows.get(key)
        if current is None:
            return None
        if current[1] <= now:
            del self._windows[key]
            return None
        return WindowCount(count=current[0], ttl_seconds=current[1] - now)

    async def delete(self, key: str) -> None:
        self._windows.pop(key, None)


class RedisSharedState(SharedState):
    """Backend for any server speaking the redis protocol (``redis://``, ``rediss://``)."""

    def __init__(self, url: str, *, key_prefix: str = _DEFAULT_KEY_PREFIX) -> None:
        self._client: aioredis.Redis = aioredis.from_url(
            url,
            socket_timeout=_SOCKET_TIMEOUT_SECONDS,
            socket_connect_timeout=_SOCKET_TIMEOUT_SECONDS,
        )
        self._prefix = key_prefix
        self._incr_window = self._client.register_script(_INCR_WINDOW_LUA)

    async def incr_window(self, key: str, window_seconds: int) -> WindowCount:
        try:
            count, ttl_ms = await self._incr_window(
                keys=[self._prefix + key], args=[window_seconds * 1000]
            )
        except (RedisError, OSError) as exc:
            raise SharedStateUnavailableError(str(exc)) from exc
        return WindowCount(count=int(count), ttl_seconds=int(ttl_ms) / 1000)

    async def get_window(self, key: str) -> WindowCount | None:
        try:
            raw = await self._client.get(self._prefix + key)
            if raw is None:
                return None
            ttl_ms = await self._client.pttl(self._prefix + key)
        except (RedisError, OSError) as exc:
            raise SharedStateUnavailableError(str(exc)) from exc
        if ttl_ms < 0:
            # The window closed between the two reads.
            return None
        return WindowCount(count=int(raw), ttl_seconds=ttl_ms / 1000)

    async def delete(self, key: str) -> None:
        try:
            await self._client.delete(self._prefix + key)
        except (RedisError, OSError) as exc:
            raise SharedStateUnavailableError(str(exc)) from exc

    async def close(self) -> None:
        await self._client.aclose()


def build_shared_state(url: str | None) -> SharedState:
    """Return the backend for *url*: in-memory when empty, redis for ``redis(s)://``."""
    if not url:
        return InMemorySharedState()
    if url.startswith(("redis://", "rediss://")):
        return RedisSharedState(url)
    raise ValueError(
        "SHARED_STATE_URL must start with redis:// or rediss:// "
        "(any redis-protocol server, e.g. Redis or Valkey, works)"
    )
