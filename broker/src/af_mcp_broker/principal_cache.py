"""In-process, per-principal cache of current authorization attributes (issue #144 step 2a).

This is the **principal cache** in #144's three-concern split (PAT store /
principal cache / capability engine): it answers "what groups/uid does this
user currently have?" -- keyed by **principal id**, not by PAT, so multiple
PATs belonging to one user share cached state, a group change propagates
once per user rather than once per token, and rotating or revoking a PAT
never disturbs it.

Stale-while-revalidate, with two SEPARATE configurable bounds (mirrors
``token_registry.RevokedJtiCache``'s shape, but per-principal-keyed rather
than a single global set, and with a second, much longer bound this class
adds on top):

* ``refresh_interval_seconds`` (short, ~30-60s) -- how long a cached value
  may be served before the *next* read for that principal triggers a
  refresh attempt. Short because a group removal is meant to be a real kill
  switch (see #144's design notes): the sooner a refresh is attempted, the
  sooner that removal actually takes effect for PAT-authenticated calls.
* ``max_staleness_seconds`` (long, hours) -- how long a value may keep being
  served *after* a refresh attempt has started failing, before this class
  gives up and fails closed. Long because a brief Keycloak outage must not
  instantly lock out every PAT-authenticated caller; this is research
  infrastructure, not a bank vault. Every refresh failure while still within
  this bound is logged loudly (structlog `warning`/`error`) so an operator
  notices a real outage well before the bound is reached.

Two failure shapes fall out of this:

* **Cold start**: nothing cached yet for this principal, and the directory
  is unreachable. There is no stale value to serve -- fails closed
  immediately (``PrincipalUnavailableError``). This is a known, documented
  limitation of shipping the cache in-memory-only for this PR: a broker
  restart during a Keycloak outage denies PAT-authenticated callers until
  the directory recovers, even if their authority hasn't actually changed.
  JWT-authenticated callers are unaffected (self-contained tokens). See the
  TODO below -- persisting this cache (so a cold start doesn't lose
  everyone's last-known attributes) is step 2b of issue #144, deliberately
  out of scope here.
* **Stale-but-within-bound**: a previously cached value exists, the latest
  refresh attempt failed, but ``max_staleness_seconds`` hasn't elapsed yet --
  serve the last-known attributes, logging loudly.

In-memory only in this PR -- TODO(#144 step 2b): persist this cache
(alongside the PAT store, in Vault) so a cold start during a Keycloak outage
doesn't fail closed for every PAT user the instant a replica restarts, while
JWT-authenticated callers sail through unaffected. Document this limitation
in the PR body, not just here.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

import structlog

if TYPE_CHECKING:
    from af_mcp_broker.principal_directory import (
        PrincipalAttributes,
        PrincipalDirectory,
    )

log = structlog.get_logger(__name__)


class PrincipalUnavailableError(Exception):
    """Raised by ``PrincipalCache.get()`` when *principal_id*'s attributes cannot be resolved and no usable (fresh-enough-to-not-fail-closed) cached value exists -- see this module's docstring for the two ways that happens."""

    def __init__(self, principal_id: str) -> None:
        self.principal_id = principal_id
        super().__init__(f"Principal {principal_id!r} attributes unavailable")


@dataclass(frozen=True)
class _CacheEntry:
    attributes: PrincipalAttributes
    fetched_at: float  # time.monotonic()


class PrincipalCache:
    """Per-principal stale-while-revalidate cache in front of a ``PrincipalDirectory``. See this module's docstring for the two-bound design and the in-memory-only limitation of this PR."""

    def __init__(
        self,
        directory: PrincipalDirectory,
        *,
        refresh_interval_seconds: float,
        max_staleness_seconds: float,
    ) -> None:
        self._directory = directory
        self._refresh_interval = refresh_interval_seconds
        self._max_staleness = max_staleness_seconds
        self._entries: dict[str, _CacheEntry] = {}
        # One lock per principal_id so refreshing principal A never blocks a
        # concurrent read for principal B -- unlike RevokedJtiCache's single
        # global refresh, there is no single snapshot shared across callers
        # here.
        self._locks: dict[str, asyncio.Lock] = {}
        self._log = structlog.get_logger(__name__).bind(component="PrincipalCache")

    def _lock_for(self, principal_id: str) -> asyncio.Lock:
        lock = self._locks.get(principal_id)
        if lock is None:
            lock = asyncio.Lock()
            self._locks[principal_id] = lock
        return lock

    async def get(self, principal_id: str) -> PrincipalAttributes:
        """Return *principal_id*'s current attributes, refreshing if the cached value (if any) is older than ``refresh_interval_seconds``.

        Raises ``PrincipalUnavailableError`` on cold start with no reachable
        directory, or once a stale cached value has exceeded
        ``max_staleness_seconds`` without a successful refresh -- see this
        module's docstring.
        """
        entry = self._entries.get(principal_id)
        now = time.monotonic()
        if entry is not None and (now - entry.fetched_at) < self._refresh_interval:
            return entry.attributes

        async with self._lock_for(principal_id):
            # Another caller may have refreshed while we waited on the lock.
            entry = self._entries.get(principal_id)
            now = time.monotonic()
            if entry is not None and (now - entry.fetched_at) < self._refresh_interval:
                return entry.attributes

            try:
                attributes = await self._directory.resolve(principal_id)
            except Exception:  # noqa: BLE001 — must never take auth down; serve stale or fail closed below
                if entry is None:
                    self._log.error(
                        "principal_cache.resolve_failed_no_cached_value",
                        principal_id=principal_id,
                        exc_info=True,
                    )
                    raise PrincipalUnavailableError(principal_id) from None

                staleness = now - entry.fetched_at
                if staleness > self._max_staleness:
                    self._log.error(
                        "principal_cache.stale_past_max_serving_failed_closed",
                        principal_id=principal_id,
                        staleness_seconds=staleness,
                        max_staleness_seconds=self._max_staleness,
                        exc_info=True,
                    )
                    raise PrincipalUnavailableError(principal_id) from None

                self._log.warning(
                    "principal_cache.refresh_failed_serving_stale",
                    principal_id=principal_id,
                    staleness_seconds=staleness,
                    exc_info=True,
                )
                return entry.attributes

            self._entries[principal_id] = _CacheEntry(
                attributes=attributes, fetched_at=now
            )
            return attributes
