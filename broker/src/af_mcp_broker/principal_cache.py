"""In-process, per-principal cache of current authorization attributes, persisted to survive a restart (issue #144 steps 2a/2b).

This is the **principal cache** in #144's three-concern split (PAT store /
principal cache / capability engine): it answers "what groups/uid does this
user currently have?" -- keyed by **principal id**, not by PAT, so multiple
PATs belonging to one user share cached state, a group change propagates
once per user rather than once per token, and rotating or revoking a PAT
never disturbs it.

**This is a cache, never the authority.** Keycloak (via
``principal_directory.PrincipalDirectory``) is always the source of truth;
everything this module stores -- in memory or persisted -- is a last-known-
value fallback with an explicit freshness timestamp attached, and every read
path enforces a staleness bound against that timestamp before serving it.
There is deliberately no code path in this module that returns a stored
value without first checking how old it is; a future change extending this
class must preserve that invariant rather than adding a "just give me
whatever's stored" shortcut.

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
  notices a real outage well before the bound is reached -- enforced
  identically whether the last-known value came from this process's own
  successful resolve() or from a persisted record loaded at cold start.

Two failure shapes fall out of this:

* **Cold start**: nothing cached in memory yet for this principal. Before
  attempting a live directory resolve(), ``get()`` consults the persistence
  backend (below) exactly once for this principal -- see "Read layering"
  under "Persisting the cache". If the backend has nothing, or what it has
  is already older than ``max_staleness_seconds``, this is the same failure
  mode the cache had before persistence existed: no usable stale value, so a
  directory failure fails closed immediately (``PrincipalUnavailableError``).
  If the backend has a value still within the staleness bound, that value
  becomes this call's last-known-value fallback -- and, if it is also still
  within ``refresh_interval_seconds``, is returned directly with no
  directory call at all.
* **Stale-but-within-bound**: a previously cached value exists (in memory,
  or just loaded from the backend as above), the latest refresh attempt
  failed, but ``max_staleness_seconds`` hasn't elapsed yet -- serve the
  last-known attributes, logging loudly.

## Persisting the cache (issue #144 step 2b)

``PrincipalCacheBackend`` is the storage contract, following
``token_registry.TokenRegistryBackend``'s shape exactly: an ABC (not a
Protocol -- same reasoning as ``PrincipalDirectory``/``CredentialProvider``
elsewhere in this codebase and Giordon's standing preference for explicit
inheritance over duck typing), a Vault-backed implementation
(``VaultPrincipalCacheBackend``) using the same shared ``VaultKV`` transport
client the token registry and oauth21 token store already use, and an
in-memory implementation (``InMemoryPrincipalCacheBackend``) for local dev,
selected the same way (``settings.principal_cache_backend``).

**Wall clock vs. monotonic clock.** Every persisted record
(``PersistedPrincipalRecord``) carries its own ``resolved_at`` -- a
**wall-clock** timestamp (``time.time()``), unlike this module's in-memory
``_CacheEntry.fetched_at`` (``time.monotonic()``). Monotonic time has no
fixed epoch across process restarts, so it cannot meaningfully be written
down by one process and read back by another; wall-clock time can. When a
persisted record is loaded at cold start, its age is computed once against
the current wall clock and translated into a synthetic monotonic
``fetched_at`` (``time.monotonic() - age``) -- the only point in this module
where the two clocks are ever compared, and only as a difference, never as
absolute values. After that translation, the existing refresh/staleness
arithmetic (already monotonic-based, deliberately immune to wall-clock
jumps such as NTP corrections) applies to a loaded record exactly as it
would to one resolved in-process.

**Write amplification, and why a pure content-diff is not enough on its
own.** A naive implementation would write to Vault on every successful
refresh -- with a ~45s refresh interval across every PAT-authenticated
principal, that is a lot of KV traffic for data that changes rarely.
Comparing content and skipping the write when unchanged fixes the traffic
problem, but on its own creates a worse one: group memberships are stable
for weeks or months in normal operation, so a pure content-diff means
``resolved_at`` only ever advances when something actually changes -- for
the *typical* principal the persisted record would be weeks old, already
well past any hours-scale ``max_staleness_seconds`` before a restart ever
happens. Persistence would then help only the rare principal whose
attributes changed recently; the common case -- the one this feature
exists for -- would get no benefit at all.

``get()`` therefore persists when *either* of two things is true:

* the newly resolved attributes differ from the value currently held
  (compared by ``PrincipalAttributes`` equality, never by comparing
  timestamps) -- a changed value persists immediately, on the very next
  refresh, never waiting for a heartbeat; or
* the current value's last write is older than
  ``heartbeat_interval_seconds`` -- a successful refresh that merely
  *confirms* unchanged attributes still refreshes the durability of that
  knowledge, so ``resolved_at`` keeps advancing even for a principal whose
  groups never change.

The very first resolve for a principal always persists (there is nothing
yet to compare against, and nothing yet to be a heartbeat "since"). Setting
``heartbeat_interval_seconds`` comfortably below ``max_staleness_seconds``
(roughly half, by default) guarantees a healthy, reachable system always
has a persisted record well inside the staleness bound, regardless of how
stable any given principal's attributes are. The write-rate arithmetic:
with the defaults (45s refresh, 3-hour heartbeat), a stable principal now
writes once per heartbeat instead of once per refresh -- a ~240x reduction
from the naive "write every refresh" baseline, while still guaranteeing
persistence never lags wall-clock reality by more than the heartbeat
interval.

**Read layering.** The in-memory ``_entries`` dict is the only thing the hot
path (every ``get()`` call) reads before deciding whether a refresh is even
attempted. The persistence backend is consulted at most once per principal
per process lifetime -- only on the very first call for a principal this
replica has never seen, i.e. a genuine cold miss -- never on a warm hit and
never as part of the steady-state refresh cycle. A future change adding a
backend read anywhere else (e.g. "just to double-check") would reintroduce
a per-request Vault round trip this design deliberately avoids.

**Failure behavior.** Neither a backend read nor a backend write is allowed
to turn a request into a failure by itself. A backend read failure at cold
start (Vault unreachable) is treated identically to "nothing persisted" --
logged, not raised -- since the fallback (an in-memory-only cache) is
exactly what shipped before this PR and is not a regression to degrade to.
A backend write failure is logged loudly (structlog `error`, since silently
non-functioning persistence deserves an operator's attention) but never
propagates -- the in-memory entry the current ``get()`` call is about to
return is already correct regardless of whether Vault accepted the write.
"""

from __future__ import annotations

import asyncio
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import structlog

from af_mcp_broker.principal_directory import PrincipalAttributes
from af_mcp_broker.vault_kv import CasConflict, VaultError, VaultKV

if TYPE_CHECKING:
    from af_mcp_broker.principal_directory import PrincipalDirectory

log = structlog.get_logger(__name__)

# Bounded retry budget for VaultPrincipalCacheBackend.put()'s read-modify-write
# CAS loop -- mirrors token_registry.py's _MAX_CAS_RETRIES exactly (same
# value, same rationale): a conflict storm this deep would indicate something
# pathological, so failing loudly past this point is preferable to retrying
# forever. Unlike the token registry, a lost race here is not itself a
# correctness problem (this is a cache, not a set of uniqueness-checked
# records) -- but exhausting the budget still means Vault didn't get this
# principal's latest attributes, which is worth surfacing rather than
# silently swallowing.
_MAX_CAS_RETRIES = 5


class PrincipalUnavailableError(Exception):
    """Raised by ``PrincipalCache.get()`` when *principal_id*'s attributes cannot be resolved and no usable (fresh-enough-to-not-fail-closed) cached value exists -- see this module's docstring for the two ways that happens."""

    def __init__(self, principal_id: str) -> None:
        self.principal_id = principal_id
        super().__init__(f"Principal {principal_id!r} attributes unavailable")


@dataclass(frozen=True)
class PersistedPrincipalRecord:
    """A principal's attributes as last resolved, together with the wall-clock time that happened -- the unit ``PrincipalCacheBackend`` stores and retrieves.

    ``resolved_at`` is deliberately ``time.time()``, not
    ``time.monotonic()`` -- see this module's docstring for why a record
    meant to be read back by a different process (after a restart) must use
    the wall clock. This dataclass carries no notion of "still fresh enough
    to serve"; every reader is responsible for comparing ``resolved_at``
    against its own staleness bound before trusting the ``attributes``
    inside -- see ``PrincipalCache._load_from_backend``.
    """

    attributes: PrincipalAttributes
    resolved_at: float  # time.time()


class PrincipalCacheBackend(ABC):
    """Durable storage for one ``PersistedPrincipalRecord`` per principal.

    An ABC, not a Protocol -- see this module's docstring. Deliberately the
    smallest possible contract: a get/put pair, no uniqueness rules, no
    revocation, no sweep. Freshness/staleness decisions are entirely
    ``PrincipalCache``'s job, one layer up -- an implementation answers only
    "what did we last write down for this principal", the same division of
    responsibility ``PrincipalDirectory`` keeps from ``PrincipalCache``
    itself ("what does Keycloak say right now").
    """

    @abstractmethod
    async def get(self, principal_id: str) -> PersistedPrincipalRecord | None:
        """Return the last persisted record for *principal_id*, or None if nothing has ever been persisted for it."""

    @abstractmethod
    async def put(self, principal_id: str, record: PersistedPrincipalRecord) -> None:
        """Persist *record* as *principal_id*'s current last-known value, overwriting whatever was previously stored."""


class InMemoryPrincipalCacheBackend(PrincipalCacheBackend):
    """Process-local, single-replica ``PrincipalCacheBackend``.

    Lost on restart -- exactly the property this module exists to avoid for
    the Vault-backed implementation below, so this one exists purely as the
    local-dev/test fallback, selected the same way
    ``InMemoryTokenRegistryBackend`` is.
    """

    def __init__(self) -> None:
        self._records: dict[str, PersistedPrincipalRecord] = {}

    async def get(self, principal_id: str) -> PersistedPrincipalRecord | None:
        return self._records.get(principal_id)

    async def put(self, principal_id: str, record: PersistedPrincipalRecord) -> None:
        self._records[principal_id] = record


def _record_to_fields(record: PersistedPrincipalRecord) -> dict[str, Any]:
    return {
        "uid": record.attributes.uid,
        "gid": record.attributes.gid,
        "unixname": record.attributes.unixname,
        "groups": list(record.attributes.groups),
        "email": record.attributes.email,
        "resolved_at": record.resolved_at,
    }


def _record_from_fields(fields: dict[str, Any]) -> PersistedPrincipalRecord:
    return PersistedPrincipalRecord(
        attributes=PrincipalAttributes(
            uid=fields.get("uid"),
            gid=fields.get("gid"),
            unixname=fields.get("unixname"),
            groups=list(fields.get("groups") or []),
            email=str(fields.get("email") or ""),
        ),
        resolved_at=float(fields["resolved_at"]),
    )


class VaultPrincipalCacheBackend(PrincipalCacheBackend):
    """``PrincipalCacheBackend`` backed by Vault/OpenBao KV-v2 via a shared ``VaultKV`` transport client.

    One entry per principal at ``{kv_path_prefix}/{principal_id}`` -- no
    secondary index of any kind, unlike ``VaultTokenRegistryBackend``'s
    lookup-owner/revoked-lookup-ids indices, because there is nothing here
    that needs one: no uniqueness rule to enforce, no denylist to bound, just
    one overwritable blob per principal. ``put()``'s read-modify-write CAS
    loop exists only to avoid clobbering a concurrent writer's version
    counter (e.g. two broker replicas refreshing the same principal at
    once); losing that race is not a correctness problem the way it would be
    for the token registry's name-uniqueness check -- the loser simply tries
    again on its own next refresh cycle, ~``refresh_interval_seconds`` later.
    """

    def __init__(self, *, vault_kv: VaultKV, kv_path_prefix: str) -> None:
        self._vault_kv = vault_kv
        self._kv_path_prefix = kv_path_prefix.strip("/")

    def _path(self, principal_id: str) -> str:
        return f"{self._kv_path_prefix}/{principal_id}"

    async def get(self, principal_id: str) -> PersistedPrincipalRecord | None:
        current = await self._vault_kv.get(self._path(principal_id))
        if current is None:
            return None
        data, _version = current
        return _record_from_fields(data)

    async def put(self, principal_id: str, record: PersistedPrincipalRecord) -> None:
        path = self._path(principal_id)
        for _attempt in range(_MAX_CAS_RETRIES):
            current = await self._vault_kv.get(path)
            version = current[1] if current is not None else None
            try:
                await self._vault_kv.write_cas(path, _record_to_fields(record), version)
                break
            except CasConflict:
                continue
        else:
            raise VaultError(
                f"put(): exceeded retry budget for principal_id={principal_id!r}"
            )


@dataclass(frozen=True)
class _CacheEntry:
    attributes: PrincipalAttributes
    fetched_at: float  # time.monotonic() -- last time these attributes were confirmed, in-process or via a cold-start backend load
    persisted_at: float  # time.monotonic() -- last time these attributes (or an earlier value confirmed unchanged via the heartbeat) were actually written to the backend; see PrincipalCache._persist_if_needed


class PrincipalCache:
    """Per-principal stale-while-revalidate cache in front of a ``PrincipalDirectory``, persisted via a ``PrincipalCacheBackend`` so a cold start doesn't lose every principal's last-known attributes. See this module's docstring for the two-bound design, the persistence write/read layering, the heartbeat write, and the wall-clock/monotonic clock translation."""

    def __init__(
        self,
        directory: PrincipalDirectory,
        *,
        backend: PrincipalCacheBackend,
        refresh_interval_seconds: float,
        max_staleness_seconds: float,
        heartbeat_interval_seconds: float,
    ) -> None:
        self._directory = directory
        self._backend = backend
        self._refresh_interval = refresh_interval_seconds
        self._max_staleness = max_staleness_seconds
        self._heartbeat_interval = heartbeat_interval_seconds
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

    async def _load_from_backend(
        self, principal_id: str, now_monotonic: float
    ) -> _CacheEntry | None:
        """Attempt to seed a cold cache miss from ``self._backend``, translating its wall-clock ``resolved_at`` into a synthetic monotonic ``fetched_at`` -- see this module's docstring.

        Called from ``get()`` at most once per principal per process
        lifetime: only when ``self._entries`` has no entry for
        *principal_id* yet, i.e. this replica has never resolved it before.
        A backend read failure (Vault unreachable) is treated exactly like
        "nothing persisted" -- logged, never raised -- per this module's
        documented failure behavior; the caller falls through to the
        ordinary directory.resolve() path exactly as it would if this
        method didn't exist.
        """
        try:
            persisted = await self._backend.get(principal_id)
        except Exception:  # noqa: BLE001 — a backend outage at cold start is a miss, not an error; see module docstring
            self._log.warning(
                "principal_cache.backend_read_failed_treated_as_miss",
                principal_id=principal_id,
                exc_info=True,
            )
            return None
        if persisted is None:
            return None

        age = max(0.0, time.time() - persisted.resolved_at)
        # The record was, by definition, last written at this same translated
        # instant -- fetched_at and persisted_at start out identical for a
        # value freshly loaded from the backend.
        fetched_at = now_monotonic - age
        entry = _CacheEntry(
            attributes=persisted.attributes,
            fetched_at=fetched_at,
            persisted_at=fetched_at,
        )
        self._entries[principal_id] = entry
        return entry

    async def _persist_if_needed(
        self,
        principal_id: str,
        attributes: PrincipalAttributes,
        previous: _CacheEntry | None,
        now_monotonic: float,
    ) -> float:
        """Write *attributes* to ``self._backend`` when content differs from *previous* or the last write is due for a heartbeat refresh; returns the ``persisted_at`` the caller's new ``_CacheEntry`` should carry -- see this module's docstring on write amplification and the heartbeat.

        A write is skipped only when *both* the content is unchanged *and*
        the heartbeat interval hasn't elapsed since *previous* was last
        written -- either condition failing triggers a write. *previous*
        being ``None`` (the very first resolve for this principal) always
        writes, since there is nothing yet to compare against or to have a
        heartbeat "since".

        A backend write failure is logged loudly but never raised: it must
        never turn a successful directory resolve into a failed request --
        see this module's documented failure behavior. On failure,
        *persisted_at* is **not** advanced (carried forward from *previous*,
        or treated as already due if there was no *previous*) so the very
        next refresh retries rather than waiting out a full heartbeat
        interval while Vault is down.
        """
        if previous is not None:
            unchanged = previous.attributes == attributes
            heartbeat_due = (
                now_monotonic - previous.persisted_at
            ) >= self._heartbeat_interval
            if unchanged and not heartbeat_due:
                return previous.persisted_at

        try:
            await self._backend.put(
                principal_id,
                PersistedPrincipalRecord(
                    attributes=attributes, resolved_at=time.time()
                ),
            )
        except Exception:  # noqa: BLE001 — persistence failing must never fail a successful resolve
            self._log.error(
                "principal_cache.persist_failed",
                principal_id=principal_id,
                exc_info=True,
            )
            return previous.persisted_at if previous is not None else float("-inf")
        return now_monotonic

    async def get(self, principal_id: str) -> PrincipalAttributes:
        """Return *principal_id*'s current attributes, refreshing if the cached value (if any) is older than ``refresh_interval_seconds``.

        On a cold miss (nothing cached in memory for *principal_id* yet),
        first attempts to load a persisted value from ``self._backend`` --
        see this module's docstring's "Read layering". Raises
        ``PrincipalUnavailableError`` when no usable cached value (in memory
        or freshly loaded from the backend) exists and the directory is
        unreachable, or once a stale cached value has exceeded
        ``max_staleness_seconds`` without a successful refresh.
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

            if entry is None:
                entry = await self._load_from_backend(principal_id, now)
                if (
                    entry is not None
                    and (now - entry.fetched_at) < self._refresh_interval
                ):
                    # A persisted value still within the refresh window --
                    # serve it directly rather than hitting the directory
                    # the instant this replica comes up.
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

            persisted_at = await self._persist_if_needed(
                principal_id, attributes, entry, now
            )
            self._entries[principal_id] = _CacheEntry(
                attributes=attributes, fetched_at=now, persisted_at=persisted_at
            )
            return attributes
