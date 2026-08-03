"""Durable storage for manually-minted bearer token metadata (issue #115).

Successor to ``api/tokens.py``'s original in-memory-only ``TokenRegistry``
(issue #24 / PR #28): at ``replicaCount: 2`` an in-process dict is invisible
across replicas and lost on restart, which breaks list/revoke consistency and
silently caps the effective mint-rate-limit at N times the configured value.

``TokenRegistryBackend`` is the storage contract two implementations satisfy:

* ``InMemoryTokenRegistryBackend`` -- single-replica, lost on restart. Local-
  dev fallback, selected the same way ``credentials.oauth21.InMemoryTokenStore``
  is (``settings.token_registry_backend == "in_memory"``, the default).
* ``VaultTokenRegistryBackend`` -- persists to Vault/OpenBao KV-v2, via the
  same shared ``VaultKV`` transport client (``vault_kv.py``)
  ``credentials/vault.py``'s ``VaultTokenStore`` holds (Kubernetes auth,
  re-authenticating from the pod's ServiceAccount JWT rather than holding a
  long-lived Vault credential of its own). The two stores persist unrelated
  payload shapes under different KV prefixes, so each keeps its own path
  layout, record (de)serialization, and CAS retry loop -- only the
  transport (auth + the four KV verbs) is shared.

Vault KV-v2 layout, all under ``{kv_mount}/data/{kv_path_prefix}/...``:

* ``by-uid/{uid}``     -> ``{jti: {...TokenRecord fields...}}``, one entry
  per uid, written with CAS. Gives O(1) list-by-uid (the common case: every
  route is scoped to the caller's own principal).
* ``jti-owner/{jti}``  -> ``{"uid": <uid>}``, one entry per jti, written once
  at mint time. Gives O(1) ownership lookup so the API layer can distinguish
  "unknown jti" (404) from "jti exists but belongs to someone else" (403)
  without a Vault LIST across every uid.
* ``revoked-jtis``     -> ``{"jtis": [...]}``, a single flat entry every
  ``revoke()`` call updates. Gives ``RevokedJtiCache`` an O(1) read for its
  periodic refresh instead of enumerating every uid's by-uid entry.

``revoke()`` writes ``revoked-jtis`` BEFORE the per-uid entry's
``revoked_at`` field deliberately: that index is the one
``RevokedJtiCache``/``identity.get_principal`` actually enforce against, so
it must never lag behind the per-uid entry, which is display-only (the
portal's token list). A failure between the two writes can only leave the
list looking briefly stale ("active" a moment longer than it should), never
the reverse (enforced-revoked but still shown as active would be a security
gap; shown-as-active-a-bit-longer while actually enforced is just UI lag).

An expired entry stops mattering the instant its JWT's own ``exp`` claim
makes it invalid, regardless of registry state (see identity.get_principal),
so leaving it around a while longer is a display/storage concern, not a
security one -- but Vault-side growth is still unbounded unless something
external prunes it. ``InMemoryTokenRegistryBackend`` needs no such external
janitor: it self-sweeps expired records inline on every ``add()``, since it's
just an in-process dict with no external TTL of its own.
``VaultTokenRegistryBackend`` does, via ``sweep_expired()`` below (a grace
window keeps a just-expired record visible as "expired" for a while rather
than removing it the instant it lapses) -- see ``token_sweep.py`` for the
cron-triggered CLI that calls it.

``name`` is a unique-per-user identifier, not free text (issue #116): two
records for the same uid may not share a name, compared case-insensitively.
Only *live* records (``revoked_at`` unset and not yet past ``expires_at``)
count as a collision -- a name freed up by revocation or natural expiry can
be reused without confusion, since the old record can no longer be mistaken
for the new one. ``add()`` enforces this itself (see
``_check_name_available`` and each backend's ``add()``) rather than leaving
it to a caller-side check-then-write, because a caller-side check racing two
concurrent mints (e.g. two broker replicas) could let both pass the check
before either writes. Both backends' single per-uid record is small enough
that a full scan of it at mint time is fine -- no separate name index. For
``VaultTokenRegistryBackend`` specifically, the uniqueness check re-runs on
every iteration of ``add()``'s existing read-modify-write CAS retry loop
(the same one that already protects the by-uid write from lost updates), so
a loser that retries after a conflict re-checks against the winner's
just-written data rather than a stale read from before the race.
"""

from __future__ import annotations

import asyncio
import contextlib
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from typing import Any

import structlog

from af_mcp_broker.vault_kv import CasConflict, VaultError, VaultKV

log = structlog.get_logger(__name__)

# Bounded retry budget for the read-modify-write CAS loops below -- a
# genuine conflict storm this deep would indicate something pathological
# (far beyond two replicas racing once), so failing loudly past this point
# is preferable to retrying forever.
_MAX_CAS_RETRIES = 5


class DuplicateNameError(Exception):
    """Raised by add() when a record's ``name`` collides, case-insensitively,
    with an existing live (non-revoked, non-expired) record for the same
    uid -- see this module's docstring for the uniqueness rule."""

    def __init__(self, uid: int, name: str) -> None:
        self.uid = uid
        self.name = name
        super().__init__(f"Token name {name!r} is already in use.")


@dataclass(frozen=True)
class TokenRecord:
    """Metadata for one manually-minted bearer token.

    Deliberately does NOT carry the raw token value or anything it could be
    reconstructed from -- see issue #115. The token is returned to the caller
    exactly once, in the mint response; this record exists solely so the
    portal can list/revoke what a uid has minted.
    """

    jti: str
    uid: int
    subject: str
    name: str
    issued_at: float
    expires_at: float
    revoked_at: float | None
    minted_via: str
    # Free-text, user-supplied, purely self-descriptive -- never consumed by
    # the broker itself (issue #116). None when the caller didn't supply one.
    note: str | None = None


def _collides(existing: TokenRecord, candidate: TokenRecord, now: float) -> bool:
    """True if *existing* is a live record that blocks *candidate*'s name."""
    return (
        existing.jti != candidate.jti
        and existing.revoked_at is None
        and existing.expires_at > now
        and existing.name.casefold() == candidate.name.casefold()
    )


def default_token_name(jti: str, issued_at: float) -> str:
    """Server-generated name (``mcp-YYYYMMDD-<jti prefix>``) used when the
    caller didn't supply one at mint time."""
    date_str = datetime.fromtimestamp(issued_at, tz=UTC).strftime("%Y%m%d")
    return f"mcp-{date_str}-{jti[:8]}"


@dataclass(frozen=True)
class SweepStats:
    """Counts returned by ``TokenRegistryBackend.sweep_expired()`` -- what a
    single sweep pass actually did, for the CLI's structlog line and (for
    ``VaultTokenRegistryBackend``) test assertions on Vault-only bookkeeping.

    ``owners_removed`` is always 0 for ``InMemoryTokenRegistryBackend``: it
    has no separate ``jti-owner`` index (``owner_uid()`` scans the by-uid
    dicts directly), so there's nothing extra to delete beyond the record
    itself.
    """

    records_removed: int
    owners_removed: int
    revoked_pruned: int
    uids_emptied: int


class TokenRegistryBackend(ABC):
    """Durable per-uid storage for manually-minted bearer token metadata."""

    @abstractmethod
    async def add(self, record: TokenRecord) -> None:
        """Persist a newly minted record.

        Raises DuplicateNameError if *record*'s name collides, case-
        insensitively, with an existing live record for the same uid --
        see this module's docstring for the uniqueness rule.
        """

    @abstractmethod
    async def list_for_uid(self, uid: int) -> list[TokenRecord]:
        """Return every record owned by *uid*, newest ``issued_at`` first."""

    @abstractmethod
    async def get(self, uid: int, jti: str) -> TokenRecord | None:
        """Return the record for (*uid*, *jti*), or None if absent."""

    @abstractmethod
    async def owner_uid(self, jti: str) -> int | None:
        """Return the uid that owns *jti*, or None if *jti* is unknown.

        Lets the API layer distinguish "unknown token" (404) from "token
        exists but you don't own it" (403) without needing a uid-scoped
        lookup first.
        """

    @abstractmethod
    async def revoke(self, uid: int, jti: str, revoked_at: float) -> TokenRecord | None:
        """Mark (*uid*, *jti*) revoked; returns the updated record, or None
        if *jti* is unknown or not owned by *uid*."""

    @abstractmethod
    async def list_revoked_jtis(self) -> frozenset[str]:
        """Return every jti, across all uids, whose ``revoked_at`` is set."""

    @abstractmethod
    async def sweep_expired(self, *, grace_seconds: int) -> SweepStats:
        """Remove every record whose ``expires_at`` is more than
        *grace_seconds* in the past, across all uids.

        The grace window is deliberate, not an implementation accident: a
        token that just expired is still meaningful to show the caller as
        "expired" on the portal's token list for a while, rather than
        vanishing the instant its JWT's own ``exp`` claim passes. Live
        records (``expires_at`` still in the future) and records expired
        less than *grace_seconds* ago are both left untouched.

        Also prunes ``revoked-jtis`` of any jti this pass removes for being
        expired past grace -- an expired JWT can never authenticate again
        regardless of its revoked status (see identity.get_principal), so
        keeping it in the denylist forever would only make that set grow
        without bound. A live-but-revoked record is untouched by this
        pruning; it stays in the denylist until its own expiry catches up.
        """


# ---------------------------------------------------------------------------
# In-memory backend -- local-dev fallback.
# ---------------------------------------------------------------------------


class InMemoryTokenRegistryBackend(TokenRegistryBackend):
    """Process-local, single-replica ``TokenRegistryBackend``.

    Lost on restart -- fine for local dev, not for a multi-replica
    deployment (see this module's docstring). Self-sweeps expired records on
    every mutating call so a long-running dev broker doesn't accumulate
    unbounded state.
    """

    def __init__(self) -> None:
        self._by_uid: dict[int, dict[str, TokenRecord]] = {}
        self._lock = asyncio.Lock()

    def _sweep_expired_locked(self, *, grace_seconds: float = 0.0) -> SweepStats:
        """Remove records expired more than *grace_seconds* in the past.

        Called with the default ``grace_seconds=0.0`` from ``add()`` --
        the existing self-sweep, unchanged -- and with a caller-supplied
        grace from the public ``sweep_expired()`` below (see that method's
        docstring for why a grace window exists at all).
        """
        now = time.time()
        cutoff = now - grace_seconds
        records_removed = 0
        revoked_pruned = 0
        uids_emptied = 0
        for uid, jtis in list(self._by_uid.items()):
            expired = [jti for jti, r in jtis.items() if r.expires_at <= cutoff]
            for jti in expired:
                if jtis[jti].revoked_at is not None:
                    revoked_pruned += 1
                del jtis[jti]
            records_removed += len(expired)
            if not jtis:
                del self._by_uid[uid]
                uids_emptied += 1
        return SweepStats(
            records_removed=records_removed,
            owners_removed=0,
            revoked_pruned=revoked_pruned,
            uids_emptied=uids_emptied,
        )

    async def sweep_expired(self, *, grace_seconds: int) -> SweepStats:
        async with self._lock:
            return self._sweep_expired_locked(grace_seconds=grace_seconds)

    async def add(self, record: TokenRecord) -> None:
        async with self._lock:
            self._sweep_expired_locked()
            now = time.time()
            for existing in self._by_uid.get(record.uid, {}).values():
                if _collides(existing, record, now):
                    raise DuplicateNameError(record.uid, record.name)
            self._by_uid.setdefault(record.uid, {})[record.jti] = record

    async def list_for_uid(self, uid: int) -> list[TokenRecord]:
        rows = list(self._by_uid.get(uid, {}).values())
        rows.sort(key=lambda r: r.issued_at, reverse=True)
        return rows

    async def get(self, uid: int, jti: str) -> TokenRecord | None:
        return self._by_uid.get(uid, {}).get(jti)

    async def owner_uid(self, jti: str) -> int | None:
        for uid, jtis in self._by_uid.items():
            if jti in jtis:
                return uid
        return None

    async def revoke(self, uid: int, jti: str, revoked_at: float) -> TokenRecord | None:
        async with self._lock:
            uid_map = self._by_uid.get(uid)
            if uid_map is None or jti not in uid_map:
                return None
            updated = replace(uid_map[jti], revoked_at=revoked_at)
            uid_map[jti] = updated
            return updated

    async def list_revoked_jtis(self) -> frozenset[str]:
        return frozenset(
            r.jti
            for jtis in self._by_uid.values()
            for r in jtis.values()
            if r.revoked_at is not None
        )


# ---------------------------------------------------------------------------
# Vault/OpenBao backend.
# ---------------------------------------------------------------------------


def _record_to_fields(record: TokenRecord) -> dict[str, Any]:
    return {
        "jti": record.jti,
        "uid": record.uid,
        "subject": record.subject,
        "name": record.name,
        "issued_at": record.issued_at,
        "expires_at": record.expires_at,
        "revoked_at": record.revoked_at,
        "minted_via": record.minted_via,
        "note": record.note,
    }


def _record_from_fields(fields: dict[str, Any]) -> TokenRecord:
    return TokenRecord(
        jti=fields["jti"],
        uid=int(fields["uid"]),
        subject=fields["subject"],
        name=fields["name"],
        issued_at=float(fields["issued_at"]),
        expires_at=float(fields["expires_at"]),
        revoked_at=(
            float(fields["revoked_at"])
            if fields.get("revoked_at") is not None
            else None
        ),
        minted_via=fields["minted_via"],
        # .get(), not [] -- entries written before issue #116 don't have this key.
        note=fields.get("note"),
    )


class VaultTokenRegistryBackend(TokenRegistryBackend):
    """``TokenRegistryBackend`` backed by Vault/OpenBao KV-v2 via a shared
    ``VaultKV`` transport client.

    See this module's docstring for the KV layout and the write-ordering
    rationale in ``revoke()``. Not thread-safe across processes beyond
    Vault's own CAS guarantees -- concurrent writers for the same uid retry
    on a version conflict (bounded by ``_MAX_CAS_RETRIES``), exactly like
    ``credentials/oauth21.py``'s ``OAuth21Provider`` handles refresh races.
    """

    def __init__(self, *, vault_kv: VaultKV, kv_path_prefix: str) -> None:
        self._vault_kv = vault_kv
        self._kv_path_prefix = kv_path_prefix.strip("/")

    def _by_uid_prefix(self) -> str:
        return f"{self._kv_path_prefix}/by-uid"

    def _uid_path(self, uid: int) -> str:
        return f"{self._kv_path_prefix}/by-uid/{uid}"

    def _owner_path(self, jti: str) -> str:
        return f"{self._kv_path_prefix}/jti-owner/{jti}"

    def _revoked_path(self) -> str:
        return f"{self._kv_path_prefix}/revoked-jtis"

    async def add(self, record: TokenRecord) -> None:
        path = self._uid_path(record.uid)
        now = time.time()
        for _attempt in range(_MAX_CAS_RETRIES):
            current = await self._vault_kv.get(path)
            data, version = current if current is not None else ({}, None)
            # Re-checked on every retry against the just-re-read data, not
            # just once up front -- see this module's docstring for why that
            # matters: a loser retrying after a CAS conflict must re-evaluate
            # uniqueness against whatever the winner just wrote, not a stale
            # read from before the race.
            for fields in data.values():
                existing = _record_from_fields(fields)
                if _collides(existing, record, now):
                    raise DuplicateNameError(record.uid, record.name)
            data = dict(data)
            data[record.jti] = _record_to_fields(record)
            try:
                await self._vault_kv.write_cas(path, data, version)
                break
            except CasConflict:
                continue
        else:
            raise VaultError(f"add(): exceeded retry budget for uid={record.uid!r}")

        # Ownership index: written once at mint time, never mutated again --
        # a plain create (expected_version=None) is correct even under a
        # (vanishingly unlikely) jti collision, since the same jti can only
        # ever belong to the uid that first minted it. A CasConflict here
        # just means a previous attempt of this same add() already recorded
        # it -- nothing to do.
        with contextlib.suppress(CasConflict):
            await self._vault_kv.write_cas(
                self._owner_path(record.jti), {"uid": record.uid}, None
            )

    async def list_for_uid(self, uid: int) -> list[TokenRecord]:
        current = await self._vault_kv.get(self._uid_path(uid))
        if current is None:
            return []
        data, _version = current
        rows = [_record_from_fields(fields) for fields in data.values()]
        rows.sort(key=lambda r: r.issued_at, reverse=True)
        return rows

    async def get(self, uid: int, jti: str) -> TokenRecord | None:
        current = await self._vault_kv.get(self._uid_path(uid))
        if current is None:
            return None
        data, _version = current
        fields = data.get(jti)
        return _record_from_fields(fields) if fields is not None else None

    async def owner_uid(self, jti: str) -> int | None:
        current = await self._vault_kv.get(self._owner_path(jti))
        if current is None:
            return None
        data, _version = current
        return int(data["uid"])

    async def _add_to_revoked_index(self, jti: str) -> None:
        path = self._revoked_path()
        for _attempt in range(_MAX_CAS_RETRIES):
            current = await self._vault_kv.get(path)
            data, version = current if current is not None else ({"jtis": []}, None)
            jtis = set(data.get("jtis", []))
            if jti in jtis:
                return
            jtis.add(jti)
            try:
                await self._vault_kv.write_cas(path, {"jtis": sorted(jtis)}, version)
            except CasConflict:
                continue
            else:
                return
        raise VaultError(
            f"revoke(): exceeded retry budget updating revoked-jtis index for jti={jti!r}"
        )

    async def revoke(self, uid: int, jti: str, revoked_at: float) -> TokenRecord | None:
        existing = await self.get(uid, jti)
        if existing is None:
            return None

        # Security-load-bearing write first -- see the module docstring.
        await self._add_to_revoked_index(jti)

        path = self._uid_path(uid)
        for _attempt in range(_MAX_CAS_RETRIES):
            current = await self._vault_kv.get(path)
            if current is None:
                return None
            data, version = current
            fields = data.get(jti)
            if fields is None:
                return None
            fields = dict(fields)
            fields["revoked_at"] = revoked_at
            new_data = dict(data)
            new_data[jti] = fields
            try:
                await self._vault_kv.write_cas(path, new_data, version)
                return _record_from_fields(fields)
            except CasConflict:
                continue
        raise VaultError(
            f"revoke(): exceeded retry budget updating uid={uid!r} jti={jti!r}"
        )

    async def list_revoked_jtis(self) -> frozenset[str]:
        current = await self._vault_kv.get(self._revoked_path())
        if current is None:
            return frozenset()
        data, _version = current
        return frozenset(data.get("jtis", []))

    async def sweep_expired(self, *, grace_seconds: int) -> SweepStats:
        now = time.time()
        cutoff = now - grace_seconds
        revoked_before = await self.list_revoked_jtis()

        records_removed = 0
        owners_removed = 0
        uids_emptied = 0
        jtis_to_prune_from_denylist: set[str] = set()

        prefix = self._by_uid_prefix()
        for uid_key in await self._vault_kv.list(prefix):
            path = f"{prefix}/{uid_key}"
            removed_this_uid: list[str] = []
            for _attempt in range(_MAX_CAS_RETRIES):
                current = await self._vault_kv.get(path)
                if current is None:
                    # Already gone -- a concurrent sweep/revoke/expiry race.
                    removed_this_uid = []
                    break
                data, version = current
                # Recomputed on every retry against the just-re-read data,
                # same reasoning as add()'s CAS loop: a conflict means
                # something else wrote this uid's entry in between, so the
                # set of still-expired jtis must be re-evaluated against
                # that write, not replayed from a stale read.
                to_remove = [
                    jti
                    for jti, fields in data.items()
                    if _record_from_fields(fields).expires_at <= cutoff
                ]
                if not to_remove:
                    removed_this_uid = []
                    break
                remaining = {
                    jti: fields for jti, fields in data.items() if jti not in to_remove
                }
                try:
                    if remaining:
                        await self._vault_kv.write_cas(path, remaining, version)
                    else:
                        # Metadata delete (not an empty-dict write_cas) so the
                        # version counter is destroyed too -- preserves a
                        # subsequent add()'s plain create (cas=0) for this
                        # uid, exactly as vault_kv.delete_metadata's
                        # docstring describes.
                        await self._vault_kv.delete_metadata(path)
                        uids_emptied += 1
                except CasConflict:
                    continue
                removed_this_uid = to_remove
                break
            else:
                raise VaultError(
                    f"sweep_expired(): exceeded retry budget for path={path!r}"
                )

            for jti in removed_this_uid:
                await self._vault_kv.delete_metadata(self._owner_path(jti))
                owners_removed += 1
                if jti in revoked_before:
                    jtis_to_prune_from_denylist.add(jti)
            records_removed += len(removed_this_uid)

        revoked_pruned = 0
        if jtis_to_prune_from_denylist:
            path = self._revoked_path()
            for _attempt in range(_MAX_CAS_RETRIES):
                current = await self._vault_kv.get(path)
                if current is None:
                    break
                data, version = current
                jtis = set(data.get("jtis", []))
                still_present = jtis & jtis_to_prune_from_denylist
                if not still_present:
                    break
                jtis -= still_present
                try:
                    await self._vault_kv.write_cas(
                        path, {"jtis": sorted(jtis)}, version
                    )
                except CasConflict:
                    continue
                revoked_pruned = len(still_present)
                break
            else:
                raise VaultError(
                    "sweep_expired(): exceeded retry budget pruning revoked-jtis"
                )

        return SweepStats(
            records_removed=records_removed,
            owners_removed=owners_removed,
            revoked_pruned=revoked_pruned,
            uids_emptied=uids_emptied,
        )


# ---------------------------------------------------------------------------
# RevokedJtiCache -- bridges the registry to identity.get_principal's hot
# JWT-validation path without a per-request Vault round trip.
# ---------------------------------------------------------------------------


class RevokedJtiCache:
    """In-process cache of revoked jtis, refreshed from a
    ``TokenRegistryBackend`` on a bounded interval.

    Every authenticated request (``/v1`` and ``/mcp`` alike) calls
    ``is_revoked()`` -- a per-request Vault read there would add real
    latency and load, so this cache serves a snapshot refreshed at most once
    per ``refresh_interval_seconds`` (default 30s, configurable via
    ``Settings.revoked_jti_cache_refresh_seconds``). Revocation therefore
    takes up to that interval to take effect broker-wide: a deliberate,
    documented staleness bound, not a bug -- see docs/auth.md.

    A refresh failure (e.g. Vault briefly unreachable) keeps serving the
    last-known set rather than failing every request open or closed
    unpredictably, mirroring identity.get_jwks's stale-on-failure fallback.
    """

    def __init__(
        self, backend: TokenRegistryBackend, refresh_interval_seconds: float = 30.0
    ) -> None:
        self._backend = backend
        self._refresh_interval = refresh_interval_seconds
        self._revoked: frozenset[str] = frozenset()
        self._last_refresh: float = float("-inf")
        self._lock = asyncio.Lock()
        self._log = structlog.get_logger(__name__).bind(component="RevokedJtiCache")

    async def is_revoked(self, jti: str) -> bool:
        await self._maybe_refresh()
        return jti in self._revoked

    async def _maybe_refresh(self) -> None:
        now = time.monotonic()
        if (now - self._last_refresh) < self._refresh_interval:
            return
        async with self._lock:
            now = time.monotonic()
            if (now - self._last_refresh) < self._refresh_interval:
                return
            try:
                self._revoked = await self._backend.list_revoked_jtis()
            except Exception:  # noqa: BLE001 — must never take auth down; serve stale
                self._log.warning(
                    "revoked_jti_cache.refresh_failed_serving_stale", exc_info=True
                )
            self._last_refresh = now
