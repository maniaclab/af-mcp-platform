"""Durable storage for broker-issued identity PAT metadata (issue #115, adapted for #144 step 2a).

Originally built for the RFC 8693 manual bearer-token bootstrap
(``api/tokens.py``'s original design, issue #24/#116), this module is
*adapted* -- not replaced -- for identity PATs (issue #144): the storage
contract (ABC, Vault-backed with an in-memory fallback, revocation, and a
sweep) is exactly the same shape, but the record it stores changes from "a
Keycloak JWT's jti + who it was exchanged for" to "a PAT's lookup_id +
secret hash + owning principal" -- see ``TokenRecord`` below.

This is the **PAT store** in #144's three-concern split (PAT store /
principal cache / capability engine): it answers "who is this token?" --
identity and metadata only. It carries no groups and no authorization data
whatsoever -- that is deliberately the principal cache's job
(``principal_cache.py``), keyed by principal id rather than by token, so
rotating or revoking a PAT never disturbs a user's cached authorization and
group changes propagate once per user rather than once per token. The one
deliberate exception (issue #144 step 4) is ``TokenRecord.capability_grant``:
an optional, static *restriction* a capability PAT carries on top of that --
never a source of authority by itself, and never consulted instead of the
principal cache's current groups. See that field's docstring and
``pat_auth._resolve_authority``/``authorization.get_principal_capabilities``
for where and how it's applied.

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

* ``by-principal/{principal_id}`` -> ``{lookup_id: {...TokenRecord fields...}}``,
  one entry per principal, written with CAS. Gives O(1) list-by-principal
  (the common case: every route is scoped to the caller's own principal).
  Partitioned by *principal_id* (the Keycloak `sub` claim, stable across
  group/uid changes) rather than POSIX uid -- a PAT record must not need any
  authorization-adjacent lookup just to know where it lives.
* ``lookup-owner/{lookup_id}`` -> ``{"principal_id": <id>}``, one entry per
  lookup_id, written once at mint time. Gives O(1) ownership lookup so the
  API layer can distinguish "unknown lookup_id" (404) from "lookup_id exists
  but belongs to someone else" (403) without a Vault LIST across every
  principal, and is what ``get_by_lookup_id()`` uses to answer validation's
  "who is this token?" question with a single indexed hop.
* ``revoked-lookup-ids``  -> ``{"jtis": [...]}``, a single flat entry every
  ``revoke()`` call updates. Gives ``RevokedJtiCache`` an O(1) read for its
  periodic refresh instead of enumerating every principal's by-principal
  entry. (The Vault key name and the cache class both still say "jti" --
  see ``RevokedJtiCache``'s docstring for why that name was kept as a
  generic "revoked token identifier" set rather than renamed.)

``revoke()`` writes ``revoked-lookup-ids`` BEFORE the per-principal entry's
``revoked_at`` field deliberately: that index is the one
``RevokedJtiCache``/PAT validation (``pat_auth.py``) actually enforce
against, so it must never lag behind the per-principal entry, which is
display-only (the portal's token list). A failure between the two writes can
only leave the list looking briefly stale ("active" a moment longer than it
should), never the reverse (enforced-revoked but still shown as active would
be a security gap; shown-as-active-a-bit-longer while actually enforced is
just UI lag).

Expiry is nullable: ``expires_at: float | None``, where ``None`` means the
PAT never expires -- an explicit opt-in (see ``api/tokens.py``'s
``MintTokenRequest.never_expires``), not the default. A record with
``expires_at=None`` is never touched by ``sweep_expired()`` and is always
"live" for the name-uniqueness check in ``_collides()`` below (until
revoked) -- there being no natural expiry to fall back on is exactly why
requiring an explicit opt-in matters.

``name`` is a unique-per-principal identifier, not free text (issue #116):
two records for the same principal may not share a name, compared
case-insensitively. Only *live* records (``revoked_at`` unset and not yet
past ``expires_at``, or never-expiring) count as a collision -- a name freed
up by revocation or natural expiry can be reused without confusion, since the
old record can no longer be mistaken for the new one. ``add()`` enforces
this itself (see ``_check_name_available`` and each backend's ``add()``)
rather than leaving it to a caller-side check-then-write, because a
caller-side check racing two concurrent mints (e.g. two broker replicas)
could let both pass the check before either writes. Both backends' single
per-principal record is small enough that a full scan of it at mint time is
fine -- no separate name index. For ``VaultTokenRegistryBackend``
specifically, the uniqueness check re-runs on every iteration of ``add()``'s
existing read-modify-write CAS retry loop (the same one that already
protects the by-principal write from lost updates), so a loser that retries
after a conflict re-checks against the winner's just-written data rather
than a stale read from before the race.

``last_used_at`` is updated via ``touch_last_used()``, called from the PAT
validation path (``pat_auth.py``) -- throttled there to at most once per
several minutes per lookup_id (see ``pat_auth.LastUsedTracker``), since a
write on every single ``/mcp`` request would hammer the KV store. This
module's ``touch_last_used()`` itself is unconditional; the throttling is the
caller's responsibility, exactly like the mint-rate-limiter in
``api/tokens.py`` is a caller-side, in-process-only concern layered on top of
this durable store.
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
    """Raised by add() when a record's ``name`` collides, case-insensitively, with an existing live (non-revoked, unexpired or never-expiring) record for the same principal -- see this module's docstring for the uniqueness rule."""

    def __init__(self, principal_id: str, name: str) -> None:
        self.principal_id = principal_id
        self.name = name
        super().__init__(f"Token name {name!r} is already in use.")


@dataclass(frozen=True)
class TokenRecord:
    """Metadata for one broker-issued identity PAT.

    Deliberately does NOT carry the PAT's plaintext secret, nor anything it
    could be reconstructed from -- only ``secret_hash`` (see ``pat.py``). The
    plaintext is returned to the caller exactly once, in the mint response;
    this record exists solely so the broker can validate a presented PAT and
    the portal can list/revoke what a principal has minted.

    Carries no groups and no authorization data of any kind -- see this
    module's docstring on the PAT-store/principal-cache split. ``principal_id``
    is the Keycloak ``sub`` claim; POSIX uid/gid/groups are resolved fresh at
    validation time from ``principal_cache.py``, never read off this record.

    ``capability_grant`` is the one deliberate exception (issue #144 step 4):
    ``None`` for an identity PAT (today's default, and every PAT minted
    before this field existed), or an explicit, immutable set of capability
    names for a **capability PAT**. It is a RESTRICTION on top of the
    principal's current capabilities, never a substitute for them --
    ``pat_auth._resolve_authority`` copies it onto the resulting
    ``Principal`` unchanged, and ``authorization.get_principal_capabilities``
    intersects it with whatever the principal's *current* groups grant. A
    record whose ``capability_grant`` happens to name a capability the
    principal doesn't currently hold (e.g. because they lost a group after
    this PAT was minted, or -- for a test -- because the record was
    constructed directly) is not a data-integrity problem: the intersection
    at request time simply never grants it, regardless of how it got here.
    """

    lookup_id: str
    principal_id: str
    secret_hash: str
    name: str
    created_at: float
    expires_at: float | None
    revoked_at: float | None
    last_used_at: float | None
    # Free-text, user-supplied, purely self-descriptive -- never consumed by
    # the broker itself (issue #116). None when the caller didn't supply one.
    note: str | None = None
    # See this dataclass's docstring. None (the default) for every identity
    # PAT; a capability PAT's grant otherwise -- see also Principal
    # .capability_grant and get_principal_capabilities.
    capability_grant: frozenset[str] | None = None


def _collides(existing: TokenRecord, candidate: TokenRecord, now: float) -> bool:
    """Return True if *existing* is a live record that blocks *candidate*'s name."""
    still_live = existing.expires_at is None or existing.expires_at > now
    return (
        existing.lookup_id != candidate.lookup_id
        and existing.revoked_at is None
        and still_live
        and existing.name.casefold() == candidate.name.casefold()
    )


def default_token_name(lookup_id: str, created_at: float) -> str:
    """Server-generated name (``mcp-YYYYMMDD-<lookup_id prefix>``) used when the caller didn't supply one at mint time."""
    date_str = datetime.fromtimestamp(created_at, tz=UTC).strftime("%Y%m%d")
    return f"mcp-{date_str}-{lookup_id[:8]}"


@dataclass(frozen=True)
class SweepStats:
    """Counts returned by ``TokenRegistryBackend.sweep_expired()`` -- what a single sweep pass actually did, for the CLI's structlog line and (for ``VaultTokenRegistryBackend``) test assertions on Vault-only bookkeeping.

    ``owners_removed`` is always 0 for ``InMemoryTokenRegistryBackend``: it
    has no separate lookup-owner index (``owner_principal_id()`` scans the
    by-principal dicts directly), so there's nothing extra to delete beyond
    the record itself.
    """

    records_removed: int
    owners_removed: int
    revoked_pruned: int
    principals_emptied: int


class TokenRegistryBackend(ABC):
    """Durable per-principal storage for broker-issued identity PAT metadata."""

    @abstractmethod
    async def add(self, record: TokenRecord) -> None:
        """Persist a newly minted record.

        Raises DuplicateNameError if *record*'s name collides, case-
        insensitively, with an existing live record for the same principal --
        see this module's docstring for the uniqueness rule.
        """

    @abstractmethod
    async def list_for_principal(self, principal_id: str) -> list[TokenRecord]:
        """Return every record owned by *principal_id*, newest ``created_at`` first."""

    @abstractmethod
    async def get(self, principal_id: str, lookup_id: str) -> TokenRecord | None:
        """Return the record for (*principal_id*, *lookup_id*), or None if absent."""

    @abstractmethod
    async def owner_principal_id(self, lookup_id: str) -> str | None:
        """Return the principal_id that owns *lookup_id*, or None if *lookup_id* is unknown.

        Lets the API layer distinguish "unknown token" (404) from "token
        exists but you don't own it" (403) without needing a principal-scoped
        lookup first.
        """

    @abstractmethod
    async def revoke(
        self, principal_id: str, lookup_id: str, revoked_at: float
    ) -> TokenRecord | None:
        """Mark (*principal_id*, *lookup_id*) revoked; returns the updated record, or None if *lookup_id* is unknown or not owned by *principal_id*."""

    async def get_by_lookup_id(self, lookup_id: str) -> TokenRecord | None:
        """Return the record for *lookup_id* regardless of owner, or None if unknown.

        A concrete (non-abstract) convenience built from ``owner_principal_id()``
        + ``get()`` -- the primary operation PAT validation needs (``pat_auth.
        resolve_pat_principal``): validation only ever has the token's own
        ``lookup_id``, not the owning principal_id, so this collapses what
        would otherwise be two round trips at every call site into one.
        Implemented once here rather than duplicated in both backends.
        """
        principal_id = await self.owner_principal_id(lookup_id)
        if principal_id is None:
            return None
        return await self.get(principal_id, lookup_id)

    @abstractmethod
    async def touch_last_used(
        self, principal_id: str, lookup_id: str, at: float
    ) -> None:
        """Best-effort update of a record's ``last_used_at``. A no-op if *lookup_id* is unknown or not owned by *principal_id* -- validation has already succeeded by the time this is called, so there is nothing more useful to do with a lost race against a concurrent revoke than silently skip the write."""

    @abstractmethod
    async def list_revoked_jtis(self) -> frozenset[str]:
        """Return every lookup_id, across all principals, whose ``revoked_at`` is set.

        Named ``list_revoked_jtis`` (not ``..._lookup_ids``) because
        ``RevokedJtiCache`` -- the sole caller -- already treats "jti" as a
        generic "unique token identifier" string, and is shared with the
        JWT-bearer-revocation path in ``identity.get_principal``; see that
        cache's docstring.
        """

    @abstractmethod
    async def sweep_expired(self, *, grace_seconds: int) -> SweepStats:
        """Remove every record whose ``expires_at`` is set and more than *grace_seconds* in the past, across all principals.

        Never-expiring records (``expires_at is None``) are never touched by
        this method -- there is no natural expiry to sweep against; they are
        only ever removed by an explicit revoke followed by... nothing, they
        simply stay listed as revoked forever (same as any revoked record
        within its own grace window).

        The grace window is deliberate, not an implementation accident: a
        token that just expired is still meaningful to show the caller as
        "expired" on the portal's token list for a while, rather than
        vanishing the instant its own ``expires_at`` passes. Live records
        (``expires_at`` still in the future, or never-expiring) and records
        expired less than *grace_seconds* ago are both left untouched.

        Also prunes ``revoked-lookup-ids`` of any lookup_id this pass removes
        for being expired past grace -- an expired PAT can never authenticate
        again regardless of its revoked status, so keeping it in the denylist
        forever would only make that set grow without bound. A live-but-
        revoked record is untouched by this pruning; it stays in the denylist
        until its own expiry catches up (or forever, if it never expires).
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
        self._by_principal: dict[str, dict[str, TokenRecord]] = {}
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
        principals_emptied = 0
        for principal_id, lookup_ids in list(self._by_principal.items()):
            expired = [
                lookup_id
                for lookup_id, r in lookup_ids.items()
                if r.expires_at is not None and r.expires_at <= cutoff
            ]
            for lookup_id in expired:
                if lookup_ids[lookup_id].revoked_at is not None:
                    revoked_pruned += 1
                del lookup_ids[lookup_id]
            records_removed += len(expired)
            if not lookup_ids:
                del self._by_principal[principal_id]
                principals_emptied += 1
        return SweepStats(
            records_removed=records_removed,
            owners_removed=0,
            revoked_pruned=revoked_pruned,
            principals_emptied=principals_emptied,
        )

    async def sweep_expired(self, *, grace_seconds: int) -> SweepStats:
        async with self._lock:
            return self._sweep_expired_locked(grace_seconds=grace_seconds)

    async def add(self, record: TokenRecord) -> None:
        async with self._lock:
            self._sweep_expired_locked()
            now = time.time()
            for existing in self._by_principal.get(record.principal_id, {}).values():
                if _collides(existing, record, now):
                    raise DuplicateNameError(record.principal_id, record.name)
            self._by_principal.setdefault(record.principal_id, {})[record.lookup_id] = (
                record
            )

    async def list_for_principal(self, principal_id: str) -> list[TokenRecord]:
        rows = list(self._by_principal.get(principal_id, {}).values())
        rows.sort(key=lambda r: r.created_at, reverse=True)
        return rows

    async def get(self, principal_id: str, lookup_id: str) -> TokenRecord | None:
        return self._by_principal.get(principal_id, {}).get(lookup_id)

    async def owner_principal_id(self, lookup_id: str) -> str | None:
        for principal_id, lookup_ids in self._by_principal.items():
            if lookup_id in lookup_ids:
                return principal_id
        return None

    async def revoke(
        self, principal_id: str, lookup_id: str, revoked_at: float
    ) -> TokenRecord | None:
        async with self._lock:
            principal_map = self._by_principal.get(principal_id)
            if principal_map is None or lookup_id not in principal_map:
                return None
            updated = replace(principal_map[lookup_id], revoked_at=revoked_at)
            principal_map[lookup_id] = updated
            return updated

    async def touch_last_used(
        self, principal_id: str, lookup_id: str, at: float
    ) -> None:
        async with self._lock:
            principal_map = self._by_principal.get(principal_id)
            if principal_map is None or lookup_id not in principal_map:
                return
            principal_map[lookup_id] = replace(
                principal_map[lookup_id], last_used_at=at
            )

    async def list_revoked_jtis(self) -> frozenset[str]:
        return frozenset(
            r.lookup_id
            for lookup_ids in self._by_principal.values()
            for r in lookup_ids.values()
            if r.revoked_at is not None
        )


# ---------------------------------------------------------------------------
# Vault/OpenBao backend.
# ---------------------------------------------------------------------------


def _record_to_fields(record: TokenRecord) -> dict[str, Any]:
    return {
        "lookup_id": record.lookup_id,
        "principal_id": record.principal_id,
        "secret_hash": record.secret_hash,
        "name": record.name,
        "created_at": record.created_at,
        "expires_at": record.expires_at,
        "revoked_at": record.revoked_at,
        "last_used_at": record.last_used_at,
        "note": record.note,
        # Sorted for a stable on-disk representation (set/frozenset iteration
        # order is not guaranteed) -- None (identity PAT) stored as None, not
        # an empty list, so _record_from_fields can distinguish "no grant at
        # all" from "a grant of zero capabilities" (the latter never arises
        # from mint_token today, but the round trip should still be exact).
        "capability_grant": (
            sorted(record.capability_grant)
            if record.capability_grant is not None
            else None
        ),
    }


def _record_from_fields(fields: dict[str, Any]) -> TokenRecord:
    return TokenRecord(
        lookup_id=fields["lookup_id"],
        principal_id=fields["principal_id"],
        secret_hash=fields["secret_hash"],
        name=fields["name"],
        created_at=float(fields["created_at"]),
        expires_at=(
            float(fields["expires_at"])
            if fields.get("expires_at") is not None
            else None
        ),
        revoked_at=(
            float(fields["revoked_at"])
            if fields.get("revoked_at") is not None
            else None
        ),
        last_used_at=(
            float(fields["last_used_at"])
            if fields.get("last_used_at") is not None
            else None
        ),
        note=fields.get("note"),
        capability_grant=(
            frozenset(fields["capability_grant"])
            if fields.get("capability_grant") is not None
            else None
        ),
    )


def _expired_past_cutoff(fields: dict[str, Any], cutoff: float) -> bool:
    """Return True if the raw KV *fields* decode to a record whose ``expires_at`` is set and at or before *cutoff*. Never-expiring records (``expires_at`` absent/None) are never "expired"."""
    expires_at = _record_from_fields(fields).expires_at
    return expires_at is not None and expires_at <= cutoff


class VaultTokenRegistryBackend(TokenRegistryBackend):
    """``TokenRegistryBackend`` backed by Vault/OpenBao KV-v2 via a shared ``VaultKV`` transport client.

    See this module's docstring for the KV layout and the write-ordering
    rationale in ``revoke()``. Not thread-safe across processes beyond
    Vault's own CAS guarantees -- concurrent writers for the same principal
    retry on a version conflict (bounded by ``_MAX_CAS_RETRIES``), exactly
    like ``credentials/oauth21.py``'s ``OAuth21Provider`` handles refresh
    races.
    """

    def __init__(self, *, vault_kv: VaultKV, kv_path_prefix: str) -> None:
        self._vault_kv = vault_kv
        self._kv_path_prefix = kv_path_prefix.strip("/")

    def _by_principal_prefix(self) -> str:
        return f"{self._kv_path_prefix}/by-principal"

    def _principal_path(self, principal_id: str) -> str:
        return f"{self._kv_path_prefix}/by-principal/{principal_id}"

    def _owner_path(self, lookup_id: str) -> str:
        return f"{self._kv_path_prefix}/lookup-owner/{lookup_id}"

    def _revoked_path(self) -> str:
        return f"{self._kv_path_prefix}/revoked-lookup-ids"

    async def add(self, record: TokenRecord) -> None:
        path = self._principal_path(record.principal_id)
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
                    raise DuplicateNameError(record.principal_id, record.name)
            data = dict(data)
            data[record.lookup_id] = _record_to_fields(record)
            try:
                await self._vault_kv.write_cas(path, data, version)
                break
            except CasConflict:
                continue
        else:
            raise VaultError(
                f"add(): exceeded retry budget for principal_id={record.principal_id!r}"
            )

        # Ownership index: written once at mint time, never mutated again --
        # a plain create (expected_version=None) is correct even under a
        # (vanishingly unlikely) lookup_id collision, since the same
        # lookup_id can only ever belong to the principal that first minted
        # it. A CasConflict here just means a previous attempt of this same
        # add() already recorded it -- nothing to do.
        with contextlib.suppress(CasConflict):
            await self._vault_kv.write_cas(
                self._owner_path(record.lookup_id),
                {"principal_id": record.principal_id},
                None,
            )

    async def list_for_principal(self, principal_id: str) -> list[TokenRecord]:
        current = await self._vault_kv.get(self._principal_path(principal_id))
        if current is None:
            return []
        data, _version = current
        rows = [_record_from_fields(fields) for fields in data.values()]
        rows.sort(key=lambda r: r.created_at, reverse=True)
        return rows

    async def get(self, principal_id: str, lookup_id: str) -> TokenRecord | None:
        current = await self._vault_kv.get(self._principal_path(principal_id))
        if current is None:
            return None
        data, _version = current
        fields = data.get(lookup_id)
        return _record_from_fields(fields) if fields is not None else None

    async def owner_principal_id(self, lookup_id: str) -> str | None:
        current = await self._vault_kv.get(self._owner_path(lookup_id))
        if current is None:
            return None
        data, _version = current
        return str(data["principal_id"])

    async def _add_to_revoked_index(self, lookup_id: str) -> None:
        path = self._revoked_path()
        for _attempt in range(_MAX_CAS_RETRIES):
            current = await self._vault_kv.get(path)
            data, version = current if current is not None else ({"jtis": []}, None)
            lookup_ids = set(data.get("jtis", []))
            if lookup_id in lookup_ids:
                return
            lookup_ids.add(lookup_id)
            try:
                await self._vault_kv.write_cas(
                    path, {"jtis": sorted(lookup_ids)}, version
                )
            except CasConflict:
                continue
            else:
                return
        raise VaultError(
            "revoke(): exceeded retry budget updating revoked-lookup-ids index "
            f"for lookup_id={lookup_id!r}"
        )

    async def revoke(
        self, principal_id: str, lookup_id: str, revoked_at: float
    ) -> TokenRecord | None:
        existing = await self.get(principal_id, lookup_id)
        if existing is None:
            return None

        # Security-load-bearing write first -- see the module docstring.
        await self._add_to_revoked_index(lookup_id)

        path = self._principal_path(principal_id)
        for _attempt in range(_MAX_CAS_RETRIES):
            current = await self._vault_kv.get(path)
            if current is None:
                return None
            data, version = current
            fields = data.get(lookup_id)
            if fields is None:
                return None
            fields = dict(fields)
            fields["revoked_at"] = revoked_at
            new_data = dict(data)
            new_data[lookup_id] = fields
            try:
                await self._vault_kv.write_cas(path, new_data, version)
                return _record_from_fields(fields)
            except CasConflict:
                continue
        raise VaultError(
            "revoke(): exceeded retry budget updating "
            f"principal_id={principal_id!r} lookup_id={lookup_id!r}"
        )

    async def touch_last_used(
        self, principal_id: str, lookup_id: str, at: float
    ) -> None:
        path = self._principal_path(principal_id)
        for _attempt in range(_MAX_CAS_RETRIES):
            current = await self._vault_kv.get(path)
            if current is None:
                return
            data, version = current
            fields = data.get(lookup_id)
            if fields is None:
                return
            fields = dict(fields)
            fields["last_used_at"] = at
            new_data = dict(data)
            new_data[lookup_id] = fields
            try:
                await self._vault_kv.write_cas(path, new_data, version)
            except CasConflict:
                continue
            else:
                return
        # Best-effort only (see the ABC docstring) -- log rather than raise,
        # since this is called from the hot validation path and must never
        # turn a successful auth into a 500.
        log.warning(
            "token_registry.touch_last_used_retry_budget_exceeded",
            principal_id=principal_id,
            lookup_id=lookup_id,
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
        principals_emptied = 0
        lookup_ids_to_prune_from_denylist: set[str] = set()

        prefix = self._by_principal_prefix()
        for principal_key in await self._vault_kv.list(prefix):
            path = f"{prefix}/{principal_key}"
            removed_this_principal: list[str] = []
            for _attempt in range(_MAX_CAS_RETRIES):
                current = await self._vault_kv.get(path)
                if current is None:
                    # Already gone -- a concurrent sweep/revoke/expiry race.
                    removed_this_principal = []
                    break
                data, version = current
                # Recomputed on every retry against the just-re-read data,
                # same reasoning as add()'s CAS loop: a conflict means
                # something else wrote this principal's entry in between, so
                # the set of still-expired lookup_ids must be re-evaluated
                # against that write, not replayed from a stale read.
                to_remove = [
                    lookup_id
                    for lookup_id, fields in data.items()
                    if _expired_past_cutoff(fields, cutoff)
                ]
                if not to_remove:
                    removed_this_principal = []
                    break
                remaining = {
                    lookup_id: fields
                    for lookup_id, fields in data.items()
                    if lookup_id not in to_remove
                }
                try:
                    if remaining:
                        await self._vault_kv.write_cas(path, remaining, version)
                    else:
                        # Metadata delete (not an empty-dict write_cas) so the
                        # version counter is destroyed too -- preserves a
                        # subsequent add()'s plain create (cas=0) for this
                        # principal, exactly as vault_kv.delete_metadata's
                        # docstring describes.
                        await self._vault_kv.delete_metadata(path)
                        principals_emptied += 1
                except CasConflict:
                    continue
                removed_this_principal = to_remove
                break
            else:
                raise VaultError(
                    f"sweep_expired(): exceeded retry budget for path={path!r}"
                )

            for lookup_id in removed_this_principal:
                await self._vault_kv.delete_metadata(self._owner_path(lookup_id))
                owners_removed += 1
                if lookup_id in revoked_before:
                    lookup_ids_to_prune_from_denylist.add(lookup_id)
            records_removed += len(removed_this_principal)

        revoked_pruned = 0
        if lookup_ids_to_prune_from_denylist:
            path = self._revoked_path()
            for _attempt in range(_MAX_CAS_RETRIES):
                current = await self._vault_kv.get(path)
                if current is None:
                    break
                data, version = current
                lookup_ids = set(data.get("jtis", []))
                still_present = lookup_ids & lookup_ids_to_prune_from_denylist
                if not still_present:
                    break
                lookup_ids -= still_present
                try:
                    await self._vault_kv.write_cas(
                        path, {"jtis": sorted(lookup_ids)}, version
                    )
                except CasConflict:
                    continue
                revoked_pruned = len(still_present)
                break
            else:
                raise VaultError(
                    "sweep_expired(): exceeded retry budget pruning revoked-lookup-ids"
                )

        return SweepStats(
            records_removed=records_removed,
            owners_removed=owners_removed,
            revoked_pruned=revoked_pruned,
            principals_emptied=principals_emptied,
        )


# ---------------------------------------------------------------------------
# RevokedJtiCache -- bridges the registry to both identity.get_principal's
# hot JWT-validation path AND pat_auth.py's PAT-validation path, without a
# per-request Vault round trip.
# ---------------------------------------------------------------------------


class RevokedJtiCache:
    """In-process cache of revoked token identifiers, refreshed from a ``TokenRegistryBackend`` on a bounded interval.

    Kept generically named "jti" (rather than renamed to something PAT-
    specific) because it is a single shared choke point for two different
    kinds of unique token identifier: a JWT's own ``jti`` claim (checked by
    ``identity.get_principal``, still exercised by any Keycloak-issued JWT
    ``/mcp``/`/v1`` accept -- see issue #144's step 5 for when that path
    eventually retires) and a PAT's ``lookup_id`` (checked by
    ``pat_auth.resolve_pat_principal``). Both are just opaque strings from
    this cache's point of view -- it has no notion of which kind it's
    looking at, and doesn't need one.

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
