"""Durable storage for manually-minted bearer token metadata (issue #115).

Successor to ``api/tokens.py``'s original in-memory-only ``TokenRegistry``
(issue #24 / PR #28): at ``replicaCount: 2`` an in-process dict is invisible
across replicas and lost on restart, which breaks list/revoke consistency and
silently caps the effective mint-rate-limit at N times the configured value.

``TokenRegistryBackend`` is the storage contract two implementations satisfy:

* ``InMemoryTokenRegistryBackend`` -- single-replica, lost on restart. Local-
  dev fallback, selected the same way ``credentials.oauth21.InMemoryTokenStore``
  is (``settings.token_registry_backend == "in_memory"``, the default).
* ``VaultTokenRegistryBackend`` -- persists to Vault/OpenBao KV-v2 via the
  Kubernetes auth method, following the same pattern
  ``credentials/vault.py``'s ``VaultTokenStore`` uses (re-authenticates from
  the pod's ServiceAccount JWT rather than holding a long-lived Vault
  credential of its own). Deliberately a separate, self-contained
  implementation rather than a subclass/composition of ``VaultTokenStore`` --
  the two stores persist unrelated payload shapes under different KV
  prefixes, and keeping them independent avoids coupling two differently
  tested Vault clients together. This does duplicate the small K8s-auth
  login routine; a shared helper is a reasonable follow-up if a third
  Vault-backed store ever appears.

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

Neither backend actively prunes expired entries from Vault -- an entry
simply stops mattering once its JWT's own ``exp`` claim makes it invalid
regardless of registry state (see identity.get_principal), so unbounded
growth here is a display/storage concern, not a security one. A future janitor
could sweep expired entries; out of scope here (`InMemoryTokenRegistryBackend`
does still self-sweep, since it is a plain in-process dict with no external
TTL of its own).
"""

from __future__ import annotations

import asyncio
import contextlib
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any

import structlog

from af_mcp_broker.http import get_http_client

if TYPE_CHECKING:
    import httpx

log = structlog.get_logger(__name__)

# Bounded retry budget for the read-modify-write CAS loops below -- a
# genuine conflict storm this deep would indicate something pathological
# (far beyond two replicas racing once), so failing loudly past this point
# is preferable to retrying forever.
_MAX_CAS_RETRIES = 5

# Vault K8s auth tokens are re-minted this many seconds before their lease
# actually expires -- mirrors credentials/vault.py's VaultTokenStore.
_AUTH_SAFETY_MARGIN_SECONDS = 60


class VaultError(Exception):
    """Raised when Vault's HTTP API returns an unexpected response."""


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


def default_token_name(jti: str, issued_at: float) -> str:
    """Server-generated name (``mcp-YYYYMMDD-<jti prefix>``) used when the
    caller didn't supply one at mint time."""
    date_str = datetime.fromtimestamp(issued_at, tz=UTC).strftime("%Y%m%d")
    return f"mcp-{date_str}-{jti[:8]}"


class TokenRegistryBackend(ABC):
    """Durable per-uid storage for manually-minted bearer token metadata."""

    @abstractmethod
    async def add(self, record: TokenRecord) -> None:
        """Persist a newly minted record."""

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

    def _sweep_expired_locked(self) -> None:
        now = time.time()
        for uid, jtis in list(self._by_uid.items()):
            expired = [jti for jti, r in jtis.items() if r.expires_at <= now]
            for jti in expired:
                del jtis[jti]
            if not jtis:
                del self._by_uid[uid]

    async def add(self, record: TokenRecord) -> None:
        async with self._lock:
            self._sweep_expired_locked()
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
    )


class VaultTokenRegistryBackend(TokenRegistryBackend):
    """``TokenRegistryBackend`` backed by Vault/OpenBao KV-v2.

    See this module's docstring for the KV layout and the write-ordering
    rationale in ``revoke()``. Not thread-safe across processes beyond
    Vault's own CAS guarantees -- concurrent writers for the same uid retry
    on a version conflict (bounded by ``_MAX_CAS_RETRIES``), exactly like
    ``credentials/oauth21.py``'s ``OAuth21Provider`` handles refresh races.
    """

    def __init__(
        self,
        *,
        addr: str,
        auth_mount: str,
        auth_role: str,
        kv_mount: str,
        kv_path_prefix: str,
        sa_token_path: str,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self._addr = addr.rstrip("/")
        self._auth_mount = auth_mount
        self._auth_role = auth_role
        self._kv_mount = kv_mount
        self._kv_path_prefix = kv_path_prefix.strip("/")
        self._sa_token_path = sa_token_path
        self._http_client = http_client

        self._client_token: str | None = None
        self._expires_at: datetime | None = None
        self._auth_lock = asyncio.Lock()

        self._log = structlog.get_logger(__name__).bind(
            provider="VaultTokenRegistryBackend"
        )

    def _http(self) -> httpx.AsyncClient:
        return self._http_client if self._http_client is not None else get_http_client()

    def _uid_path(self, uid: int) -> str:
        return f"{self._kv_path_prefix}/by-uid/{uid}"

    def _owner_path(self, jti: str) -> str:
        return f"{self._kv_path_prefix}/jti-owner/{jti}"

    def _revoked_path(self) -> str:
        return f"{self._kv_path_prefix}/revoked-jtis"

    async def _authenticate(self) -> str:
        """Return a valid Vault client token, re-authenticating if the
        cached one is missing or near expiry. See ``VaultTokenStore``
        (credentials/vault.py) for the identical pattern this mirrors."""
        async with self._auth_lock:
            now = datetime.now(UTC)
            if (
                self._client_token is not None
                and self._expires_at is not None
                and now < self._expires_at
            ):
                return self._client_token

            jwt = Path(self._sa_token_path).read_text().strip()
            resp = await self._http().post(
                f"{self._addr}/v1/auth/{self._auth_mount}/login",
                json={"role": self._auth_role, "jwt": jwt},
                timeout=10.0,
            )
            if resp.status_code != 200:
                raise VaultError(
                    "vault k8s auth login failed: "
                    f"status={resp.status_code} body={resp.text!r}"
                )

            auth = resp.json()["auth"]
            client_token: str = auth["client_token"]
            lease_duration = int(auth["lease_duration"])

            self._client_token = client_token
            self._expires_at = now + timedelta(
                seconds=lease_duration - _AUTH_SAFETY_MARGIN_SECONDS
            )
            self._log.info(
                "vault_token_registry.reauthenticated", lease_duration=lease_duration
            )
            return client_token

    async def _kv_get(self, path: str) -> tuple[dict[str, Any], int] | None:
        token = await self._authenticate()
        resp = await self._http().get(
            f"{self._addr}/v1/{self._kv_mount}/data/{path}",
            headers={"X-Vault-Token": token},
            timeout=10.0,
        )
        if resp.status_code == 404:
            return None
        if resp.status_code != 200:
            raise VaultError(
                f"vault kv read failed for path={path!r}: "
                f"status={resp.status_code} body={resp.text!r}"
            )
        body = resp.json()["data"]
        return body["data"], int(body["metadata"]["version"])

    async def _kv_write_cas(
        self, path: str, data: dict[str, Any], expected_version: int | None
    ) -> int:
        token = await self._authenticate()
        cas = 0 if expected_version is None else expected_version
        resp = await self._http().post(
            f"{self._addr}/v1/{self._kv_mount}/data/{path}",
            headers={"X-Vault-Token": token},
            json={"options": {"cas": cas}, "data": data},
            timeout=10.0,
        )
        if resp.status_code == 200:
            return int(resp.json()["data"]["version"])
        if resp.status_code == 400:
            errors = resp.json().get("errors", [])
            if any("check-and-set" in err for err in errors):
                raise _CasConflict(path)
        raise VaultError(
            f"vault kv write failed for path={path!r}: "
            f"status={resp.status_code} body={resp.text!r}"
        )

    async def add(self, record: TokenRecord) -> None:
        path = self._uid_path(record.uid)
        for _attempt in range(_MAX_CAS_RETRIES):
            current = await self._kv_get(path)
            data, version = current if current is not None else ({}, None)
            data = dict(data)
            data[record.jti] = _record_to_fields(record)
            try:
                await self._kv_write_cas(path, data, version)
                break
            except _CasConflict:
                continue
        else:
            raise VaultError(f"add(): exceeded retry budget for uid={record.uid!r}")

        # Ownership index: written once at mint time, never mutated again --
        # a plain create (expected_version=None) is correct even under a
        # (vanishingly unlikely) jti collision, since the same jti can only
        # ever belong to the uid that first minted it. A _CasConflict here
        # just means a previous attempt of this same add() already recorded
        # it -- nothing to do.
        with contextlib.suppress(_CasConflict):
            await self._kv_write_cas(
                self._owner_path(record.jti), {"uid": record.uid}, None
            )

    async def list_for_uid(self, uid: int) -> list[TokenRecord]:
        current = await self._kv_get(self._uid_path(uid))
        if current is None:
            return []
        data, _version = current
        rows = [_record_from_fields(fields) for fields in data.values()]
        rows.sort(key=lambda r: r.issued_at, reverse=True)
        return rows

    async def get(self, uid: int, jti: str) -> TokenRecord | None:
        current = await self._kv_get(self._uid_path(uid))
        if current is None:
            return None
        data, _version = current
        fields = data.get(jti)
        return _record_from_fields(fields) if fields is not None else None

    async def owner_uid(self, jti: str) -> int | None:
        current = await self._kv_get(self._owner_path(jti))
        if current is None:
            return None
        data, _version = current
        return int(data["uid"])

    async def _add_to_revoked_index(self, jti: str) -> None:
        path = self._revoked_path()
        for _attempt in range(_MAX_CAS_RETRIES):
            current = await self._kv_get(path)
            data, version = current if current is not None else ({"jtis": []}, None)
            jtis = set(data.get("jtis", []))
            if jti in jtis:
                return
            jtis.add(jti)
            try:
                await self._kv_write_cas(path, {"jtis": sorted(jtis)}, version)
            except _CasConflict:
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
            current = await self._kv_get(path)
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
                await self._kv_write_cas(path, new_data, version)
                return _record_from_fields(fields)
            except _CasConflict:
                continue
        raise VaultError(
            f"revoke(): exceeded retry budget updating uid={uid!r} jti={jti!r}"
        )

    async def list_revoked_jtis(self) -> frozenset[str]:
        current = await self._kv_get(self._revoked_path())
        if current is None:
            return frozenset()
        data, _version = current
        return frozenset(data.get("jtis", []))


class _CasConflict(Exception):
    """Internal signal for a Vault KV-v2 CAS version mismatch -- caught by
    the retry loops in add()/revoke()/_add_to_revoked_index(), never raised
    to callers of the public TokenRegistryBackend interface."""


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
