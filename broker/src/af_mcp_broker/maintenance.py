"""Broker-wide maintenance mode.

Toggling maintenance mode must be visible to every broker replica
consistently -- a flag flipped on one pod is useless if the others keep
admitting requests. The store contract follows the same
ABC-plus-selectable-backend shape as
``token_registry.TokenRegistryBackend``/``usage.UsageStore`` in anticipation
of that shared-visibility requirement. ``check_not_maintenance`` is the
request-path enforcement gate that reads a store; it is wired into /v1 (see
``identity.require_not_in_maintenance``). The admin-facing endpoint to
toggle the state, and the /mcp call site, are later, separate work and do
not exist yet.

``MaintenanceModeStore`` has ``start()``/``aclose()`` like ``UsageStore``
(not the simpler get/put-only shape of ``PrincipalCacheBackend``/
``TokenRegistryBackend``) because the postgres backend needs its own asyncpg
connection pool lifecycle; the in-memory and Vault backends' start/aclose are
no-ops, matching ``InMemoryUsageStore``'s asymmetry with
``PostgresUsageStore``.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import asyncpg  # type: ignore[import-untyped]
from fastapi import HTTPException, status

from af_mcp_broker.authorization import is_admin
from af_mcp_broker.vault_kv import CasConflict, VaultKV

if TYPE_CHECKING:
    from af_mcp_broker.config import Settings
    from af_mcp_broker.identity import Principal


class MaintenanceStateConflict(Exception):
    """Raised by ``MaintenanceModeStore.set`` when a concurrent writer already changed the state."""


@dataclass(frozen=True)
class MaintenanceState:
    """The broker's maintenance-mode flag and who set it."""

    enabled: bool
    reason: str | None
    enabled_by: str | None  # admin subject
    enabled_at: float | None  # time.time()


_DISABLED = MaintenanceState(
    enabled=False, reason=None, enabled_by=None, enabled_at=None
)


class MaintenanceModeStore(abc.ABC):
    """Durable storage for the broker's single maintenance-mode record."""

    @abc.abstractmethod
    async def start(self) -> None:
        """Acquire whatever the backend needs (connections, schema)."""

    @abc.abstractmethod
    async def aclose(self) -> None:
        """Release the backend's resources."""

    @abc.abstractmethod
    async def get(self) -> MaintenanceState:
        """Return the current maintenance state -- disabled if never set."""

    @abc.abstractmethod
    async def set(self, state: MaintenanceState) -> None:
        """Overwrite the current maintenance state.

        May raise ``MaintenanceStateConflict`` on backends that support
        compare-and-set writes (currently only ``VaultMaintenanceModeStore``)
        when a concurrent writer already changed the state; other backends
        silently apply last-writer-wins.
        """


class InMemoryMaintenanceModeStore(MaintenanceModeStore):
    """Process-local, single-replica store -- the dev/local default.

    State is lost on process restart. That's a sharper caveat here than for
    ``InMemoryUsageStore``: an admin enabling maintenance mode to ride out a
    pod restart would have it silently revert to disabled the moment that
    pod comes back up, working against the feature's own primary use case.
    """

    def __init__(self) -> None:
        self._state: MaintenanceState = _DISABLED

    async def start(self) -> None:
        """Nothing to acquire."""

    async def aclose(self) -> None:
        """Nothing to release."""

    async def get(self) -> MaintenanceState:
        return self._state

    async def set(self, state: MaintenanceState) -> None:
        self._state = state


_KV_KEY = "state"


def _state_to_fields(state: MaintenanceState) -> dict[str, Any]:
    return {
        "enabled": state.enabled,
        "reason": state.reason,
        "enabled_by": state.enabled_by,
        "enabled_at": state.enabled_at,
    }


def _state_from_fields(fields: dict[str, Any]) -> MaintenanceState:
    return MaintenanceState(
        enabled=bool(fields.get("enabled", False)),
        reason=fields.get("reason"),
        enabled_by=fields.get("enabled_by"),
        enabled_at=fields.get("enabled_at"),
    )


class VaultMaintenanceModeStore(MaintenanceModeStore):
    """``MaintenanceModeStore`` backed by Vault/OpenBao KV-v2, one record at ``{kv_path_prefix}/state`` -- HA-safe across replicas.

    No CAS-retry loop, unlike ``VaultPrincipalCacheBackend.put()`` -- see
    this class's ``set()``.
    """

    def __init__(self, *, vault_kv: VaultKV, kv_path_prefix: str) -> None:
        self._vault_kv = vault_kv
        self._path = f"{kv_path_prefix.strip('/')}/{_KV_KEY}"

    async def start(self) -> None:
        """Nothing to acquire -- vault_kv is already authenticated by app.py's lifespan."""

    async def aclose(self) -> None:
        """Nothing to release."""

    async def get(self) -> MaintenanceState:
        current = await self._vault_kv.get(self._path)
        if current is None:
            return _DISABLED
        data, _version = current
        return _state_from_fields(data)

    async def set(self, state: MaintenanceState) -> None:
        """Overwrite the current maintenance state.

        A single read-then-CAS-write, no retry loop: unlike
        ``VaultPrincipalCacheBackend.put()`` (whose lost race is harmless --
        the loser just tries again on its own next refresh cycle), this is a
        deliberate admin action toggling shared, user-visible facility state.
        Silently retrying such an action behind the caller's back could
        commit them to a decision made with stale knowledge of the current
        state; raising ``MaintenanceStateConflict`` once and letting the
        caller (the admin API, a later task) decide whether to re-read and
        retry is the correct failure mode for this kind of write.
        """
        current = await self._vault_kv.get(self._path)
        version = current[1] if current is not None else None
        try:
            await self._vault_kv.write_cas(self._path, _state_to_fields(state), version)
        except CasConflict as exc:
            raise MaintenanceStateConflict(
                f"vault cas write conflict for path={self._path!r} "
                f"expected_version={version!r}"
            ) from exc


# Idempotent DDL, single-row table (id is always 1) -- mirrors usage/postgres.py's
# CREATE TABLE IF NOT EXISTS shape; one table does not justify a migration
# framework here either. CREATE TABLE IF NOT EXISTS makes every broker
# start (and every replica racing another against the same database) safe
# against a schema that already exists.
_DDL = """
CREATE TABLE IF NOT EXISTS af_mcp_maintenance_mode (
    id SMALLINT PRIMARY KEY DEFAULT 1,
    enabled BOOLEAN NOT NULL,
    reason TEXT,
    enabled_by TEXT,
    enabled_at DOUBLE PRECISION,
    CONSTRAINT single_row CHECK (id = 1)
);
"""

_UPSERT = """
INSERT INTO af_mcp_maintenance_mode (id, enabled, reason, enabled_by, enabled_at)
VALUES (1, $1, $2, $3, $4)
ON CONFLICT (id) DO UPDATE SET
    enabled = EXCLUDED.enabled,
    reason = EXCLUDED.reason,
    enabled_by = EXCLUDED.enabled_by,
    enabled_at = EXCLUDED.enabled_at
"""

_SELECT = "SELECT enabled, reason, enabled_by, enabled_at FROM af_mcp_maintenance_mode WHERE id = 1"


class PostgresMaintenanceModeStore(MaintenanceModeStore):
    """``MaintenanceModeStore`` backed by a single-row Postgres table (asyncpg)."""

    def __init__(self, dsn: str) -> None:
        self._dsn = dsn
        self._pool: asyncpg.Pool | None = None

    async def start(self) -> None:
        self._pool = await asyncpg.create_pool(self._dsn)
        async with self._pool.acquire() as conn:
            await conn.execute(_DDL)

    async def aclose(self) -> None:
        if self._pool is None:
            return
        await self._pool.close()
        self._pool = None

    def _require_pool(self) -> asyncpg.Pool:
        if self._pool is None:
            raise RuntimeError("PostgresMaintenanceModeStore used before start()")
        return self._pool

    async def get(self) -> MaintenanceState:
        row = await self._require_pool().fetchrow(_SELECT)
        if row is None:
            return _DISABLED
        return MaintenanceState(
            enabled=row["enabled"],
            reason=row["reason"],
            enabled_by=row["enabled_by"],
            enabled_at=row["enabled_at"],
        )

    async def set(self, state: MaintenanceState) -> None:
        await self._require_pool().execute(
            _UPSERT, state.enabled, state.reason, state.enabled_by, state.enabled_at
        )


async def check_not_maintenance(
    principal: Principal,
    settings: Settings,
    store: MaintenanceModeStore | None,
) -> None:
    """Raise HTTPException(503) when maintenance mode is on and *principal* is not an admin.

    Called from /v1 (``identity.require_not_in_maintenance``) and, in a
    later task, from /mcp (AsgiAuthMiddleware, mcp/middleware/identity_mw.py)
    right after a Principal is resolved (JWT or PAT) -- one gate, two call
    sites, so both credential types and both surfaces are covered uniformly.
    A None *store* (maintenance mode unconfigured -- unreachable in a
    properly started app, but matches the getattr-default-None pattern every
    other optional app.state lookup in this codebase uses) never blocks
    anyone.

    ``state.reason`` is echoed verbatim to every blocked caller across both
    /v1 and /mcp -- treat it like a public status-page message; never put
    secrets or internal details in it.

    Store-unavailability limitation: this function has no error handling
    around ``store.get()`` -- an outage there surfaces as an unclassified
    exception, not a clean 503 (see the admin-check comment below). Every
    caller of this function fails OPEN on that exception rather than
    treating it as "blocked": ``identity.require_not_in_maintenance``'s
    docstring has the full reasoning and, importantly, the resulting
    limitation -- maintenance mode is a planned-maintenance convenience
    feature, not an incident-containment control, precisely because a
    store outage lets non-admins straight through rather than blocking
    them.
    """
    if store is None:
        return
    # Admin check runs before store.get() as a fail-safe, not just an
    # optimization: if the store backend itself is unreachable (a Vault or
    # Postgres outage), an admin must still be able to get through to fix
    # things. This function has no error handling around store.get() -- an
    # outage there surfaces as an unclassified exception, not a clean 503.
    if is_admin(principal, settings):
        return
    state = await store.get()
    if not state.enabled:
        return
    detail = "The broker is in maintenance mode."
    if state.reason:
        detail = f"{detail} Reason: {state.reason}"
    raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=detail)
