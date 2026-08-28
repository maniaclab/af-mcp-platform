"""Broker-wide maintenance mode.

Toggling maintenance mode must be visible to every broker replica
consistently -- a flag flipped on one pod is useless if the others keep
admitting requests. This module only defines the store contract, so it
follows the same ABC-plus-selectable-backend shape as
``token_registry.TokenRegistryBackend``/``usage.UsageStore`` in anticipation
of that shared-visibility requirement; the admin-facing endpoint and the
``/v1``/``/mcp`` request-path enforcement that will read this store are
later, separate work and do not exist yet.

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
from typing import Any

from af_mcp_broker.vault_kv import CasConflict, VaultKV


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

        Raises ``MaintenanceStateConflict`` when a concurrent writer already
        changed the state.
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
