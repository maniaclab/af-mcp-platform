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
        """Overwrite the current maintenance state."""


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
