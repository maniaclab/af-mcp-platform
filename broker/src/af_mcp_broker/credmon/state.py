"""Cross-replica credmon sync state: the single-runner lease and the last-run status record.

Every broker replica runs the sync loop, but only the lease holder runs a
cycle -- so with N replicas credd sees one store per user per cycle, not
N. The holder then writes the cycle's ``SyncReport`` as the status record,
which ``GET /v1/admin/credmon`` (and the portal admin page) read back, so
every replica answers the status question identically.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class CredmonSyncState(ABC):
    """Lease + status storage shared by every broker replica."""

    @abstractmethod
    async def try_acquire_lease(
        self, holder: str, *, ttl_seconds: float, now: float
    ) -> bool:
        """Take (or renew) the lease for *holder* until ``now + ttl_seconds``; False when another holder's lease is still live or a concurrent acquire won."""

    @abstractmethod
    async def write_status(self, status: dict[str, Any]) -> None:
        """Replace the last-run status record."""

    @abstractmethod
    async def read_status(self) -> dict[str, Any] | None:
        """Return the last-run status record, or None before the first cycle."""


class InMemoryCredmonSyncState(CredmonSyncState):
    """Single-process state for local dev and tests (no Vault): one replica, so the lease always goes to whoever asks while unexpired-or-own."""

    def __init__(self) -> None:
        self._holder: str | None = None
        self._expires_at = 0.0
        self._status: dict[str, Any] | None = None

    async def try_acquire_lease(
        self, holder: str, *, ttl_seconds: float, now: float
    ) -> bool:
        if self._holder not in (None, holder) and self._expires_at > now:
            return False
        self._holder = holder
        self._expires_at = now + ttl_seconds
        return True

    async def write_status(self, status: dict[str, Any]) -> None:
        self._status = dict(status)

    async def read_status(self) -> dict[str, Any] | None:
        return dict(self._status) if self._status is not None else None
