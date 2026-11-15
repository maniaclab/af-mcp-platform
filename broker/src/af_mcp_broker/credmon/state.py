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
    async def release_lease(self, holder: str, *, now: float) -> None:
        """Give up *holder*'s lease so another replica can run a cycle immediately; a no-op if the lease is held by someone else (or nobody)."""

    @abstractmethod
    async def write_status(self, status: dict[str, Any]) -> None:
        """Replace the last-run status record."""

    @abstractmethod
    async def read_status(self) -> dict[str, Any] | None:
        """Return the last-run status record, or None before the first cycle."""
