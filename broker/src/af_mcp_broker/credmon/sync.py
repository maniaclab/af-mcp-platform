"""The in-broker credmon loop: decide when to run a ``CredmonStorer`` cycle, run it on one replica, and make the outcome visible.

Every replica ticks every ``poll_seconds``. A timer cycle runs only when
the shared status record says one is due (``now - last finished >=
interval_seconds``) and this replica wins the short per-cycle lease; a
manual run (``POST /v1/admin/credmon/sync``) skips the due check but still
needs the lease, so it works from whichever replica the request hits
without ever overlapping a running cycle. The lease holder writes the
status record that ``GET /v1/admin/credmon`` serves, and every outcome is
counted in Prometheus (metrics.py ``credmon_sync_*``).
"""

from __future__ import annotations

import asyncio
import contextlib
import time
from dataclasses import asdict
from typing import TYPE_CHECKING, Any

import structlog

from af_mcp_broker.metrics import (
    credmon_sync_credentials_total,
    credmon_sync_duration_seconds,
    credmon_sync_last_success_timestamp_seconds,
    credmon_sync_runs_total,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from af_mcp_broker.credmon.state import CredmonSyncState
    from af_mcp_broker.credmon.storer import CredmonStorer, SyncReport

log = structlog.get_logger(__name__)

# Most errors kept in the status record -- enough to diagnose, bounded so a
# credd outage across every user can't grow the Vault record without limit.
_MAX_STATUS_ERRORS = 20


class CredmonSyncService:
    """Runs credmon sync cycles on a timer and on demand, one replica at a time."""

    def __init__(
        self,
        *,
        storer: CredmonStorer,
        state: CredmonSyncState,
        holder: str,
        interval_seconds: float,
        lease_ttl_seconds: float,
        poll_seconds: float,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._storer = storer
        self._state = state
        self._holder = holder
        self._interval = interval_seconds
        self._lease_ttl = lease_ttl_seconds
        self._poll = poll_seconds
        self._clock = clock
        self._task: asyncio.Task[None] | None = None

    @property
    def interval_seconds(self) -> float:
        return self._interval

    @property
    def kinds(self) -> list[str]:
        return self._storer.kind_names

    async def tick(self) -> dict[str, Any] | None:
        """Run a timer cycle if one is due and the lease is ours; return the new status, or None when nothing ran."""
        status = await self._state.read_status()
        # Publish the shared last success on every tick, not only on the
        # replica that ran it: after a rollout no cycle may be due for hours,
        # and a fresh pod's gauge would otherwise read 0 and trip a
        # stale-sync alert on max() across replicas.
        if status is not None and status.get("last_success_at") is not None:
            credmon_sync_last_success_timestamp_seconds.set(
                float(status["last_success_at"])
            )
        if (
            status is not None
            and self._clock() - float(status["finished_at"]) < self._interval
        ):
            return None
        return await self._run("timer", previous=status)

    async def run_now(self) -> dict[str, Any] | None:
        """Run a cycle immediately (admin trigger); None when another replica holds the lease."""
        return await self._run("manual", previous=await self._state.read_status())

    async def read_status(self) -> dict[str, Any] | None:
        return await self._state.read_status()

    async def _run(
        self, trigger: str, *, previous: dict[str, Any] | None
    ) -> dict[str, Any] | None:
        if not await self._state.try_acquire_lease(
            self._holder, ttl_seconds=self._lease_ttl, now=self._clock()
        ):
            credmon_sync_runs_total.labels(
                outcome="skipped_lease", trigger=trigger
            ).inc()
            return None

        started_at = self._clock()
        last_success_at = previous.get("last_success_at") if previous else None
        try:
            report = await self._storer.run_once()
        except Exception as exc:
            # Any cycle-level failure (Vault LIST down, a bug) must surface
            # as a recorded, counted failure -- never kill the loop task.
            log.exception("credmon_sync.failed", trigger=trigger)
            status: dict[str, Any] = {
                "outcome": "failed",
                "trigger": trigger,
                "holder": self._holder,
                "started_at": started_at,
                "finished_at": self._clock(),
                "stored": {},
                "not_linked": {},
                "skipped_no_posix": {},
                "failed": {},
                "errors": [f"cycle failed: {exc}"],
                "errors_truncated": 0,
                "last_success_at": last_success_at,
            }
        else:
            status = self._status_from_report(report, trigger)

        credmon_sync_runs_total.labels(outcome=status["outcome"], trigger=trigger).inc()
        credmon_sync_duration_seconds.observe(
            status["finished_at"] - status["started_at"]
        )
        if status["outcome"] != "failed":
            credmon_sync_last_success_timestamp_seconds.set(status["finished_at"])
        await self._state.write_status(status)
        return status

    def _status_from_report(self, report: SyncReport, trigger: str) -> dict[str, Any]:
        for metric_outcome, counts in (
            ("stored", report.stored),
            ("failed", report.failed),
            ("not_linked", report.not_linked),
            ("no_posix", report.skipped_no_posix),
        ):
            for kind, count in counts.items():
                if count:
                    credmon_sync_credentials_total.labels(
                        kind=kind, outcome=metric_outcome
                    ).inc(count)
        data = asdict(report)
        errors: list[str] = data.pop("errors")
        return {
            **data,
            "outcome": "partial" if report.failed else "success",
            "trigger": trigger,
            "holder": self._holder,
            "errors": errors[:_MAX_STATUS_ERRORS],
            "errors_truncated": max(0, len(errors) - _MAX_STATUS_ERRORS),
            "last_success_at": report.finished_at,
        }

    def start(self) -> None:
        """Start the background polling loop (idempotent)."""
        if self._task is None:
            self._task = asyncio.create_task(self._loop(), name="credmon-sync")

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
            self._task = None

    async def _loop(self) -> None:
        while True:
            # Sleep first: a pod that just booted (or a test app) must not hit
            # Vault/htcondor-api at the instant of startup; the shared status
            # record, not this replica, decides whether a cycle is due.
            await asyncio.sleep(self._poll)
            try:
                await self.tick()
            except Exception:
                # Lease/status storage itself failed (e.g. Vault down): log
                # and keep polling -- the stale last-success gauge is what
                # tells the operator, not a dead task.
                log.exception("credmon_sync.tick_failed")
