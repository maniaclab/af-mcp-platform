"""Per-user usage accounting store (observability roadmap PR C).

The broker itself is the metering system: the metering pipeline
(``audit/pipeline.py``) hands every success/error tool-call ``AuditRecord``
to a ``UsageStore``, which accumulates per-(day, service, tool, outcome)
aggregates that ``GET /v1/usage`` serves back to the calling user. Usage is
best-effort by the same contract as metering -- the audit log stays
authoritative -- and dollars are NEVER stored: only tokens; cost is derived
at read time from a price table (see ``api/usage.py``).

``InMemoryUsageStore`` here is the dev/small-facility default -- lost on
restart; ``usage/postgres.py`` is the durable backend, selected by
``settings.usage_store_backend``. Module-level wiring (init/aclose/the
``record_usage`` helper) lives in the package ``__init__``, mirroring the
pipeline's own shape.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import date

    from af_mcp_broker.audit.logger import AuditRecord


@dataclass(frozen=True)
class UsageAggregate:
    """One subject's usage rolled up per (UTC day, service, tool, outcome).

    ``duration_ms``/``result_bytes``/``result_tokens_est`` are sums over the
    aggregated calls; a record whose corresponding ``AuditRecord`` field was
    None (nothing was measured) contributes 0 to the sum but still counts in
    ``calls``.
    """

    day: date
    service: str
    tool: str
    outcome: str  # "success" | "error"
    calls: int
    duration_ms: float
    result_bytes: int
    result_tokens_est: int


class UsageStore(abc.ABC):
    """Where per-user usage aggregates live.

    Implementations must tolerate redelivery of the same record: the
    metering contract is best-effort, so a caller may hand over a record it
    is not certain was stored. ``AuditRecord.audit_id`` is the idempotency
    key.
    """

    @abc.abstractmethod
    async def start(self) -> None:
        """Acquire whatever the backend needs (connections, schema)."""

    @abc.abstractmethod
    async def aclose(self) -> None:
        """Release the backend's resources."""

    @abc.abstractmethod
    async def record(self, record: AuditRecord) -> None:
        """Account one tool-call audit record (``mcp_service`` set)."""

    @abc.abstractmethod
    async def query(self, subject: str, days: int) -> list[UsageAggregate]:
        """Aggregates for *subject* over the trailing *days* UTC calendar days, today inclusive."""


def window_start(days: int) -> date:
    """First UTC calendar day inside a trailing *days*-day window.

    Shared by both backends so "trailing N days" means the same thing
    regardless of where the data lives: N calendar days, today (UTC)
    inclusive -- days=1 is just today.
    """
    return datetime.now(tz=UTC).date() - timedelta(days=days - 1)


@dataclass
class _Counters:
    """Mutable accumulator behind one InMemoryUsageStore key."""

    calls: int = 0
    duration_ms: float = 0.0
    result_bytes: int = 0
    result_tokens_est: int = 0


class InMemoryUsageStore(UsageStore):
    """Dict-of-counters usage store -- lost on restart.

    This is the dev/small-facility default: single-replica, no persistence,
    a broker restart zeroes everyone's usage view (the audit log, which is
    authoritative, is unaffected). Facilities that want durable usage select
    the postgres backend instead.
    """

    def __init__(self) -> None:
        # (subject, day, service, tool, outcome) -> counters. Aggregating at
        # write time (rather than keeping raw events) bounds memory by the
        # number of distinct keys, not the call volume.
        self._counters: dict[tuple[str, date, str, str, str], _Counters] = {}

    async def start(self) -> None:  # noqa: D102 -- nothing to acquire
        pass

    async def aclose(self) -> None:  # noqa: D102 -- nothing to release
        pass

    async def record(self, record: AuditRecord) -> None:
        if record.mcp_service is None:
            # Defensive: only tool-call records are usage (the pipeline-side
            # helper already filters these out before they get here).
            return
        day = datetime.fromtimestamp(record.timestamp, tz=UTC).date()
        key = (
            record.principal_sub,
            day,
            record.mcp_service,
            record.action,
            record.outcome,
        )
        counters = self._counters.setdefault(key, _Counters())
        counters.calls += 1
        # None means "nothing measured" -- counts as a call, adds nothing.
        counters.duration_ms += record.duration_ms or 0.0
        counters.result_bytes += record.result_bytes or 0
        counters.result_tokens_est += record.result_tokens_est or 0

    async def query(self, subject: str, days: int) -> list[UsageAggregate]:
        start = window_start(days)
        return [
            UsageAggregate(
                day=day,
                service=service,
                tool=tool,
                outcome=outcome,
                calls=c.calls,
                duration_ms=c.duration_ms,
                result_bytes=c.result_bytes,
                result_tokens_est=c.result_tokens_est,
            )
            for (sub, day, service, tool, outcome), c in sorted(
                self._counters.items()
            )
            if sub == subject and day >= start
        ]
