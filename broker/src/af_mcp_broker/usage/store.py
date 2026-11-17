"""Per-user usage accounting store (observability roadmap PR C).

The broker itself is the metering system: the metering pipeline
(``metering.py``) hands every success/error tool-call ``AuditRecord``
to a ``UsageStore``, which accumulates per-(day, service, method, outcome)
aggregates that ``GET /v1/usage`` serves back to the calling user. Usage is
best-effort by the same contract as metering -- the audit log stays
authoritative.

``InMemoryUsageStore`` here is the dev/small-facility default -- lost on
restart; ``usage/postgres.py`` is the durable backend, selected by
``settings.usage_store_backend``. Module-level wiring (init/aclose/the
``record_usage`` helper) lives in the package ``__init__``, mirroring the
pipeline's own shape.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from af_mcp_broker.audit.measure import ContentMeasure

if TYPE_CHECKING:
    from datetime import date

    from af_mcp_broker.audit.logger import AuditRecord


@dataclass(frozen=True)
class UsageAggregate:
    """One subject's usage rolled up per (UTC day, service, method, outcome).

    ``duration_ms``/``result_bytes``/``result_tokens_est`` are sums over the
    aggregated calls; a record whose corresponding ``AuditRecord`` field was
    None (nothing was measured) contributes 0 to the sum but still counts in
    ``calls``.

    ``content`` is the same sums split per MCP content type (an open set: see
    ``audit/measure.py``). A call recorded without a breakdown (unmeasured, or
    written by a replica that predates the breakdown) is in the totals but in
    no ``content`` entry, so the entries can sum to less than the totals;
    they never sum to more.
    """

    day: date
    service: str
    # The method (MCP "tool") name -- Elwood vocabulary; matches the
    # postgres column.
    method: str
    outcome: str  # "success" | "error"
    calls: int
    duration_ms: float
    result_bytes: int
    result_tokens_est: int
    content: dict[str, ContentMeasure] = field(default_factory=dict)


@dataclass(frozen=True)
class SubjectActivity:
    """A subject with recorded usage and the latest moment it was seen.

    ``last_seen`` is the timestamp of the subject's latest call; for usage
    already folded into the daily rollup only the UTC day survives, so it is
    that day's midnight.
    """

    subject: str
    last_seen: datetime


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

    async def record_many(self, records: list[AuditRecord]) -> None:
        """Account a batch of tool-call audit records.

        Backends with a cheaper bulk write override this (see
        ``PostgresUsageStore``); the default is one ``record`` per record.
        Redelivery tolerance applies across and within batches alike.
        """
        for record in records:
            await self.record(record)

    @abc.abstractmethod
    async def query(self, subject: str, days: int) -> list[UsageAggregate]:
        """Return aggregates for *subject* over the trailing *days* UTC calendar days, today inclusive."""

    @abc.abstractmethod
    async def list_subject_activity(self, days: int) -> list[SubjectActivity]:
        """Return each subject with usage in the trailing *days*-day window and when it was last seen, most recently seen first.

        Backs the admin user search, whose population is the people the
        platform has seen. One row per subject however many calls it made,
        so the result is bounded by the number of distinct users.
        """


def add_content(
    total: ContentMeasure | None, measure: ContentMeasure
) -> ContentMeasure:
    """*total* (None for a first sight of the type) plus *measure*."""
    if total is None:
        return measure
    return ContentMeasure(
        blocks=total.blocks + measure.blocks,
        bytes=total.bytes + measure.bytes,
        tokens_est=total.tokens_est + measure.tokens_est,
    )


def window_start(days: int) -> date:
    """First UTC calendar day inside a trailing *days*-day window.

    Shared by both backends so "trailing N days" means the same thing
    regardless of where the data lives: N calendar days, today (UTC)
    inclusive -- days=1 is just today.
    """
    return datetime.now(tz=UTC).date() - timedelta(days=days - 1)


_NEVER_SEEN = datetime.min.replace(tzinfo=UTC)


@dataclass
class _Counters:
    """Mutable accumulator behind one InMemoryUsageStore key."""

    calls: int = 0
    duration_ms: float = 0.0
    result_bytes: int = 0
    result_tokens_est: int = 0
    content: dict[str, ContentMeasure] = field(default_factory=dict)
    last_seen: datetime = _NEVER_SEEN


class InMemoryUsageStore(UsageStore):
    """Dict-of-counters usage store -- lost on restart.

    This is the dev/small-facility default: single-replica, no persistence,
    a broker restart zeroes everyone's usage view (the audit log, which is
    authoritative, is unaffected). Facilities that want durable usage select
    the postgres backend instead.
    """

    def __init__(self) -> None:
        # (subject, day, service, method, outcome) -> counters. Aggregating at
        # write time (rather than keeping raw events) bounds memory by the
        # number of distinct keys, not the call volume.
        self._counters: dict[tuple[str, date, str, str, str], _Counters] = {}

    async def start(self) -> None:
        """Nothing to acquire."""

    async def aclose(self) -> None:
        """Nothing to release."""

    async def record(self, record: AuditRecord) -> None:
        if record.mcp_service is None:
            # Defensive: only tool-call records are usage (the pipeline-side
            # helper already filters these out before they get here).
            return
        day = datetime.fromtimestamp(record.timestamp, tz=UTC).date()
        key = (
            record.subject,
            day,
            record.mcp_service,
            record.action,
            record.outcome,
        )
        counters = self._counters.setdefault(key, _Counters())
        counters.calls += 1
        counters.last_seen = max(
            counters.last_seen, datetime.fromtimestamp(record.timestamp, tz=UTC)
        )
        # None means "nothing measured" -- counts as a call, adds nothing.
        counters.duration_ms += record.duration_ms or 0.0
        counters.result_bytes += record.result_bytes or 0
        counters.result_tokens_est += record.result_tokens_est or 0
        for content_type, measure in (record.result_content or {}).items():
            counters.content[content_type] = add_content(
                counters.content.get(content_type), measure
            )

    async def query(self, subject: str, days: int) -> list[UsageAggregate]:
        start = window_start(days)
        return [
            UsageAggregate(
                day=day,
                service=service,
                method=method,
                outcome=outcome,
                calls=c.calls,
                duration_ms=c.duration_ms,
                result_bytes=c.result_bytes,
                result_tokens_est=c.result_tokens_est,
                content=dict(c.content),
            )
            for (sub, day, service, method, outcome), c in sorted(
                self._counters.items()
            )
            if sub == subject and day >= start
        ]

    async def list_subject_activity(self, days: int) -> list[SubjectActivity]:
        start = window_start(days)
        last_seen: dict[str, datetime] = {}
        for (sub, day, _s, _m, _o), counters in self._counters.items():
            if day < start:
                continue
            if sub not in last_seen or counters.last_seen > last_seen[sub]:
                last_seen[sub] = counters.last_seen
        return [
            SubjectActivity(subject=sub, last_seen=seen)
            for sub, seen in sorted(
                last_seen.items(), key=lambda item: item[1], reverse=True
            )
        ]
