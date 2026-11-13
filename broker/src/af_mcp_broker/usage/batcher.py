"""Size- and age-bounded buffer of usage records (metering worker only).

The metering worker is a single task, so this buffer is deliberately not
thread- or task-safe. It holds records that already passed the audit write
and hands them to a sink in one call when ``max_size`` records have
accumulated or ``interval_seconds`` have elapsed since the first buffered
record, whichever comes first -- which is what turns one store round trip
per tool call into one per batch. Records buffered here are lost on a hard
crash; the audit line for each was written first, so the audit log stays
authoritative.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from af_mcp_broker.audit.logger import AuditRecord


class UsageBatcher:
    """Accumulate records; hand them to *sink* in batches."""

    def __init__(
        self,
        sink: Callable[[list[AuditRecord]], Awaitable[None]],
        max_size: int,
        interval_seconds: float,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._sink = sink
        self._max_size = max_size
        self._interval_seconds = interval_seconds
        self._clock = clock
        self._pending: list[AuditRecord] = []
        # clock() reading at which the oldest buffered record must be flushed;
        # None while the buffer is empty.
        self._deadline: float | None = None

    def seconds_until_due(self) -> float | None:
        """Seconds until the age bound forces a flush (0 if overdue); None if empty."""
        if self._deadline is None:
            return None
        return max(0.0, self._deadline - self._clock())

    async def add(self, record: AuditRecord) -> None:
        """Buffer *record*, flushing if that fills the batch."""
        if not self._pending:
            self._deadline = self._clock() + self._interval_seconds
        self._pending.append(record)
        if len(self._pending) >= self._max_size:
            await self.flush()

    async def flush_if_due(self) -> None:
        """Flush if the oldest buffered record has reached the age bound."""
        if self.seconds_until_due() == 0.0:
            await self.flush()

    async def flush(self) -> None:
        """Hand everything buffered to the sink as one batch."""
        if not self._pending:
            return
        # Swap before awaiting: the buffer is empty again whether or not the
        # sink succeeds, so a failing batch is never re-sent.
        batch, self._pending = self._pending, []
        self._deadline = None
        await self._sink(batch)
