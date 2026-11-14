"""Postgres-backed ``UsageStore`` (asyncpg) -- the durable usage backend.

One raw event row per tool-call audit record, keyed by ``audit_id``:
inserting with ``ON CONFLICT (audit_id) DO NOTHING`` makes recording
idempotent, so redelivery of the same record (best-effort metering may hand
one over more than once) is safe by construction. Aggregation happens in
SQL at query time (``GROUP BY day, service, method, outcome``), keeping the
stored data raw enough to re-slice later without a schema change.

Raw rows are bounded by retention: ``rollup_and_prune`` folds rows older than
the window into the ``af_mcp_usage_daily`` rollup (keyed ``(day,
principal_sub, service, method, outcome)``, the shape every read uses) and
deletes them in one statement. Reads sum raw rows and rollup rows, so a
window answers identically before and after a row moves.

The DSN is ``settings.usage_postgres_dsn`` -- with Crunchy PGO, typically
the ``uri`` key of the operator-generated ``<cluster>-pguser-<user>``
secret.
"""

from __future__ import annotations

import asyncio
import contextlib
from datetime import UTC, date, datetime, time, timedelta
from typing import TYPE_CHECKING, Any

import asyncpg  # type: ignore[import-untyped]
import structlog

from af_mcp_broker.usage.store import UsageAggregate, UsageStore, window_start

if TYPE_CHECKING:
    from af_mcp_broker.audit.logger import AuditRecord

logger = structlog.get_logger(__name__)

# Idempotent DDL run by start(). Deliberate: a handful of tables, indexes and
# ADD COLUMN IF NOT EXISTS statements do not justify a migration framework
# yet -- IF NOT EXISTS makes every broker start (and every replica racing
# another) safe against a schema that already exists. Revisit if a
# non-idempotent change ever shows up.
#
# The DO block is the one migration so far (Elwood vocabulary: the public
# name for what a service exposes is a *method*): tables created before the
# rename carry a `tool` column, and renaming it here -- guarded, so it is
# idempotent and a no-op on fresh or already-migrated tables -- lets deploys
# self-migrate with no manual step. During a rolling deploy, not-yet-updated
# replicas briefly fail their inserts against the renamed column; usage is
# best-effort by contract (audit records are authoritative), so that window
# loses nothing that matters.
_DDL = """
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = current_schema()
          AND table_name = 'af_mcp_usage_events'
          AND column_name = 'tool'
    ) THEN
        ALTER TABLE af_mcp_usage_events RENAME COLUMN tool TO method;
    END IF;
END $$;
CREATE TABLE IF NOT EXISTS af_mcp_usage_events (
    audit_id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL,
    principal_sub TEXT NOT NULL,
    service TEXT NOT NULL,
    method TEXT NOT NULL,
    action_type TEXT NOT NULL,
    outcome TEXT NOT NULL,
    ts TIMESTAMPTZ NOT NULL,
    duration_ms DOUBLE PRECISION,
    result_bytes BIGINT,
    result_tokens_est BIGINT
);
-- token_id (the calling PAT's public lookup_id) and trace_id (OTel trace)
-- join a usage row to the token it was made with and to the trace; NULL for
-- a session JWT, for an untraced call, and on rows that predate the columns. Deliberately not
-- indexed: nothing reads by them yet, and an index would add write load.
ALTER TABLE af_mcp_usage_events ADD COLUMN IF NOT EXISTS token_id TEXT;
ALTER TABLE af_mcp_usage_events ADD COLUMN IF NOT EXISTS trace_id TEXT;
CREATE INDEX IF NOT EXISTS af_mcp_usage_events_principal_ts
    ON af_mcp_usage_events (principal_sub, ts);
CREATE INDEX IF NOT EXISTS af_mcp_usage_events_ts
    ON af_mcp_usage_events (ts);
CREATE TABLE IF NOT EXISTS af_mcp_usage_daily (
    day DATE NOT NULL,
    principal_sub TEXT NOT NULL,
    service TEXT NOT NULL,
    method TEXT NOT NULL,
    outcome TEXT NOT NULL,
    calls BIGINT NOT NULL,
    duration_ms DOUBLE PRECISION NOT NULL,
    result_bytes BIGINT NOT NULL,
    result_tokens_est BIGINT NOT NULL,
    PRIMARY KEY (day, principal_sub, service, method, outcome)
);
CREATE INDEX IF NOT EXISTS af_mcp_usage_daily_principal_day
    ON af_mcp_usage_daily (principal_sub, day);
"""

_INSERT = """
INSERT INTO af_mcp_usage_events (
    audit_id, request_id, principal_sub, service, method, action_type,
    outcome, ts, duration_ms, result_bytes, result_tokens_est,
    token_id, trace_id
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
ON CONFLICT (audit_id) DO NOTHING
"""

# Advisory lock key serializing the rollup job across replicas (see
# rollup_and_prune). Arbitrary but fixed: ASCII "afmcusg" + 1.
_ROLLUP_LOCK_KEY = 0x61666D6375736701

# The window bound is computed in Python (usage/store.py's window_start) and
# passed in, so both backends share one definition of "trailing N days". The
# raw-row predicate is a plain range on ``ts`` (bound = UTC midnight of the
# window's first day) so the ts / (principal_sub, ts) indexes stay usable;
# wrapping ``ts`` in ``(ts AT TIME ZONE 'UTC')::date`` there defeats them.
# The cast stays in the SELECT list, where it costs nothing.
_RAW_QUERY = """
SELECT (ts AT TIME ZONE 'UTC')::date AS day,
       service, method, outcome,
       count(*)::bigint AS calls,
       coalesce(sum(duration_ms), 0)::double precision AS duration_ms,
       coalesce(sum(result_bytes), 0)::bigint AS result_bytes,
       coalesce(sum(result_tokens_est), 0)::bigint AS result_tokens_est
FROM af_mcp_usage_events
WHERE principal_sub = $1 AND ts >= $2
GROUP BY day, service, method, outcome
"""

# Raw rows plus rolled-up days, summed per key: a key can appear in both when
# a late-arriving old row is still waiting for the next rollup pass.
_QUERY = f"""
SELECT day, service, method, outcome,
       sum(calls)::bigint AS calls,
       sum(duration_ms)::double precision AS duration_ms,
       sum(result_bytes)::bigint AS result_bytes,
       sum(result_tokens_est)::bigint AS result_tokens_est
FROM (
    {_RAW_QUERY}
    UNION ALL
    SELECT day, service, method, outcome,
           calls, duration_ms, result_bytes, result_tokens_est
    FROM af_mcp_usage_daily
    WHERE principal_sub = $1 AND day >= $3
) AS merged
GROUP BY day, service, method, outcome
ORDER BY day, service, method, outcome
"""

_RAW_SUBJECTS_QUERY = """
SELECT DISTINCT principal_sub
FROM af_mcp_usage_events
WHERE ts >= $1
"""

_LIST_SUBJECTS_QUERY = f"""
{_RAW_SUBJECTS_QUERY}
UNION
SELECT principal_sub FROM af_mcp_usage_daily WHERE day >= $2
"""

# Folds every raw row older than $1 into the daily rollup and deletes it in
# ONE statement: the rows the DELETE returns are exactly the rows summed, so
# nothing is counted twice or lost even if a row is inserted concurrently.
# ON CONFLICT adds to an existing daily row (a late-arriving old row lands in
# a day that was already rolled up), which is correct because each raw row
# is summed exactly once, in the statement that deletes it.
_ROLLUP = """
WITH moved AS (
    DELETE FROM af_mcp_usage_events
    WHERE ts < $1
    RETURNING principal_sub, service, method, outcome, ts,
              duration_ms, result_bytes, result_tokens_est
)
INSERT INTO af_mcp_usage_daily AS d (
    day, principal_sub, service, method, outcome,
    calls, duration_ms, result_bytes, result_tokens_est
)
SELECT (ts AT TIME ZONE 'UTC')::date, principal_sub, service, method, outcome,
       count(*),
       coalesce(sum(duration_ms), 0),
       coalesce(sum(result_bytes), 0),
       coalesce(sum(result_tokens_est), 0)
FROM moved
GROUP BY 1, 2, 3, 4, 5
ON CONFLICT (day, principal_sub, service, method, outcome) DO UPDATE SET
    calls = d.calls + EXCLUDED.calls,
    duration_ms = d.duration_ms + EXCLUDED.duration_ms,
    result_bytes = d.result_bytes + EXCLUDED.result_bytes,
    result_tokens_est = d.result_tokens_est + EXCLUDED.result_tokens_est
"""


def _utc_midnight(day: date) -> datetime:
    return datetime.combine(day, time.min, tzinfo=UTC)


# asyncpg.create_pool()'s own defaults are min_size=10, max_size=10 --
# eagerly opening 10 connections per replica at start(), regardless of
# actual load. This DSN commonly shares one small Postgres instance with
# PostgresMaintenanceModeStore's own pool (maintenance.py) and, in
# production, with a second broker deployment pointed at a sibling database
# on the same server -- the unbounded defaults exhausted the instance's
# max_connections during a routine rolling restart, once a second platform
# instance (sharing the same Postgres server) was stood up alongside this
# one (2026-09-19 production incident). Bounded down here rather than left
# at the driver's default.
_POOL_MIN_SIZE = 1
_POOL_MAX_SIZE = 5


class PostgresUsageStore(UsageStore):
    """asyncpg-pooled usage store over the ``af_mcp_usage_events`` table."""

    def __init__(
        self,
        dsn: str,
        *,
        retention_days: int = 0,
        rollup_interval_seconds: float = 3600,
    ) -> None:
        self._dsn = dsn
        self._retention_days = retention_days
        self._rollup_interval_seconds = rollup_interval_seconds
        self._pool: asyncpg.Pool | None = None
        self._rollup_task: asyncio.Task[None] | None = None

    async def start(self) -> None:
        self._pool = await asyncpg.create_pool(
            self._dsn, min_size=_POOL_MIN_SIZE, max_size=_POOL_MAX_SIZE
        )
        async with self._pool.acquire() as conn:
            await conn.execute(_DDL)
        if self._retention_days > 0:
            self._rollup_task = asyncio.create_task(
                self._rollup_loop(), name="usage-rollup"
            )

    async def aclose(self) -> None:
        if self._rollup_task is not None:
            self._rollup_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._rollup_task
            self._rollup_task = None
        if self._pool is None:
            return
        await self._pool.close()
        self._pool = None

    def _require_pool(self) -> asyncpg.Pool:
        if self._pool is None:
            raise RuntimeError("PostgresUsageStore used before start()")
        return self._pool

    @staticmethod
    def _insert_args(record: AuditRecord) -> tuple[Any, ...]:
        return (
            record.audit_id,
            record.request_id,
            record.principal_sub,
            record.mcp_service,
            record.action,
            record.action_type,
            record.outcome,
            datetime.fromtimestamp(record.timestamp, tz=UTC),
            record.duration_ms,
            record.result_bytes,
            record.result_tokens_est,
            record.token_id,
            record.trace_id,
        )

    async def record(self, record: AuditRecord) -> None:
        if record.mcp_service is None:
            # Defensive: only tool-call records are usage (the pipeline-side
            # helper already filters these out before they get here).
            return
        await self._require_pool().execute(_INSERT, *self._insert_args(record))

    async def record_many(self, records: list[AuditRecord]) -> None:
        # executemany over one multi-row INSERT: asyncpg prepares the
        # statement once and pipelines every argument tuple in a single
        # round trip, with no SQL to build and no 32767-bind-parameter
        # ceiling to size USAGE_BATCH_MAX against. ON CONFLICT DO NOTHING
        # also dedups a repeated audit_id inside the batch. The batch runs in
        # one implicit transaction, so it is all-or-nothing: one rejected row
        # rolls back its siblings, and the caller (usage.record_usage_batch)
        # counts every row of a failed batch as failed.
        args = [
            self._insert_args(record)
            for record in records
            if record.mcp_service is not None
        ]
        if not args:
            return
        await self._require_pool().executemany(_INSERT, args)

    async def query(self, subject: str, days: int) -> list[UsageAggregate]:
        start = window_start(days)
        rows = await self._require_pool().fetch(
            _QUERY, subject, _utc_midnight(start), start
        )
        return [
            UsageAggregate(
                day=row["day"],
                service=row["service"],
                method=row["method"],
                outcome=row["outcome"],
                calls=row["calls"],
                duration_ms=row["duration_ms"],
                result_bytes=row["result_bytes"],
                result_tokens_est=row["result_tokens_est"],
            )
            for row in rows
        ]

    async def list_subjects(self, days: int) -> list[str]:
        start = window_start(days)
        rows = await self._require_pool().fetch(
            _LIST_SUBJECTS_QUERY, _utc_midnight(start), start
        )
        return sorted(row["principal_sub"] for row in rows)

    async def rollup_and_prune(self, retention_days: int) -> bool:
        """Fold raw rows older than *retention_days* UTC days into the daily rollup.

        Returns False without touching anything when retention is disabled
        (``retention_days`` 0) or another replica holds the job. Every replica
        calls this on a timer; ``pg_try_advisory_xact_lock`` lets one through.
        A Postgres advisory lock is used rather than the shared-state store
        because the work is in Postgres already: the lock needs no second
        dependency (shared state is Redis, optional, and falls back to
        per-replica memory when down -- which would let every replica run the
        job), it is released automatically when the transaction ends or the
        replica dies, and it cannot outlive the work it guards. Safety does
        not depend on the lock: the single DELETE ... RETURNING statement sums
        exactly the rows it removes, so two replicas racing would still count
        each row once; the lock only avoids the duplicate scan.
        """
        if retention_days <= 0:
            return False
        cutoff = _utc_midnight(
            datetime.now(tz=UTC).date() - timedelta(days=retention_days)
        )
        async with self._require_pool().acquire() as conn, conn.transaction():
            if not await conn.fetchval(
                "SELECT pg_try_advisory_xact_lock($1)", _ROLLUP_LOCK_KEY
            ):
                return False
            status = await conn.execute(_ROLLUP, cutoff)
        logger.info("usage_rollup_completed", status=status, cutoff=cutoff.isoformat())
        return True

    async def _rollup_loop(self) -> None:
        # Never dies on a failed pass: usage is best-effort and the next
        # interval retries.
        while True:
            try:
                await self.rollup_and_prune(self._retention_days)
            except Exception as exc:  # noqa: BLE001 -- retry next interval
                logger.warning("usage_rollup_failed", error=str(exc))
            await asyncio.sleep(self._rollup_interval_seconds)
