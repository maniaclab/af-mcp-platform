"""Postgres-backed ``UsageStore`` (asyncpg) -- the durable usage backend.

One raw event row per tool-call audit record, keyed by ``audit_id``:
inserting with ``ON CONFLICT (audit_id) DO NOTHING`` makes recording
idempotent, so redelivery of the same record (best-effort metering may hand
one over more than once) is safe by construction. Aggregation happens in
SQL at query time (``GROUP BY day, service, method, outcome``), keeping the
stored data raw enough to re-slice later without a schema change.

Each event row also has one child row per MCP content type in
``af_mcp_usage_event_content`` (``audit_id, content_type, blocks, bytes,
tokens_est``), written in the same transaction. ``content_type`` is an open
set (see ``audit/measure.py``), so a new content type is new rows, never a
schema change; the parent's ``result_bytes`` / ``result_tokens_est`` are the
totals over its children. A parent with no children (unmeasured, or written by
a replica that predates the breakdown) means "breakdown unknown", never an
error.

Raw rows are bounded by retention: ``rollup_and_prune`` folds rows older than
the window into the ``af_mcp_usage_daily`` rollup (keyed ``(day,
subject, service, method, outcome)``, the shape every read uses) and
deletes them in one statement; their child rows are folded into
``af_mcp_usage_daily_content`` (keyed like the daily rollup plus
``content_type``) in that same statement, before the delete cascades them away.
Reads sum raw rows and rollup rows, so a window answers identically before and
after a row moves.

The DSN is ``settings.usage_postgres_dsn`` -- with Crunchy PGO, typically
the ``uri`` key of the operator-generated ``<cluster>-pguser-<user>``
secret.
"""

from __future__ import annotations

import asyncio
import contextlib
from datetime import UTC, date, datetime, time, timedelta
from typing import TYPE_CHECKING, Any

import asyncpg
import structlog

from af_mcp_broker.audit.measure import ContentMeasure
from af_mcp_broker.constants import POOL_MAX_SIZE, POOL_MIN_SIZE
from af_mcp_broker.usage.store import (
    SubjectActivity,
    UsageAggregate,
    UsageStore,
    window_start,
)

if TYPE_CHECKING:
    from af_mcp_broker.audit.logger import AuditRecord

logger = structlog.get_logger(__name__)

# Idempotent DDL run by start(). Deliberate: a handful of tables, indexes and
# ADD COLUMN IF NOT EXISTS statements do not justify a migration framework
# yet -- IF NOT EXISTS makes every broker start (and every replica racing
# another) safe against a schema that already exists. Revisit if a
# non-idempotent change ever shows up.
#
# The DO block is one migration (Elwood vocabulary: the public
# name for what a service exposes is a *method*): tables created before the
# rename carry a `tool` column, and renaming it here -- guarded, so it is
# idempotent and a no-op on fresh or already-migrated tables -- lets deploys
# self-migrate with no manual step. During a rolling deploy, not-yet-updated
# replicas briefly fail their inserts against the renamed column; usage is
# best-effort by contract (audit records are authoritative), so that window
# loses nothing that matters.
#
# The content tables are the second migration (the per-content-type
# breakdown): created IF NOT EXISTS, then backfilled. The backfill gives every
# measured event row (result_bytes > 0) that has no child rows one `text`
# child, and every daily row without content rows one `text` content row.
# Rows recorded without a breakdown measured only text, so `text` is what those
# totals were; `blocks` is NOT NULL and the backfill cannot know the real
# block count, so it is an approximation (1 per event row, `calls` per daily
# row). NOT EXISTS makes the backfill run exactly once per row however many
# times (or from however many replicas) the DDL runs, and ON CONFLICT DO
# NOTHING makes two replicas backfilling concurrently safe. It also adopts
# childless rows a not-yet-updated replica inserts during a rolling deploy --
# correctly, since that replica measures text only. Parents with
# result_bytes NULL or 0 are left childless: there is nothing to attribute.
#
# The user column is `subject` everywhere (logs, audit records, usage rows);
# tables created before that carry `principal_sub`, renamed here in every
# table that has one, guarded like the `tool` rename. A replica still running
# the previous release writes `principal_sub`, so its inserts fail (and are
# logged as usage.record_batch_failed with their audit ids) until it is
# replaced.
_DDL = """
DO $$
DECLARE
    usage_table TEXT;
BEGIN
    FOREACH usage_table IN ARRAY ARRAY[
        'af_mcp_usage_events', 'af_mcp_usage_daily', 'af_mcp_usage_daily_content'
    ] LOOP
        IF EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_schema = current_schema()
              AND table_name = usage_table
              AND column_name = 'principal_sub'
        ) THEN
            EXECUTE format(
                'ALTER TABLE %I RENAME COLUMN principal_sub TO subject', usage_table
            );
        END IF;
    END LOOP;
END $$;
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
    subject TEXT NOT NULL,
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
    ON af_mcp_usage_events (subject, ts);
CREATE INDEX IF NOT EXISTS af_mcp_usage_events_ts
    ON af_mcp_usage_events (ts);
CREATE TABLE IF NOT EXISTS af_mcp_usage_daily (
    day DATE NOT NULL,
    subject TEXT NOT NULL,
    service TEXT NOT NULL,
    method TEXT NOT NULL,
    outcome TEXT NOT NULL,
    calls BIGINT NOT NULL,
    duration_ms DOUBLE PRECISION NOT NULL,
    result_bytes BIGINT NOT NULL,
    result_tokens_est BIGINT NOT NULL,
    PRIMARY KEY (day, subject, service, method, outcome)
);
CREATE INDEX IF NOT EXISTS af_mcp_usage_daily_principal_day
    ON af_mcp_usage_daily (subject, day);
CREATE TABLE IF NOT EXISTS af_mcp_usage_event_content (
    audit_id TEXT NOT NULL REFERENCES af_mcp_usage_events (audit_id) ON DELETE CASCADE,
    content_type TEXT NOT NULL,
    blocks BIGINT NOT NULL,
    bytes BIGINT NOT NULL,
    tokens_est BIGINT NOT NULL,
    PRIMARY KEY (audit_id, content_type)
);
CREATE TABLE IF NOT EXISTS af_mcp_usage_daily_content (
    day DATE NOT NULL,
    subject TEXT NOT NULL,
    service TEXT NOT NULL,
    method TEXT NOT NULL,
    outcome TEXT NOT NULL,
    content_type TEXT NOT NULL,
    blocks BIGINT NOT NULL,
    bytes BIGINT NOT NULL,
    tokens_est BIGINT NOT NULL,
    PRIMARY KEY (day, subject, service, method, outcome, content_type)
);
CREATE INDEX IF NOT EXISTS af_mcp_usage_daily_content_principal_day
    ON af_mcp_usage_daily_content (subject, day);
INSERT INTO af_mcp_usage_event_content (
    audit_id, content_type, blocks, bytes, tokens_est
)
SELECT e.audit_id, 'text', 1, e.result_bytes, coalesce(e.result_tokens_est, 0)
FROM af_mcp_usage_events e
WHERE e.result_bytes > 0
  AND NOT EXISTS (
      SELECT 1 FROM af_mcp_usage_event_content c WHERE c.audit_id = e.audit_id
  )
ON CONFLICT DO NOTHING;
INSERT INTO af_mcp_usage_daily_content (
    day, subject, service, method, outcome,
    content_type, blocks, bytes, tokens_est
)
SELECT d.day, d.subject, d.service, d.method, d.outcome,
       'text', d.calls, d.result_bytes, d.result_tokens_est
FROM af_mcp_usage_daily d
WHERE d.result_bytes > 0
  AND NOT EXISTS (
      SELECT 1 FROM af_mcp_usage_daily_content c
      WHERE c.day = d.day AND c.subject = d.subject
        AND c.service = d.service AND c.method = d.method
        AND c.outcome = d.outcome
  )
ON CONFLICT DO NOTHING;
"""

_INSERT = """
INSERT INTO af_mcp_usage_events (
    audit_id, request_id, subject, service, method, action_type,
    outcome, ts, duration_ms, result_bytes, result_tokens_est,
    token_id, trace_id
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
ON CONFLICT (audit_id) DO NOTHING
"""

_INSERT_CONTENT = """
INSERT INTO af_mcp_usage_event_content (
    audit_id, content_type, blocks, bytes, tokens_est
) VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (audit_id, content_type) DO NOTHING
"""

# Advisory lock key serializing the rollup job across replicas (see
# rollup_and_prune). Arbitrary but fixed: ASCII "afmcusg" + 1.
_ROLLUP_LOCK_KEY = 0x61666D6375736701

# The window bound is computed in Python (usage/store.py's window_start) and
# passed in, so both backends share one definition of "trailing N days". The
# raw-row predicate is a plain range on ``ts`` (bound = UTC midnight of the
# window's first day) so the ts / (subject, ts) indexes stay usable;
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
WHERE subject = $1 AND ts >= $2
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
    WHERE subject = $1 AND day >= $3
) AS merged
GROUP BY day, service, method, outcome
ORDER BY day, service, method, outcome
"""  # noqa: S608 -- interpolates only the module-level constant _RAW_QUERY; request values are bound parameters ($1..$3)

# The per-content-type counterpart of _QUERY. Only rows that have children
# appear; parents without children are "breakdown unknown" and contribute
# nothing here (their totals are in _QUERY).
_CONTENT_RAW_QUERY = """
SELECT (e.ts AT TIME ZONE 'UTC')::date AS day,
       e.service, e.method, e.outcome, c.content_type,
       sum(c.blocks)::bigint AS blocks,
       sum(c.bytes)::bigint AS bytes,
       sum(c.tokens_est)::bigint AS tokens_est
FROM af_mcp_usage_events e
JOIN af_mcp_usage_event_content c ON c.audit_id = e.audit_id
WHERE e.subject = $1 AND e.ts >= $2
GROUP BY day, e.service, e.method, e.outcome, c.content_type
"""

_CONTENT_QUERY = f"""
SELECT day, service, method, outcome, content_type,
       sum(blocks)::bigint AS blocks,
       sum(bytes)::bigint AS bytes,
       sum(tokens_est)::bigint AS tokens_est
FROM (
    {_CONTENT_RAW_QUERY}
    UNION ALL
    SELECT day, service, method, outcome, content_type, blocks, bytes, tokens_est
    FROM af_mcp_usage_daily_content
    WHERE subject = $1 AND day >= $3
) AS merged
GROUP BY day, service, method, outcome, content_type
"""  # noqa: S608 -- interpolates only the module-level constant _CONTENT_RAW_QUERY; request values are bound parameters ($1..$3)

# Latest call per subject: the raw rows' own timestamps plus each rolled-up
# day's midnight (a rolled-up row has no finer time than its day).
_RAW_SUBJECT_ACTIVITY_QUERY = """
SELECT subject, ts AS seen FROM af_mcp_usage_events WHERE ts >= $1
"""

_SUBJECT_ACTIVITY_QUERY = f"""
SELECT subject, max(seen) AS last_seen
FROM (
    {_RAW_SUBJECT_ACTIVITY_QUERY}
    UNION ALL
    SELECT subject, day::timestamp AT TIME ZONE 'UTC' AS seen
    FROM af_mcp_usage_daily WHERE day >= $2
) AS merged
GROUP BY subject
ORDER BY last_seen DESC
"""  # noqa: S608 -- interpolates only the module-level constant _RAW_SUBJECT_ACTIVITY_QUERY; request values are bound parameters ($1, $2)

# Folds every raw row older than $1 into the daily rollup and deletes it in
# ONE statement: the rows the DELETE returns are exactly the rows summed, so
# nothing is counted twice or lost even if a row is inserted concurrently.
# The CTE chain does the same for the child rows: they are summed into the
# daily content rollup in the very statement that deletes their parents.
# ON CONFLICT adds to an existing daily row (a late-arriving old row lands in
# a day that was already rolled up), which is correct because each raw row
# is summed exactly once, in the statement that deletes it.
_ROLLUP = """
WITH moved AS (
    DELETE FROM af_mcp_usage_events
    WHERE ts < $1
    RETURNING audit_id, subject, service, method, outcome, ts,
              duration_ms, result_bytes, result_tokens_est
),
folded_content AS (
    -- Reads the children from the statement's own snapshot, so they are
    -- still visible although the DELETE above cascades them away.
    INSERT INTO af_mcp_usage_daily_content AS dc (
        day, subject, service, method, outcome,
        content_type, blocks, bytes, tokens_est
    )
    SELECT (m.ts AT TIME ZONE 'UTC')::date, m.subject, m.service,
           m.method, m.outcome, c.content_type,
           sum(c.blocks)::bigint, sum(c.bytes)::bigint, sum(c.tokens_est)::bigint
    FROM moved m
    JOIN af_mcp_usage_event_content c ON c.audit_id = m.audit_id
    GROUP BY 1, 2, 3, 4, 5, 6
    ON CONFLICT (day, subject, service, method, outcome, content_type)
    DO UPDATE SET
        blocks = dc.blocks + EXCLUDED.blocks,
        bytes = dc.bytes + EXCLUDED.bytes,
        tokens_est = dc.tokens_est + EXCLUDED.tokens_est
)
INSERT INTO af_mcp_usage_daily AS d (
    day, subject, service, method, outcome,
    calls, duration_ms, result_bytes, result_tokens_est
)
SELECT (ts AT TIME ZONE 'UTC')::date, subject, service, method, outcome,
       count(*),
       coalesce(sum(duration_ms), 0),
       coalesce(sum(result_bytes), 0),
       coalesce(sum(result_tokens_est), 0)
FROM moved
GROUP BY 1, 2, 3, 4, 5
ON CONFLICT (day, subject, service, method, outcome) DO UPDATE SET
    calls = d.calls + EXCLUDED.calls,
    duration_ms = d.duration_ms + EXCLUDED.duration_ms,
    result_bytes = d.result_bytes + EXCLUDED.result_bytes,
    result_tokens_est = d.result_tokens_est + EXCLUDED.result_tokens_est
"""


def _utc_midnight(day: date) -> datetime:
    return datetime.combine(day, time.min, tzinfo=UTC)


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
            self._dsn, min_size=POOL_MIN_SIZE, max_size=POOL_MAX_SIZE
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
            record.subject,
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

    @staticmethod
    def _content_args(record: AuditRecord) -> list[tuple[Any, ...]]:
        return [
            (record.audit_id, content_type, m.blocks, m.bytes, m.tokens_est)
            for content_type, m in (record.result_content or {}).items()
        ]

    async def record(self, record: AuditRecord) -> None:
        if record.mcp_service is None:
            # Defensive: only tool-call records are usage (the pipeline-side
            # helper already filters these out before they get here).
            return
        # Parent and children in one transaction: a reader never sees a
        # measured parent without its breakdown.
        async with self._require_pool().acquire() as conn, conn.transaction():
            await conn.execute(_INSERT, *self._insert_args(record))
            content_args = self._content_args(record)
            if content_args:
                await conn.executemany(_INSERT_CONTENT, content_args)

    async def record_many(self, records: list[AuditRecord]) -> None:
        # executemany over one multi-row INSERT (per table): asyncpg prepares the
        # statement once and pipelines every argument tuple in a single
        # round trip, with no SQL to build and no 32767-bind-parameter
        # ceiling to size USAGE_BATCH_MAX against. ON CONFLICT DO NOTHING
        # also dedups a repeated audit_id inside the batch. The batch runs in
        # one explicit transaction, so it is all-or-nothing: one rejected row
        # rolls back its siblings, and the caller (usage.record_usage_batch)
        # counts every row of a failed batch as failed.
        usage = [record for record in records if record.mcp_service is not None]
        if not usage:
            return
        content_args = [args for record in usage for args in self._content_args(record)]
        async with self._require_pool().acquire() as conn, conn.transaction():
            await conn.executemany(_INSERT, [self._insert_args(r) for r in usage])
            if content_args:
                await conn.executemany(_INSERT_CONTENT, content_args)

    async def query(self, subject: str, days: int) -> list[UsageAggregate]:
        start = window_start(days)
        pool = self._require_pool()
        rows = await pool.fetch(_QUERY, subject, _utc_midnight(start), start)
        content_rows = await pool.fetch(
            _CONTENT_QUERY, subject, _utc_midnight(start), start
        )
        content: dict[tuple[date, str, str, str], dict[str, ContentMeasure]] = {}
        for row in content_rows:
            key = (row["day"], row["service"], row["method"], row["outcome"])
            content.setdefault(key, {})[row["content_type"]] = ContentMeasure(
                blocks=row["blocks"], bytes=row["bytes"], tokens_est=row["tokens_est"]
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
                content=content.get(
                    (row["day"], row["service"], row["method"], row["outcome"]), {}
                ),
            )
            for row in rows
        ]

    async def list_subject_activity(self, days: int) -> list[SubjectActivity]:
        start = window_start(days)
        rows = await self._require_pool().fetch(
            _SUBJECT_ACTIVITY_QUERY, _utc_midnight(start), start
        )
        return [
            SubjectActivity(subject=row["subject"], last_seen=row["last_seen"])
            for row in rows
        ]

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
        logger.info("usage.rollup_completed", status=status, cutoff=cutoff.isoformat())
        return True

    async def _rollup_loop(self) -> None:
        # Never dies on a failed pass: usage is best-effort and the next
        # interval retries.
        while True:
            try:
                await self.rollup_and_prune(self._retention_days)
            except Exception as exc:  # noqa: BLE001 -- retry next interval
                logger.warning("usage.rollup_failed", error=str(exc))
            await asyncio.sleep(self._rollup_interval_seconds)
