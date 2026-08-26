"""Postgres-backed ``UsageStore`` (asyncpg) -- the durable usage backend.

One raw event row per tool-call audit record, keyed by ``audit_id``:
inserting with ``ON CONFLICT (audit_id) DO NOTHING`` makes recording
idempotent, so redelivery of the same record (best-effort metering may hand
one over more than once) is safe by construction. Aggregation happens in
SQL at query time (``GROUP BY day, service, tool, outcome``), keeping the
stored data raw enough to re-slice later without a schema change.

The DSN is ``settings.usage_postgres_dsn`` -- with Crunchy PGO, typically
the ``uri`` key of the operator-generated ``<cluster>-pguser-<user>``
secret.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

import asyncpg  # type: ignore[import-untyped]

from af_mcp_broker.usage.store import UsageAggregate, UsageStore, window_start

if TYPE_CHECKING:
    from af_mcp_broker.audit.logger import AuditRecord

# Idempotent DDL run by start(). Deliberate: one table plus one index does
# not justify a migration framework yet -- CREATE ... IF NOT EXISTS makes
# every broker start (and every replica racing another) safe against a
# schema that already exists. Revisit if a second table or an ALTER ever
# shows up.
_DDL = """
CREATE TABLE IF NOT EXISTS af_mcp_usage_events (
    audit_id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL,
    principal_sub TEXT NOT NULL,
    service TEXT NOT NULL,
    tool TEXT NOT NULL,
    action_type TEXT NOT NULL,
    outcome TEXT NOT NULL,
    ts TIMESTAMPTZ NOT NULL,
    duration_ms DOUBLE PRECISION,
    result_bytes BIGINT,
    result_tokens_est BIGINT
);
CREATE INDEX IF NOT EXISTS af_mcp_usage_events_principal_ts
    ON af_mcp_usage_events (principal_sub, ts);
"""

_INSERT = """
INSERT INTO af_mcp_usage_events (
    audit_id, request_id, principal_sub, service, tool, action_type,
    outcome, ts, duration_ms, result_bytes, result_tokens_est
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
ON CONFLICT (audit_id) DO NOTHING
"""

# The window bound is computed in Python (usage/store.py's window_start) and
# passed in, so both backends share one definition of "trailing N days".
_QUERY = """
SELECT (ts AT TIME ZONE 'UTC')::date AS day,
       service, tool, outcome,
       count(*)::bigint AS calls,
       coalesce(sum(duration_ms), 0)::double precision AS duration_ms,
       coalesce(sum(result_bytes), 0)::bigint AS result_bytes,
       coalesce(sum(result_tokens_est), 0)::bigint AS result_tokens_est
FROM af_mcp_usage_events
WHERE principal_sub = $1 AND (ts AT TIME ZONE 'UTC')::date >= $2
GROUP BY day, service, tool, outcome
ORDER BY day, service, tool, outcome
"""


class PostgresUsageStore(UsageStore):
    """asyncpg-pooled usage store over the ``af_mcp_usage_events`` table."""

    def __init__(self, dsn: str) -> None:
        self._dsn = dsn
        self._pool: asyncpg.Pool | None = None

    async def start(self) -> None:
        self._pool = await asyncpg.create_pool(self._dsn)
        async with self._pool.acquire() as conn:
            await conn.execute(_DDL)

    async def aclose(self) -> None:
        if self._pool is None:
            return
        await self._pool.close()
        self._pool = None

    def _require_pool(self) -> asyncpg.Pool:
        if self._pool is None:
            raise RuntimeError("PostgresUsageStore used before start()")
        return self._pool

    async def record(self, record: AuditRecord) -> None:
        if record.mcp_service is None:
            # Defensive: only tool-call records are usage (the pipeline-side
            # helper already filters these out before they get here).
            return
        await self._require_pool().execute(
            _INSERT,
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
        )

    async def query(self, subject: str, days: int) -> list[UsageAggregate]:
        rows = await self._require_pool().fetch(_QUERY, subject, window_start(days))
        return [
            UsageAggregate(
                day=row["day"],
                service=row["service"],
                tool=row["tool"],
                outcome=row["outcome"],
                calls=row["calls"],
                duration_ms=row["duration_ms"],
                result_bytes=row["result_bytes"],
                result_tokens_est=row["result_tokens_est"],
            )
            for row in rows
        ]
