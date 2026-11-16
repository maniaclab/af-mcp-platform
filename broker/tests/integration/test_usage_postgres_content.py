"""Per-content-type usage breakdown in postgres: schema migration, storage, fold.

Real ephemeral postgres (see ``conftest.postgres_dsn``), no mocks. Covers the
three deploy states the DDL must survive: a fresh database, a database created
by the earlier schema's DDL (with data to backfill), and a not-yet-updated
replica still inserting parent rows without children during a rolling deploy.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

import asyncpg  # type: ignore[import-untyped]
import pytest
from test_usage_postgres import _record

from af_mcp_broker.audit.measure import ContentMeasure
from af_mcp_broker.usage import PostgresUsageStore

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

_ALL_TABLES = (
    "af_mcp_usage_daily_content, af_mcp_usage_daily, "
    "af_mcp_usage_event_content, af_mcp_usage_events"
)

# The earlier schema's DDL, verbatim: what an already-deployed database has
# when start() runs against it.
PREVIOUS_RELEASE_DDL = """
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

# The earlier schema's insert: what a not-yet-updated replica keeps running
# during a rolling deploy.
PREVIOUS_RELEASE_INSERT = """
INSERT INTO af_mcp_usage_events (
    audit_id, request_id, principal_sub, service, method, action_type,
    outcome, ts, duration_ms, result_bytes, result_tokens_est,
    token_id, trace_id
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
ON CONFLICT (audit_id) DO NOTHING
"""

# A raw row written without children (unmeasured, or measured before the
# breakdown existed), against the current schema.
CHILDLESS_INSERT = PREVIOUS_RELEASE_INSERT.replace("principal_sub", "subject")

_IMAGE = {
    "text": ContentMeasure(blocks=1, bytes=29, tokens_est=14),
    "image": ContentMeasure(blocks=1, bytes=32_000, tokens_est=414),
}


async def _execute(dsn: str, sql: str, *args: Any) -> None:
    conn = await asyncpg.connect(dsn)
    try:
        await conn.execute(sql, *args)
    finally:
        await conn.close()


async def _fetch(dsn: str, sql: str, *args: Any) -> list[asyncpg.Record]:
    conn = await asyncpg.connect(dsn)
    try:
        return list(await conn.fetch(sql, *args))
    finally:
        await conn.close()


def _days_ago(days: int) -> float:
    return (datetime.now(tz=UTC) - timedelta(days=days)).timestamp()


@pytest.fixture
async def fresh_dsn(postgres_dsn: str) -> AsyncIterator[str]:
    """The session database with every usage table dropped."""
    await _execute(postgres_dsn, f"DROP TABLE IF EXISTS {_ALL_TABLES} CASCADE")
    yield postgres_dsn
    await _execute(postgres_dsn, f"DROP TABLE IF EXISTS {_ALL_TABLES} CASCADE")


async def _start(dsn: str) -> PostgresUsageStore:
    store = PostgresUsageStore(dsn)
    await store.start()
    return store


# --- storage -----------------------------------------------------------------


async def test_record_stores_one_child_row_per_content_type(fresh_dsn: str) -> None:
    store = await _start(fresh_dsn)
    await store.record(_record(audit_id="a1", result_content=_IMAGE))
    await store.aclose()

    rows = await _fetch(
        fresh_dsn,
        "SELECT content_type, blocks, bytes, tokens_est "
        "FROM af_mcp_usage_event_content WHERE audit_id = 'a1' ORDER BY 1",
    )
    assert [tuple(r) for r in rows] == [("image", 1, 32_000, 414), ("text", 1, 29, 14)]


async def test_record_many_writes_parents_and_children_together(
    fresh_dsn: str,
) -> None:
    store = await _start(fresh_dsn)
    await store.record_many(
        [
            _record(audit_id="a1", result_content=_IMAGE),
            _record(audit_id="a2", result_bytes=None, result_content=None),
        ]
    )
    await store.aclose()

    rows = await _fetch(
        fresh_dsn,
        "SELECT audit_id, count(*) FROM af_mcp_usage_event_content GROUP BY 1",
    )
    assert [tuple(r) for r in rows] == [("a1", 2)]
    (n,) = await _fetch(fresh_dsn, "SELECT count(*) FROM af_mcp_usage_events")
    assert n[0] == 2


async def test_redelivery_does_not_duplicate_or_fail_on_children(
    fresh_dsn: str,
) -> None:
    store = await _start(fresh_dsn)
    record = _record(audit_id="a1", result_content=_IMAGE)
    await store.record(record)
    await store.record(record)
    await store.record_many([record, record])
    await store.aclose()

    (n,) = await _fetch(fresh_dsn, "SELECT count(*) FROM af_mcp_usage_event_content")
    assert n[0] == 2


async def test_query_reports_the_breakdown_and_treats_childless_parents_as_unknown(
    fresh_dsn: str,
) -> None:
    store = await _start(fresh_dsn)
    await store.record(_record(audit_id="a1", result_content=_IMAGE))
    await store.record(_record(audit_id="a2", result_content=_IMAGE))
    # A parent with no children: a not-yet-updated replica's row.
    await _execute(
        fresh_dsn,
        CHILDLESS_INSERT,
        "old-replica", "req", "sub-abc", "rucio", "rucio_list_dids", "read",
        "success", datetime.now(tz=UTC), 1.0, 500, 100, None, None,
    )  # fmt: skip

    (agg,) = await store.query("sub-abc", days=30)
    await store.aclose()

    assert agg.calls == 3
    assert agg.result_bytes == 100 + 100 + 500  # parent totals include every row
    assert agg.content == {
        "text": ContentMeasure(blocks=2, bytes=58, tokens_est=28),
        "image": ContentMeasure(blocks=2, bytes=64_000, tokens_est=828),
    }


# --- migration ---------------------------------------------------------------


async def test_ddl_on_a_fresh_database_is_idempotent(fresh_dsn: str) -> None:
    for _ in range(2):
        await (await _start(fresh_dsn)).aclose()

    tables = {
        r[0]
        for r in await _fetch(
            fresh_dsn,
            "SELECT tablename FROM pg_tables WHERE tablename LIKE 'af_mcp_usage%'",
        )
    }
    assert {
        "af_mcp_usage_event_content",
        "af_mcp_usage_daily_content",
    } <= tables


async def _seed_previous_release(dsn: str) -> None:
    await _execute(dsn, PREVIOUS_RELEASE_DDL)
    when = datetime.now(tz=UTC)
    for audit_id, rbytes, rtokens in (
        ("measured", 24_070, 14),
        ("unmeasured", None, None),
        ("tokens-off", 40, None),
    ):
        await _execute(
            dsn,
            PREVIOUS_RELEASE_INSERT,
            audit_id, "req", "sub-abc", "jhub", "jhub_nb_execute_code", "state_change",
            "success", when, 1.0, rbytes, rtokens, None, None,
        )  # fmt: skip
    await _execute(
        dsn,
        "INSERT INTO af_mcp_usage_daily VALUES "
        "(current_date - 200, 'sub-abc', 'rucio', 'rucio_list_dids', 'success', "
        "4, 8.0, 400, 60)",
    )


async def test_ddl_backfills_a_previous_release_database_exactly_once(
    fresh_dsn: str,
) -> None:
    await _seed_previous_release(fresh_dsn)

    for _ in range(2):  # the second start must not backfill again
        await (await _start(fresh_dsn)).aclose()

    events = await _fetch(
        fresh_dsn,
        "SELECT audit_id, content_type, blocks, bytes, tokens_est "
        "FROM af_mcp_usage_event_content ORDER BY 1",
    )
    # An unmeasured row (NULL bytes) has no breakdown to backfill; NULL tokens
    # backfill as 0. blocks is the documented approximation of 1.
    assert [tuple(r) for r in events] == [
        ("measured", "text", 1, 24_070, 14),
        ("tokens-off", "text", 1, 40, 0),
    ]
    daily = await _fetch(
        fresh_dsn,
        "SELECT service, method, outcome, content_type, blocks, bytes, tokens_est "
        "FROM af_mcp_usage_daily_content",
    )
    assert [tuple(r) for r in daily] == [
        ("rucio", "rucio_list_dids", "success", "text", 4, 400, 60)
    ]


async def test_previous_release_replica_insert_fails_loudly_after_migration(
    fresh_dsn: str,
) -> None:
    """A replica that still writes ``principal_sub`` gets an error, not a silent drop.

    Its batch is logged as ``usage.record_batch_failed`` with the audit ids, and
    the audit log keeps the records, so the rows can be rebuilt.
    """
    store = await _start(fresh_dsn)
    with pytest.raises(asyncpg.UndefinedColumnError):
        await _execute(
            fresh_dsn,
            PREVIOUS_RELEASE_INSERT,
            "old-replica", "req", "sub-abc", "rucio", "rucio_list_dids", "read",
            "success", datetime.now(tz=UTC), 1.0, 500, 100, None, None,
        )  # fmt: skip
    await store.aclose()


async def test_ddl_renames_principal_sub_to_subject_in_every_table(
    fresh_dsn: str,
) -> None:
    # A deployed database: the content tables exist and the user column is
    # still `principal_sub` everywhere.
    await (await _start(fresh_dsn)).aclose()
    for table in (
        "af_mcp_usage_events",
        "af_mcp_usage_daily",
        "af_mcp_usage_daily_content",
    ):
        await _execute(
            fresh_dsn, f"ALTER TABLE {table} RENAME COLUMN subject TO principal_sub"
        )
    await _execute(
        fresh_dsn,
        PREVIOUS_RELEASE_INSERT,
        "raw-1", "req", "sub-abc", "jhub", "jhub_nb_execute_code", "state_change",
        "success", datetime.now(tz=UTC), 1.0, 10, 5, None, None,
    )  # fmt: skip
    await _execute(
        fresh_dsn,
        "INSERT INTO af_mcp_usage_daily VALUES "
        "(current_date - 200, 'sub-abc', 'rucio', 'rucio_list_dids', 'success', "
        "4, 8.0, 400, 60)",
    )
    await _execute(
        fresh_dsn,
        "INSERT INTO af_mcp_usage_daily_content VALUES "
        "(current_date - 200, 'sub-abc', 'rucio', 'rucio_list_dids', 'success', "
        "'text', 4, 400, 60)",
    )

    for _ in range(2):  # a second start is a no-op
        await (await _start(fresh_dsn)).aclose()

    columns = await _fetch(
        fresh_dsn,
        "SELECT table_name, column_name FROM information_schema.columns "
        "WHERE table_name IN ('af_mcp_usage_events', 'af_mcp_usage_daily', "
        "'af_mcp_usage_daily_content') AND column_name IN ('subject', 'principal_sub') "
        "ORDER BY 1, 2",
    )
    assert [tuple(r) for r in columns] == [
        ("af_mcp_usage_daily", "subject"),
        ("af_mcp_usage_daily_content", "subject"),
        ("af_mcp_usage_events", "subject"),
    ]
    store = await _start(fresh_dsn)
    try:
        aggregates = await store.query("sub-abc", days=365)
        subjects = await store.list_subjects(365)
    finally:
        await store.aclose()
    # Rows written before the rename (raw and rolled up) are read under the new name.
    assert {(a.service, a.calls) for a in aggregates} == {("jhub", 1), ("rucio", 4)}
    assert subjects == ["sub-abc"]


# --- fold --------------------------------------------------------------------


async def test_fold_moves_children_into_the_daily_content_rollup(
    fresh_dsn: str,
) -> None:
    store = await _start(fresh_dsn)
    await store.record_many(
        [
            _record(audit_id="o1", timestamp=_days_ago(100), result_content=_IMAGE),
            _record(audit_id="o2", timestamp=_days_ago(100), result_content=_IMAGE),
            _record(audit_id="new", result_content=_IMAGE),
        ]
    )

    assert await store.rollup_and_prune(retention_days=90) is True

    daily = await _fetch(
        fresh_dsn,
        "SELECT content_type, blocks, bytes, tokens_est "
        "FROM af_mcp_usage_daily_content ORDER BY 1",
    )
    assert [tuple(r) for r in daily] == [
        ("image", 2, 64_000, 828),
        ("text", 2, 58, 28),
    ]
    # The cascade removed the folded parents' children; the recent parent's stay.
    (n,) = await _fetch(fresh_dsn, "SELECT count(*) FROM af_mcp_usage_event_content")
    assert n[0] == 2
    # A window covering both answers the same as before the fold.
    aggs = await store.query("sub-abc", days=365)
    await store.aclose()
    assert sum(a.calls for a in aggs) == 3
    assert {
        t: sum(a.content[t].bytes for a in aggs if t in a.content) for t in _IMAGE
    } == {"text": 87, "image": 96_000}


async def test_fold_adds_to_an_existing_daily_content_row(fresh_dsn: str) -> None:
    store = await _start(fresh_dsn)
    await store.record(
        _record(audit_id="o1", timestamp=_days_ago(100), result_content=_IMAGE)
    )
    await store.rollup_and_prune(retention_days=90)
    await store.record(  # a late arrival for the already-rolled-up day
        _record(audit_id="o2", timestamp=_days_ago(100), result_content=_IMAGE)
    )
    await store.rollup_and_prune(retention_days=90)
    await store.aclose()

    (image,) = await _fetch(
        fresh_dsn,
        "SELECT blocks, bytes, tokens_est FROM af_mcp_usage_daily_content "
        "WHERE content_type = 'image'",
    )
    assert tuple(image) == (2, 64_000, 828)


async def test_fold_of_a_childless_parent_keeps_its_totals(fresh_dsn: str) -> None:
    store = await _start(fresh_dsn)
    await _execute(
        fresh_dsn,
        CHILDLESS_INSERT,
        "old-replica", "req", "sub-abc", "rucio", "rucio_list_dids", "read",
        "success", datetime.fromtimestamp(_days_ago(100), tz=UTC), 1.0, 500, 100, None, None,
    )  # fmt: skip

    await store.rollup_and_prune(retention_days=90)

    (daily,) = await _fetch(
        fresh_dsn,
        "SELECT calls, result_bytes, result_tokens_est FROM af_mcp_usage_daily",
    )
    assert tuple(daily) == (1, 500, 100)
    (n,) = await _fetch(fresh_dsn, "SELECT count(*) FROM af_mcp_usage_daily_content")
    assert n[0] == 0
    (agg,) = await store.query("sub-abc", days=365)
    await store.aclose()
    assert (agg.calls, agg.result_bytes, agg.content) == (1, 500, {})
