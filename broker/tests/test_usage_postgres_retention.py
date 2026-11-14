"""Usage-store retention, daily rollup, token/trace columns and query plans.

Real ephemeral postgres (see ``conftest.postgres_dsn``), no mocks: the
behaviour under test is SQL -- the migration, the DELETE-into-rollup CTE, the
advisory lock, and the planner's use of the ``ts`` indexes.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

import asyncpg  # type: ignore[import-untyped]
import pytest
from test_usage_postgres import _record

from af_mcp_broker.usage import PostgresUsageStore
from af_mcp_broker.usage import postgres as usage_postgres

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

_LOCK_KEY = usage_postgres._ROLLUP_LOCK_KEY


@pytest.fixture
async def store(postgres_dsn: str) -> AsyncIterator[PostgresUsageStore]:
    """A started store on the session server, with clean tables per test."""
    s = PostgresUsageStore(postgres_dsn)
    await s.start()
    await _truncate(postgres_dsn)
    yield s
    await s.aclose()


async def _truncate(dsn: str) -> None:
    conn = await asyncpg.connect(dsn)
    try:
        await conn.execute("TRUNCATE af_mcp_usage_events, af_mcp_usage_daily")
    finally:
        await conn.close()


def _days_ago(days: int) -> float:
    return (datetime.now(tz=UTC) - timedelta(days=days)).timestamp()


async def _count(dsn: str, table: str) -> int:
    conn = await asyncpg.connect(dsn)
    try:
        return int(await conn.fetchval(f"SELECT count(*) FROM {table}"))
    finally:
        await conn.close()


async def _seed_old_and_new(store: PostgresUsageStore) -> None:
    await store.record_many(
        [
            _record(audit_id="old-1", timestamp=_days_ago(100), duration_ms=1.0),
            _record(audit_id="old-2", timestamp=_days_ago(100), duration_ms=2.0),
            _record(
                audit_id="old-3",
                timestamp=_days_ago(100),
                outcome="error",
                result_bytes=None,
                result_tokens_est=None,
            ),
            _record(audit_id="old-4", timestamp=_days_ago(95), principal_sub="other"),
            _record(audit_id="new-1", timestamp=_days_ago(10)),
            _record(audit_id="new-2"),
        ]
    )


# --- token_id / trace_id columns -------------------------------------------


async def _token_trace_rows(dsn: str) -> list[tuple[str, str | None, str | None]]:
    conn = await asyncpg.connect(dsn)
    try:
        rows = await conn.fetch(
            "SELECT audit_id, token_id, trace_id FROM af_mcp_usage_events "
            "ORDER BY audit_id"
        )
    finally:
        await conn.close()
    return [(r["audit_id"], r["token_id"], r["trace_id"]) for r in rows]


async def test_record_persists_token_id_and_trace_id(
    store: PostgresUsageStore, postgres_dsn: str
) -> None:
    await store.record(_record(audit_id="one", token_id="tok-1", trace_id="t" * 32))
    await store.record_many([_record(audit_id="two", token_id="tok-2", trace_id=None)])

    assert await _token_trace_rows(postgres_dsn) == [
        ("one", "tok-1", "t" * 32),
        ("two", "tok-2", None),
    ]


async def test_start_adds_token_and_trace_columns_to_an_existing_table(
    postgres_dsn: str,
) -> None:
    """A table created before token_id/trace_id existed is altered in place by
    start(): old rows keep their data with NULLs in the new columns, the
    migration is idempotent, and new records populate the columns."""
    conn = await asyncpg.connect(postgres_dsn)
    try:
        await conn.execute("DROP TABLE IF EXISTS af_mcp_usage_events")
        await conn.execute(
            """
            CREATE TABLE af_mcp_usage_events (
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
            )
            """
        )
        await conn.execute(
            "INSERT INTO af_mcp_usage_events VALUES "
            "('pre-1', 'req', 'user-a', 'svc', 'm', 'read', "
            "'success', now(), 1.0, 10, 5)"
        )
    finally:
        await conn.close()

    first = PostgresUsageStore(postgres_dsn)
    await first.start()
    second = PostgresUsageStore(postgres_dsn)
    await second.start()  # idempotent
    try:
        await first.record(_record(audit_id="post-1", token_id="tok", trace_id="tr"))
        assert await _token_trace_rows(postgres_dsn) == [
            ("post-1", "tok", "tr"),
            ("pre-1", None, None),
        ]
    finally:
        await first.aclose()
        await second.aclose()


# --- retention and daily rollup --------------------------------------------


async def test_rollup_moves_old_rows_into_daily_aggregates(
    store: PostgresUsageStore, postgres_dsn: str
) -> None:
    await _seed_old_and_new(store)

    assert await store.rollup_and_prune(retention_days=90) is True

    # Raw rows older than the window are gone; newer ones stay.
    assert await _count(postgres_dsn, "af_mcp_usage_events") == 2
    conn = await asyncpg.connect(postgres_dsn)
    try:
        rows = await conn.fetch(
            "SELECT principal_sub, outcome, calls, duration_ms, result_bytes, "
            "result_tokens_est FROM af_mcp_usage_daily "
            "ORDER BY principal_sub, outcome"
        )
    finally:
        await conn.close()
    assert [tuple(r.values()) for r in rows] == [
        ("other", "success", 1, 10.0, 100, 25),
        ("sub-abc", "error", 1, 10.0, 0, 0),
        ("sub-abc", "success", 2, 3.0, 200, 50),
    ]


async def test_rollup_with_retention_disabled_keeps_every_raw_row(
    store: PostgresUsageStore, postgres_dsn: str
) -> None:
    await _seed_old_and_new(store)

    assert await store.rollup_and_prune(retention_days=0) is False

    assert await _count(postgres_dsn, "af_mcp_usage_events") == 6
    assert await _count(postgres_dsn, "af_mcp_usage_daily") == 0


async def test_query_is_identical_before_and_after_rollup(
    store: PostgresUsageStore,
) -> None:
    await _seed_old_and_new(store)
    before = await store.query("sub-abc", days=365)
    assert await store.list_subjects(days=365) == ["other", "sub-abc"]

    await store.rollup_and_prune(retention_days=90)

    assert await store.query("sub-abc", days=365) == before
    assert await store.list_subjects(days=365) == ["other", "sub-abc"]


async def test_query_merges_raw_and_rolled_up_rows_of_the_same_key(
    store: PostgresUsageStore,
) -> None:
    """The same (day, service, method, outcome) key can be partly rolled up
    and partly raw (a late-arriving old row not yet pruned); the read merges
    both into one aggregate whose sums are exact, and a second rollup
    accumulates into the existing daily row instead of replacing it."""
    await store.record(_record(audit_id="a", timestamp=_days_ago(100)))
    await store.rollup_and_prune(retention_days=90)
    await store.record(_record(audit_id="b", timestamp=_days_ago(100)))

    (agg,) = await store.query("sub-abc", days=365)
    assert (agg.calls, agg.result_bytes) == (2, 200)

    await store.rollup_and_prune(retention_days=90)
    (agg,) = await store.query("sub-abc", days=365)
    assert (agg.calls, agg.result_bytes) == (2, 200)
    assert agg.duration_ms == pytest.approx(20.0)


async def test_query_window_excludes_rolled_up_days_outside_it(
    store: PostgresUsageStore,
) -> None:
    await _seed_old_and_new(store)
    await store.rollup_and_prune(retention_days=90)

    assert sum(a.calls for a in await store.query("sub-abc", days=30)) == 2
    assert await store.list_subjects(days=30) == ["sub-abc"]
    assert sum(a.calls for a in await store.query("sub-abc", days=365)) == 5


async def test_rollup_is_skipped_while_another_replica_holds_the_lock(
    store: PostgresUsageStore, postgres_dsn: str
) -> None:
    await _seed_old_and_new(store)
    holder = await asyncpg.connect(postgres_dsn)
    try:
        await holder.execute("SELECT pg_advisory_lock($1)", _LOCK_KEY)
        assert await store.rollup_and_prune(retention_days=90) is False
        assert await _count(postgres_dsn, "af_mcp_usage_events") == 6
        assert await _count(postgres_dsn, "af_mcp_usage_daily") == 0
        await holder.execute("SELECT pg_advisory_unlock($1)", _LOCK_KEY)
    finally:
        await holder.close()

    assert await store.rollup_and_prune(retention_days=90) is True


async def test_racing_replicas_roll_each_row_up_exactly_once(
    postgres_dsn: str,
) -> None:
    stores = [PostgresUsageStore(postgres_dsn) for _ in range(4)]
    for s in stores:
        await s.start()
    try:
        await _truncate(postgres_dsn)
        await stores[0].record_many(
            [_record(audit_id=f"old-{i}", timestamp=_days_ago(100)) for i in range(50)]
        )

        await asyncio.gather(*(s.rollup_and_prune(retention_days=90) for s in stores))

        assert await _count(postgres_dsn, "af_mcp_usage_events") == 0
        (agg,) = await stores[0].query("sub-abc", days=365)
        assert (agg.calls, agg.result_bytes) == (50, 5000)
    finally:
        for s in stores:
            await s.aclose()


async def test_background_job_prunes_on_its_interval(postgres_dsn: str) -> None:
    s = PostgresUsageStore(
        postgres_dsn, retention_days=90, rollup_interval_seconds=0.05
    )
    await s.start()
    try:
        await _truncate(postgres_dsn)
        await s.record(_record(audit_id="old", timestamp=_days_ago(100)))
        async with asyncio.timeout(10):
            while await _count(postgres_dsn, "af_mcp_usage_events"):
                await asyncio.sleep(0.05)
        (agg,) = await s.query("sub-abc", days=365)
        assert agg.calls == 1
    finally:
        await s.aclose()


async def test_background_job_is_off_without_retention(postgres_dsn: str) -> None:
    s = PostgresUsageStore(postgres_dsn)
    await s.start()
    try:
        assert s._rollup_task is None
    finally:
        await s.aclose()


# --- query plans -----------------------------------------------------------


@pytest.mark.parametrize(
    ("sql", "args"),
    [
        (usage_postgres._RAW_QUERY, ("sub-abc", datetime.now(tz=UTC))),
        (usage_postgres._RAW_SUBJECTS_QUERY, (datetime.now(tz=UTC),)),
    ],
    ids=["query", "list_subjects"],
)
async def test_raw_queries_can_use_the_ts_indexes(
    store: PostgresUsageStore, postgres_dsn: str, sql: str, args: tuple[Any, ...]
) -> None:
    """The window predicate must be a plain range on ``ts`` so an index is
    usable; wrapping ``ts`` in ``(ts AT TIME ZONE 'UTC')::date`` makes the
    indexes unusable even with seq scans disabled."""
    conn = await asyncpg.connect(postgres_dsn)
    try:
        await conn.execute("SET enable_seqscan = off")
        plan = "\n".join(r[0] for r in await conn.fetch("EXPLAIN " + sql, *args))
    finally:
        await conn.close()
    # The window bound must be an Index Cond (a Filter would mean the index
    # is only being scanned in full, which is as bad as a seq scan).
    index_conds = [line for line in plan.splitlines() if "Index Cond" in line]
    assert any("(ts >=" in line for line in index_conds), plan
