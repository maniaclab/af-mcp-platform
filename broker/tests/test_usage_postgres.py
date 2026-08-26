"""Tests for ``usage/postgres.py`` against a REAL ephemeral postgres.

No mocks (repo policy): the session fixture ``initdb``s a throwaway cluster
into a temp directory, starts it on a random loopback port with unix
sockets disabled, and tears it down afterwards -- deterministic, offline,
and exercising the actual SQL (DDL idempotency, ON CONFLICT semantics,
GROUP BY aggregation) instead of an asyncpg stand-in. The server binaries
come from the dev feature's ``postgresql`` dependency (pixi.toml).
"""

from __future__ import annotations

import shutil
import subprocess
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

import asyncpg  # type: ignore[import-untyped]
import pytest
from fastmcp.utilities.http import find_available_port

from af_mcp_broker.audit import AuditRecord
from af_mcp_broker.usage import PostgresUsageStore, UsageStore

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Iterator


def _record(**overrides: Any) -> AuditRecord:
    fields: dict[str, Any] = {
        "principal_sub": "sub-abc",
        "principal_uid": 1000,
        "permission": "read_data",
        "target": "rucio",
        "action": "rucio_list_dids",
        "action_type": "read",
        "args_summary": "scope=...",
        "timestamp": datetime.now(tz=UTC).timestamp(),
        "request_id": "req-1",
        "mcp_service": "rucio",
        "outcome": "success",
        "duration_ms": 10.0,
        "result_bytes": 100,
        "result_tokens_est": 25,
    }
    fields.update(overrides)
    return AuditRecord(**fields)


@pytest.fixture(scope="session")
def postgres_dsn(tmp_path_factory: pytest.TempPathFactory) -> Iterator[str]:
    """DSN of a real, throwaway postgres started for this test session.

    Loopback TCP on a random free port (unix sockets disabled entirely --
    their path-length limit is easy to trip under pytest temp dirs), trust
    auth (it only ever listens on 127.0.0.1 for the lifetime of one test
    run), fsync off for speed on a database we're about to delete.
    """
    for binary in ("initdb", "pg_ctl"):
        if shutil.which(binary) is None:
            raise RuntimeError(
                f"{binary} not found -- the dev pixi environment provides "
                "the postgresql server these tests require (pixi.toml's dev "
                "feature); run via `pixi run -e dev pytest`."
            )

    datadir = tmp_path_factory.mktemp("pg") / "data"
    subprocess.run(
        ["initdb", "-D", str(datadir), "-U", "postgres", "--auth=trust", "--no-sync"],
        check=True,
        capture_output=True,
    )
    port = find_available_port()
    subprocess.run(
        [
            "pg_ctl",
            "-D",
            str(datadir),
            "-l",
            str(datadir / "server.log"),
            "-w",
            "-o",
            f"-p {port} -c listen_addresses=127.0.0.1 "
            "-c unix_socket_directories='' -c fsync=off",
            "start",
        ],
        check=True,
        capture_output=True,
    )
    try:
        yield f"postgresql://postgres@127.0.0.1:{port}/postgres"
    finally:
        subprocess.run(
            ["pg_ctl", "-D", str(datadir), "-m", "immediate", "stop"],
            check=False,
            capture_output=True,
        )


@pytest.fixture
async def store(postgres_dsn: str) -> AsyncIterator[PostgresUsageStore]:
    """A started store on the session server, with a clean table per test."""
    s = PostgresUsageStore(postgres_dsn)
    await s.start()
    conn = await asyncpg.connect(postgres_dsn)
    try:
        await conn.execute("TRUNCATE af_mcp_usage_events")
    finally:
        await conn.close()
    yield s
    await s.aclose()


def test_postgres_store_satisfies_the_abc() -> None:
    assert issubclass(PostgresUsageStore, UsageStore)


async def test_start_ddl_is_idempotent(postgres_dsn: str) -> None:
    """start() runs CREATE TABLE/INDEX IF NOT EXISTS -- a second broker
    start (or a second replica) against the same database must not fail."""
    first = PostgresUsageStore(postgres_dsn)
    await first.start()
    await first.aclose()
    second = PostgresUsageStore(postgres_dsn)
    await second.start()  # must not raise
    await second.aclose()


async def test_record_and_query_round_trip(store: PostgresUsageStore) -> None:
    await store.record(_record())
    await store.record(
        _record(
            audit_id="different",
            duration_ms=5.0,
            result_bytes=50,
            result_tokens_est=5,
        )
    )

    (agg,) = await store.query("sub-abc", days=30)
    assert agg.service == "rucio"
    assert agg.tool == "rucio_list_dids"
    assert agg.outcome == "success"
    assert agg.day == datetime.now(tz=UTC).date()
    assert agg.calls == 2
    assert agg.duration_ms == pytest.approx(15.0)
    assert agg.result_bytes == 150
    assert agg.result_tokens_est == 30


async def test_same_audit_id_twice_inserts_one_row(
    store: PostgresUsageStore,
) -> None:
    """audit_id is the idempotency key: redelivery of the same record
    (best-effort metering may hand a record over more than once) is safe by
    construction via ON CONFLICT DO NOTHING."""
    record = _record()
    await store.record(record)
    await store.record(record)

    (agg,) = await store.query("sub-abc", days=30)
    assert agg.calls == 1


async def test_null_measurements_count_calls_but_contribute_zero_sums(
    store: PostgresUsageStore,
) -> None:
    await store.record(_record())
    await store.record(
        _record(
            audit_id="unmeasured",
            duration_ms=None,
            result_bytes=None,
            result_tokens_est=None,
        )
    )

    (agg,) = await store.query("sub-abc", days=30)
    assert agg.calls == 2
    assert agg.duration_ms == pytest.approx(10.0)
    assert agg.result_bytes == 100
    assert agg.result_tokens_est == 25


async def test_aggregates_split_by_day_service_tool_and_outcome(
    store: PostgresUsageStore,
) -> None:
    yesterday = (datetime.now(tz=UTC) - timedelta(days=1)).timestamp()
    await store.record(_record(audit_id="a1"))
    await store.record(_record(audit_id="a2", timestamp=yesterday))
    await store.record(
        _record(audit_id="a3", mcp_service="ami", action="ami_list_datasets")
    )
    await store.record(_record(audit_id="a4", outcome="error"))

    aggs = await store.query("sub-abc", days=30)
    keys = {(a.day, a.service, a.tool, a.outcome) for a in aggs}
    today = datetime.now(tz=UTC).date()
    assert keys == {
        (today, "rucio", "rucio_list_dids", "success"),
        (today - timedelta(days=1), "rucio", "rucio_list_dids", "success"),
        (today, "ami", "ami_list_datasets", "success"),
        (today, "rucio", "rucio_list_dids", "error"),
    }
    assert all(a.calls == 1 for a in aggs)


async def test_query_excludes_records_outside_the_trailing_window(
    store: PostgresUsageStore,
) -> None:
    old_ts = (datetime.now(tz=UTC) - timedelta(days=40)).timestamp()
    await store.record(_record(audit_id="old", timestamp=old_ts))
    await store.record(_record(audit_id="recent"))

    aggs = await store.query("sub-abc", days=30)
    assert sum(a.calls for a in aggs) == 1
    aggs_year = await store.query("sub-abc", days=365)
    assert sum(a.calls for a in aggs_year) == 2


async def test_query_is_scoped_to_the_subject(store: PostgresUsageStore) -> None:
    await store.record(_record(audit_id="mine"))
    await store.record(_record(audit_id="theirs", principal_sub="sub-other"))

    aggs = await store.query("sub-abc", days=30)
    assert sum(a.calls for a in aggs) == 1
