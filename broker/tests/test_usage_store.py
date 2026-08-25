"""Tests for ``usage/`` -- the per-user usage accounting store (PR C).

The store consumes the same ``AuditRecord``s the metering pipeline writes
(metering is best-effort; audit records are authoritative) and answers one
question: per-(day, service, tool, outcome) aggregates for one subject over
a trailing window. These tests cover the in-memory backend and the
module-level wiring (``init_usage_store``/``record_usage``); the postgres
backend has its own suite against a real ephemeral server in
``test_usage_postgres.py``.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from prometheus_client import REGISTRY

from af_mcp_broker.audit import AuditRecord
from af_mcp_broker.config import Settings
from af_mcp_broker.usage import (
    InMemoryUsageStore,
    UsageStore,
    aclose_usage_store,
    get_usage_store,
    init_usage_store,
    record_usage,
)


def _sample(name: str) -> float:
    return REGISTRY.get_sample_value(name) or 0.0


@pytest.fixture(autouse=True)
async def clean_usage_store():
    """Never leak an installed module-level store into other tests."""
    yield
    await aclose_usage_store()


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


# ---------------------------------------------------------------------------
# InMemoryUsageStore
# ---------------------------------------------------------------------------


def test_in_memory_store_satisfies_the_abc() -> None:
    assert issubclass(InMemoryUsageStore, UsageStore)
    assert isinstance(InMemoryUsageStore(), UsageStore)


async def test_record_and_query_round_trip() -> None:
    store = InMemoryUsageStore()
    await store.start()

    await store.record(_record())
    await store.record(_record(duration_ms=5.0, result_bytes=50, result_tokens_est=5))
    (agg,) = await store.query("sub-abc", days=30)

    assert agg.service == "rucio"
    assert agg.tool == "rucio_list_dids"
    assert agg.outcome == "success"
    assert agg.day == datetime.now(tz=UTC).date()
    assert agg.calls == 2
    assert agg.duration_ms == pytest.approx(15.0)
    assert agg.result_bytes == 150
    assert agg.result_tokens_est == 30
    await store.aclose()


async def test_unmeasured_records_count_calls_but_contribute_zero_sums() -> None:
    """A record whose duration/bytes/tokens are None (nothing was measured)
    still counts as a call -- the sums just don't grow."""
    store = InMemoryUsageStore()
    await store.record(_record())
    await store.record(
        _record(duration_ms=None, result_bytes=None, result_tokens_est=None)
    )

    (agg,) = await store.query("sub-abc", days=30)
    assert agg.calls == 2
    assert agg.duration_ms == pytest.approx(10.0)
    assert agg.result_bytes == 100
    assert agg.result_tokens_est == 25


async def test_aggregates_split_by_service_tool_and_outcome() -> None:
    store = InMemoryUsageStore()
    await store.record(_record())
    await store.record(_record(mcp_service="ami", action="ami_list_datasets"))
    await store.record(_record(outcome="error"))

    aggs = await store.query("sub-abc", days=30)
    keys = {(a.service, a.tool, a.outcome) for a in aggs}
    assert keys == {
        ("rucio", "rucio_list_dids", "success"),
        ("ami", "ami_list_datasets", "success"),
        ("rucio", "rucio_list_dids", "error"),
    }


async def test_query_is_scoped_to_the_subject() -> None:
    store = InMemoryUsageStore()
    await store.record(_record())
    await store.record(_record(principal_sub="sub-other"))

    aggs = await store.query("sub-abc", days=30)
    assert sum(a.calls for a in aggs) == 1


async def test_query_excludes_records_outside_the_trailing_window() -> None:
    """The window is *days* trailing UTC calendar days, today inclusive --
    a record 40 days old must not show up in a 30-day query but must in a
    365-day one."""
    store = InMemoryUsageStore()
    old_ts = (datetime.now(tz=UTC) - timedelta(days=40)).timestamp()
    await store.record(_record(timestamp=old_ts, request_id="old"))
    await store.record(_record(request_id="recent"))

    aggs = await store.query("sub-abc", days=30)
    assert sum(a.calls for a in aggs) == 1
    aggs_year = await store.query("sub-abc", days=365)
    assert sum(a.calls for a in aggs_year) == 2


# ---------------------------------------------------------------------------
# Module-level wiring -- mirrors audit/pipeline.py's init/aclose/helper shape.
# ---------------------------------------------------------------------------


async def test_init_builds_the_backend_selected_by_settings() -> None:
    store = await init_usage_store(Settings(usage_store_backend="in_memory"))
    assert isinstance(store, InMemoryUsageStore)
    assert get_usage_store() is store

    await aclose_usage_store()
    assert get_usage_store() is None


async def test_record_usage_is_a_noop_without_an_installed_store() -> None:
    # Must not raise -- unit tests and local dev run without init.
    await record_usage(_record())


async def test_record_usage_feeds_the_installed_store() -> None:
    store = await init_usage_store(Settings())
    await record_usage(_record())
    (agg,) = await store.query("sub-abc", days=30)
    assert agg.calls == 1


@pytest.mark.parametrize("outcome", ["denied", "unmapped"])
async def test_record_usage_skips_non_usage_outcomes(outcome: str) -> None:
    """Denied/unmapped calls are security events, not usage -- they live in
    the audit log only."""
    store = await init_usage_store(Settings())
    await record_usage(_record(outcome=outcome))
    assert await store.query("sub-abc", days=30) == []


async def test_record_usage_skips_records_without_an_mcp_service() -> None:
    """Only tool-call records (mcp_service set) are usage."""
    store = await init_usage_store(Settings())
    await record_usage(_record(mcp_service=None))
    assert await store.query("sub-abc", days=30) == []


async def test_record_usage_counts_error_outcomes() -> None:
    store = await init_usage_store(Settings())
    await record_usage(_record(outcome="error"))
    (agg,) = await store.query("sub-abc", days=30)
    assert agg.outcome == "error"


async def test_record_usage_swallows_store_failures_and_counts_them() -> None:
    """A failing store must never propagate into the audit write or the
    tool call -- the failure is logged and counted on the existing
    metering-worker error counter."""

    class _ExplodingStore(InMemoryUsageStore):
        async def record(self, record: AuditRecord) -> None:
            raise RuntimeError("usage store down")

    await init_usage_store(Settings())
    # Swap in the exploding store behind the module-level accessor.
    from af_mcp_broker import usage

    usage._store = _ExplodingStore()

    before = _sample("af_mcp_metering_worker_errors_total")
    await record_usage(_record())  # must not raise
    assert _sample("af_mcp_metering_worker_errors_total") == before + 1
