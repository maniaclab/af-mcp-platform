"""Fixtures and helpers shared by the unit and integration tests of ``test_metering_pipeline``."""

from __future__ import annotations

import json
import time
from typing import Any

import pytest

from af_mcp_broker.audit import AuditRecord
from af_mcp_broker.config import Settings
from af_mcp_broker.metering import (
    InProcessMeteringBackend,
)
from af_mcp_broker.usage import InMemoryUsageStore, UsageStore

# Pins the encoding name so ambient env vars can't change test behavior
# (mirrors test_measure.py).
_SETTINGS = Settings(token_estimate_encoding="o200k_base")


def _backend(
    settings: Settings = _SETTINGS,
    usage_store: UsageStore | None = None,
    **kwargs: Any,
) -> InProcessMeteringBackend:
    """An (unstarted) in-process backend feeding *usage_store*, a fresh in-memory one when omitted."""
    return InProcessMeteringBackend(
        settings, usage_store or InMemoryUsageStore(), **kwargs
    )


def _record(**overrides: Any) -> AuditRecord:
    fields: dict[str, Any] = {
        "subject": "sub-abc",
        "uid": 1000,
        "permission": "read_data",
        "target": "rucio",
        "action": "rucio_list_dids",
        "action_type": "read",
        "args_summary": "scope=...",
        "timestamp": 1234.5,
        "request_id": "req-1",
        "outcome": "success",
        "duration_ms": 12.5,
    }
    fields.update(overrides)
    return AuditRecord(**fields)


def _lines(audit_buffer) -> list[dict[str, Any]]:
    return [json.loads(line) for line in audit_buffer.getvalue().splitlines()]


# ---------------------------------------------------------------------------
# Usage store feed (PR C) -- after each audit write the record is accounted
# in the installed UsageStore (tool-call records with outcome success/error
# only). Best-effort: a store failure never affects the audit write, which
# always happens FIRST.
# ---------------------------------------------------------------------------


@pytest.fixture(name="usage_store")
def usage_store_fixture() -> InMemoryUsageStore:
    return InMemoryUsageStore()


# ---------------------------------------------------------------------------
# Usage batching -- the worker buffers usage records and writes them with one
# UsageStore.record_many per batch: at USAGE_BATCH_MAX records, after
# USAGE_BATCH_INTERVAL_MS, or on aclose. The audit line is still written first
# and per record; only the usage write is batched. The inline paths (overflow,
# no pipeline running) are unbatched and covered above.
# ---------------------------------------------------------------------------

_NEVER_MS = 3_600_000  # an interval that cannot fire during a test


def _usage_record(**overrides: Any) -> AuditRecord:
    return _record(mcp_service="rucio", timestamp=time.time(), **overrides)
