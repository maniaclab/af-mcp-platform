"""Fixtures and helpers shared by the unit and integration tests of ``test_usage_otel_events``."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest
from opentelemetry.sdk._logs.export import (
    InMemoryLogRecordExporter,
)
from usage_postgres_support import _record

from af_mcp_broker.usage import (
    OtelUsageEventEmitter,
)

if TYPE_CHECKING:
    from collections.abc import Iterator

    from af_mcp_broker.audit.logger import AuditRecord


@pytest.fixture(name="exporter")
def exporter_fixture() -> InMemoryLogRecordExporter:
    return InMemoryLogRecordExporter()


@pytest.fixture(name="emitter")
def emitter_fixture(
    exporter: InMemoryLogRecordExporter,
) -> Iterator[OtelUsageEventEmitter]:
    e = OtelUsageEventEmitter(exporter)
    yield e
    e.shutdown()


def _full_record(**overrides: Any) -> AuditRecord:
    fields: dict[str, Any] = {
        "audit_id": "audit-1",
        "trace_id": "a" * 32,
        "subject": "alice-sub",
        "token_id": "tok-1",
        "args_summary": "scope=SECRET-ARGUMENT",
        "duration_ms": 12.5,
        "result_bytes": 321,
        "result_tokens_est": 80,
        # No breakdown: the base attribute set is asserted exactly; the
        # per-content-type attributes have their own test.
        "result_content": None,
    }
    fields.update(overrides)
    return _record(**fields)


def _logs(exporter: InMemoryLogRecordExporter) -> list[Any]:
    return [r.log_record for r in exporter.get_finished_logs()]
