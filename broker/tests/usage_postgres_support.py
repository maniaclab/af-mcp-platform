"""Builders shared by the tests of ``test_usage_postgres``."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from af_mcp_broker.audit import AuditRecord
from af_mcp_broker.audit.measure import ContentMeasure


def _record(**overrides: Any) -> AuditRecord:
    fields: dict[str, Any] = {
        "subject": "sub-abc",
        "uid": 1000,
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
        "result_content": {"text": ContentMeasure(blocks=1, bytes=100, tokens_est=25)},
    }
    fields.update(overrides)
    return AuditRecord(**fields)
