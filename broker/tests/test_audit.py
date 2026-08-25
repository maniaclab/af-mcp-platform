from __future__ import annotations

import io
import json

from af_mcp_broker.audit import AuditRecord, write_audit
from af_mcp_broker.audit.logger import init_audit_logger


async def test_write_audit_emits_json_line() -> None:
    buffer = io.StringIO()
    init_audit_logger(buffer)

    record = AuditRecord(
        principal_sub="sub-abc",
        principal_uid=1000,
        permission="submit_jobs",
        target="panda",
        action="submit_task",
        action_type="state_change",
        args_summary="task=...",
        timestamp=1234.5,
        request_id="req-1",
    )
    await write_audit(record)

    out = buffer.getvalue().strip()
    assert out, "expected an audit line to be written to the configured output"
    line = json.loads(out)
    assert line["event"] == "audit"
    assert line["target"] == "panda"
    assert line["action_type"] == "state_change"
    assert line["principal_uid"] == 1000
    # outcome defaults to "success" so pre-existing call sites (that never
    # set it) still audit as a successful invocation.
    assert line["outcome"] == "success"
    assert line["error"] is None


async def test_write_audit_metering_fields_default_none() -> None:
    """The per-call metering fields (duration_ms, result_bytes,
    result_tokens_est) must default to None so pre-existing call sites (and
    denied/unmapped paths, where nothing executed) still serialize -- None,
    not 0, distinguishes "not measured" from "measured as zero"."""
    buffer = io.StringIO()
    init_audit_logger(buffer)

    record = AuditRecord(
        principal_sub="sub-abc",
        principal_uid=1000,
        permission="submit_jobs",
        target="panda",
        action="submit_task",
        action_type="state_change",
        args_summary="task=...",
        timestamp=1234.5,
        request_id="req-1",
    )
    await write_audit(record)

    line = json.loads(buffer.getvalue().strip())
    assert line["duration_ms"] is None
    assert line["result_bytes"] is None
    assert line["result_tokens_est"] is None


async def test_write_audit_metering_fields_serialize_when_set() -> None:
    buffer = io.StringIO()
    init_audit_logger(buffer)

    record = AuditRecord(
        principal_sub="sub-abc",
        principal_uid=1000,
        permission="submit_jobs",
        target="panda",
        action="submit_task",
        action_type="state_change",
        args_summary="task=...",
        timestamp=1234.5,
        request_id="req-1",
        duration_ms=123.456,
        result_bytes=2048,
        result_tokens_est=512,
    )
    await write_audit(record)

    line = json.loads(buffer.getvalue().strip())
    assert line["duration_ms"] == 123.456
    assert line["result_bytes"] == 2048
    assert line["result_tokens_est"] == 512


async def test_write_audit_records_denied_outcome_and_error() -> None:
    buffer = io.StringIO()
    init_audit_logger(buffer)

    record = AuditRecord(
        principal_sub="sub-abc",
        principal_uid=1000,
        permission="submit_jobs",
        target="panda",
        action="submit_task",
        action_type="state_change",
        args_summary="task=...",
        timestamp=1234.5,
        request_id="req-1",
        outcome="denied",
        error="principal lacks permission 'submit_jobs'",
    )
    await write_audit(record)

    line = json.loads(buffer.getvalue().strip())
    assert line["outcome"] == "denied"
    assert line["error"] == "principal lacks permission 'submit_jobs'"
