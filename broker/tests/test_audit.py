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
