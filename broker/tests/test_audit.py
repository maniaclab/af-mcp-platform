from __future__ import annotations

import io
import json
import logging
import sys
import threading
from datetime import datetime

import pytest
import structlog

from af_mcp_broker.audit import AuditRecord, write_audit
from af_mcp_broker.audit.measure import ContentMeasure
from af_mcp_broker.logging import (
    AUDIT_LOGGER_NAME,
    AuditFileHandler,
    configure_logging,
)


def _record(**overrides: object) -> AuditRecord:
    fields: dict[str, object] = {
        "subject": "sub-abc",
        "principal_uid": 1000,
        "permission": "submit_jobs",
        "target": "panda",
        "action": "submit_task",
        "action_type": "state_change",
        "args_summary": "task=...",
        "timestamp": 1234.5,
        "request_id": "req-1",
    }
    fields.update(overrides)
    return AuditRecord(**fields)  # type: ignore[arg-type]


async def test_write_audit_emits_json_line(audit_buffer) -> None:

    record = AuditRecord(
        subject="sub-abc",
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

    out = audit_buffer.getvalue().strip()
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


async def test_write_audit_metering_fields_default_none(audit_buffer) -> None:
    """The per-call metering fields (duration_ms, result_bytes,
    result_tokens_est) must default to None so pre-existing call sites (and
    denied/unmapped paths, where nothing executed) still serialize -- None,
    not 0, distinguishes "not measured" from "measured as zero"."""

    record = AuditRecord(
        subject="sub-abc",
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

    line = json.loads(audit_buffer.getvalue().strip())
    assert line["duration_ms"] is None
    assert line["result_bytes"] is None
    assert line["result_tokens_est"] is None


async def test_write_audit_metering_fields_serialize_when_set(audit_buffer) -> None:

    record = AuditRecord(
        subject="sub-abc",
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

    line = json.loads(audit_buffer.getvalue().strip())
    assert line["duration_ms"] == 123.456
    assert line["result_bytes"] == 2048
    assert line["result_tokens_est"] == 512


async def test_write_audit_token_id_defaults_none(audit_buffer) -> None:
    """token_id (issue #247) must default to None so every pre-existing call
    site -- and every session-JWT call, which has no distinct long-lived
    token to attribute -- still serializes, with an explicit null."""

    record = AuditRecord(
        subject="sub-abc",
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

    line = json.loads(audit_buffer.getvalue().strip())
    assert line["token_id"] is None


async def test_write_audit_token_id_serializes_when_set(audit_buffer) -> None:

    record = AuditRecord(
        subject="sub-abc",
        principal_uid=1000,
        permission="submit_jobs",
        target="panda",
        action="submit_task",
        action_type="state_change",
        args_summary="task=...",
        timestamp=1234.5,
        request_id="req-1",
        token_id="pat-lookup-1",
    )
    await write_audit(record)

    line = json.loads(audit_buffer.getvalue().strip())
    assert line["token_id"] == "pat-lookup-1"


async def test_write_audit_nickname_defaults_none(audit_buffer) -> None:
    """nickname (issue #199) must default to None so every pre-existing call
    site -- and every non-x509 record, which has no grid identity to
    attribute -- still serializes, with an explicit null."""

    record = AuditRecord(
        subject="sub-abc",
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

    line = json.loads(audit_buffer.getvalue().strip())
    assert line["nickname"] is None


async def test_write_audit_nickname_serializes_when_set(audit_buffer) -> None:

    record = AuditRecord(
        subject="sub-abc",
        principal_uid=1000,
        permission=None,
        target="ami",
        action="x509_proxy_release",
        action_type="read",
        args_summary="proxy released to backend 'ami'",
        timestamp=1234.5,
        request_id="req-1",
        nickname="jdoe",
    )
    await write_audit(record)

    line = json.loads(audit_buffer.getvalue().strip())
    assert line["nickname"] == "jdoe"


async def test_write_audit_emits_off_the_event_loop_thread(audit_buffer) -> None:
    """write_audit must not block the event loop: the destination can be a
    real file (or stdout redirected to one) whose write/flush block, so the
    emit must run in a worker thread."""

    class _ThreadRecordingHandler(logging.Handler):
        def __init__(self) -> None:
            super().__init__()
            self.emit_threads: list[threading.Thread] = []

        def emit(self, record: logging.LogRecord) -> None:
            self.emit_threads.append(threading.current_thread())

    recorder = _ThreadRecordingHandler()
    logging.getLogger(AUDIT_LOGGER_NAME).addHandler(recorder)

    await write_audit(_record())

    # The line still lands (same JSON contract as every other test here) ...
    assert json.loads(audit_buffer.getvalue().strip())["event"] == "audit"
    # ... but no emit ever ran on the event loop's own thread.
    assert recorder.emit_threads
    loop_thread = threading.current_thread()
    assert all(t is not loop_thread for t in recorder.emit_threads)


async def test_write_audit_line_matches_the_shape_of_every_other_log_line(
    audit_buffer,
) -> None:
    """Audit lines go through structlog's processor chain: ISO timestamp,
    level, logger name, and the request's context (here the caller's
    ``client_request_id``)."""
    structlog.contextvars.clear_contextvars()
    structlog.contextvars.bind_contextvars(client_request_id="cli-123")

    await write_audit(_record(timestamp=1234.5))

    (line,) = audit_buffer.lines()
    assert line["event"] == "audit"
    assert line["level"] == "info"
    assert line["logger"] == AUDIT_LOGGER_NAME
    assert line["client_request_id"] == "cli-123"
    assert line["request_id"] == "req-1"
    assert line["subject"] == "sub-abc"
    # `timestamp` is the write time as an ISO string, like every other line;
    # the record's own epoch time is `recorded_at`.
    assert isinstance(line["timestamp"], str)
    datetime.fromisoformat(line["timestamp"])
    assert line["recorded_at"] == "1970-01-01T00:20:34.500000+00:00"
    structlog.contextvars.clear_contextvars()


async def test_write_audit_raises_when_the_destination_cannot_be_written(
    audit_buffer,
) -> None:
    """An audit line that cannot be written is an error for the caller, not
    a message on stderr."""

    class _UnwritableStream(io.StringIO):
        def write(self, s: str) -> int:
            msg = "disk full"
            raise OSError(msg)

    (handler,) = [
        h
        for h in logging.getLogger(AUDIT_LOGGER_NAME).handlers
        if isinstance(h, AuditFileHandler)
    ]
    handler.stream = _UnwritableStream()

    with pytest.raises(OSError, match="disk full"):
        await write_audit(_record())


async def test_stdout_destination_resolves_sys_stdout_at_write_time(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    audit_buffer,
) -> None:
    """A stdout that was current when logging was configured and is closed
    since (a captured stream under pytest) cannot break later writes."""
    stale = io.StringIO()
    with monkeypatch.context() as m:
        m.setattr(sys, "stdout", stale)
        configure_logging("INFO")
    stale.close()

    await write_audit(_record())

    assert json.loads(capsys.readouterr().out)["event"] == "audit"


async def test_write_audit_records_denied_outcome_and_error(audit_buffer) -> None:

    record = AuditRecord(
        subject="sub-abc",
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

    line = json.loads(audit_buffer.getvalue().strip())
    assert line["outcome"] == "denied"
    assert line["error"] == "principal lacks permission 'submit_jobs'"


async def test_write_audit_carries_the_content_breakdown(audit_buffer) -> None:
    """The audit line is authoritative for usage: it carries the
    per-content-type breakdown, keyed by the real content-type string."""
    record = AuditRecord(
        subject="sub-abc",
        principal_uid=1000,
        permission="read_data",
        target="jhub",
        action="jhub_nb_execute_code",
        action_type="state_change",
        args_summary="",
        timestamp=1234.5,
        request_id="req-1",
        result_bytes=24_099,
        result_tokens_est=428,
        result_content={
            "text": ContentMeasure(blocks=1, bytes=29, tokens_est=14),
            "image": ContentMeasure(blocks=1, bytes=24_070, tokens_est=414),
        },
    )
    await write_audit(record)

    line = json.loads(audit_buffer.getvalue().strip())
    assert line["result_content"] == {
        "text": {"blocks": 1, "bytes": 29, "tokens_est": 14},
        "image": {"blocks": 1, "bytes": 24_070, "tokens_est": 414},
    }


async def test_write_audit_content_breakdown_defaults_none(audit_buffer) -> None:
    await write_audit(
        AuditRecord(
            subject="sub-abc",
            principal_uid=1000,
            permission="read_data",
            target="x",
            action="x_y",
            action_type="read",
            args_summary="",
            timestamp=1.0,
            request_id="r",
        )
    )

    assert json.loads(audit_buffer.getvalue().strip())["result_content"] is None
