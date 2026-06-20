from __future__ import annotations

import sys
import uuid
from dataclasses import dataclass, field
from typing import TextIO

import structlog

logger = structlog.get_logger(__name__)

_audit_logger: AuditLogger | None = None


@dataclass
class AuditRecord:
    principal_sub: str
    principal_uid: int
    capability: str
    target: str
    action: str
    action_type: str  # "read" | "state_change"
    args_summary: str  # truncated, no secrets
    timestamp: float   # epoch seconds
    request_id: str
    audit_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    mcp_backend: str | None = None
    execution_model: str | None = None


class AuditLogger:
    """Append-only audit logger. Writes JSON lines via structlog."""

    def __init__(self, output: TextIO = sys.stdout) -> None:
        self._output = output

    async def write(self, record: AuditRecord) -> None:
        logger.info(
            "audit",
            audit_id=record.audit_id,
            principal_sub=record.principal_sub,
            principal_uid=record.principal_uid,
            capability=record.capability,
            target=record.target,
            action=record.action,
            action_type=record.action_type,
            args_summary=record.args_summary[:500],  # truncate to 500 chars
            timestamp=record.timestamp,
            request_id=record.request_id,
            mcp_backend=record.mcp_backend,
            execution_model=record.execution_model,
        )


def init_audit_logger(output: TextIO = sys.stdout) -> None:
    global _audit_logger
    _audit_logger = AuditLogger(output)


async def write_audit(record: AuditRecord) -> None:
    """Module-level helper. Falls back to a structlog warning if not initialized."""
    if _audit_logger is None:
        logger.warning(
            "audit_logger_not_initialized",
            audit_id=record.audit_id,
            target=record.target,
            action=record.action,
        )
        return
    await _audit_logger.write(record)
