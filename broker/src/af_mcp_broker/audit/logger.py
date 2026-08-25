from __future__ import annotations

import dataclasses
import json
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
    # Optional (issue #148): POSIX identity is no longer required of every
    # principal, but audit records still carry it when present -- operators
    # want it, and `principal_sub` alone is a stable substitute when it's
    # absent, not a gap in the record.
    principal_uid: int | None
    permission: str | None
    target: str
    action: str
    action_type: str  # "read" | "state_change"
    args_summary: str  # truncated, no secrets
    timestamp: float  # epoch seconds
    request_id: str
    audit_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    mcp_service: str | None = None
    execution_model: str | None = None
    # "success" | "denied" | "error" -- lets a single audit line cover both a
    # completed tool call and an authorization denial or a downstream
    # failure, rather than only ever recording successes.
    outcome: str = "success"
    error: str | None = None
    # Sorted list of permission names, or None -- the calling PAT's
    # Principal.permission_grant, if it has one (issue #144 step 4). None
    # covers both "not a PAT" and "an identity PAT with no restriction",
    # which is deliberate: this field exists so an admin reading a *denied*
    # record can tell "the principal doesn't hold this permission at all"
    # (None here, denied anyway) apart from "the principal holds it, but
    # this particular PAT is scoped away from it" (named here, and absent
    # from the effective set that denied the call) -- see
    # authorization.get_principal_permissions for the intersection this
    # reflects.
    principal_permission_grant: list[str] | None = None


class AuditLogger:
    """Append-only audit logger. Writes one JSON line per record to *output*."""

    def __init__(self, output: TextIO = sys.stdout) -> None:
        self._output = output

    async def write(self, record: AuditRecord) -> None:
        payload = dataclasses.asdict(record)
        # Truncate the args summary defensively — it is caller-supplied.
        payload["args_summary"] = payload["args_summary"][:500]
        payload["event"] = "audit"
        line = json.dumps(payload, default=str)
        self._output.write(line + "\n")
        self._output.flush()


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
