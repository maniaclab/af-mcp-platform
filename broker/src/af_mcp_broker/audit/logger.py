from __future__ import annotations

import asyncio
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
    # Per-token attribution (issue #247): the calling PAT's public,
    # non-secret lookup_id, null for a session JWT (not a distinct
    # long-lived credential). ``principal_sub`` identifies the user across
    # all their tokens; this identifies the specific token, so a leaked
    # PAT's calls can be isolated -- and that one token revoked -- without
    # guessing among the owner's other tokens. NEVER secret material or the
    # full token.
    token_id: str | None = None
    # Per-call metering (observability roadmap PR B). All three are None,
    # not 0, when nothing was measured -- a denied or unmapped call never
    # executed anything, so it has no duration and no result.
    #
    # duration_ms: wall time of the downstream call (credential resolution
    # plus the backend tool call), recorded on the success and error paths.
    duration_ms: float | None = None
    # result_bytes / result_tokens_est: size of the tool result's serialized
    # text content -- an estimate of what the call injects into the LLM
    # client's context, not wire size. Success path only; tokens are a
    # tiktoken ESTIMATE (see audit/measure.py) and stay None when estimation
    # is disabled or unavailable.
    result_bytes: int | None = None
    result_tokens_est: int | None = None
    # The trace <-> audit <-> usage join key (observability roadmap PR D):
    # 32-hex-lowercase OTel trace id of the tool-call span that was current
    # when the middleware built this record, or None when there was no
    # recording span (tracing disabled, or the trace was sampled out). Spans
    # carry identity/outcome/timing; measurements (the fields above) live
    # only here and are joined back to a trace via this id -- they are
    # filled in by the metering worker AFTER the response returns, so they
    # can never be span attributes. Captured at record construction
    # (tracing.current_trace_id()), which is why the later background write
    # doesn't lose it.
    trace_id: str | None = None
    # The resolved VOMS nickname -- the CERN/Rucio account the x509 proxy
    # authenticates as -- on x509 proxy-release records (issue #199). Distinct
    # from principal_sub/principal_uid, which identify the AF principal, not
    # the grid identity the credential is actually usable as; an operator
    # grepping the audit trail during an incident (nickname-resolution bug,
    # VOMS AC parsing regression, a user who changed their Globus identity)
    # needs to query which account a released proxy was good for. Null for
    # every non-x509 record, and for the legacy redeem path whose ProxyMeta
    # cache carries no nickname.
    nickname: str | None = None


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
        # The output can be a real file (or stdout redirected to one) whose
        # write/flush block — never do that on the event loop.
        await asyncio.to_thread(self._write_line, line)

    def _write_line(self, line: str) -> None:
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
