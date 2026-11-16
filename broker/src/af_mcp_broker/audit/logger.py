from __future__ import annotations

import asyncio
import dataclasses
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

import structlog

from af_mcp_broker.logging import AUDIT_LOGGER_NAME

if TYPE_CHECKING:
    from af_mcp_broker.audit.measure import ContentMeasure


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
    # "success" | "denied" | "rate_limited" | "error" -- lets a single audit
    # line cover both a completed tool call and an authorization denial, a
    # rate-limit refusal (policy.yaml's rate_limits) or a downstream
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
    # result_bytes / result_tokens_est: totals over every content block of the
    # tool result -- the sums of result_content below (see audit/measure.py
    # for exactly what each content type contributes). Bytes are wire size;
    # tokens are an ESTIMATE of what the result costs the LLM client's context
    # and stay None when token estimation is disabled or unavailable.
    # Success path only.
    result_bytes: int | None = None
    result_tokens_est: int | None = None
    # The per-content-type breakdown behind those totals: MCP content type
    # (text, image, audio, resource, resource_link, ..., structured) ->
    # ContentMeasure. An open set, so a new content type needs no schema
    # change. None when nothing was measured; {} for a measured empty result.
    result_content: dict[str, ContentMeasure] | None = None
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
    # every non-x509 record, and for a proxy whose VOMS attributes carry no
    # nickname.
    nickname: str | None = None
    # Failure classification, observability only (issue #216 A.3): on an
    # outcome="error" record, "transient_connection" when the backend call
    # failed on a known-transient connection error (connection reset, socket
    # EOF / closed connection, connect timeout -- see backend_errors.py) vs
    # "backend_error" for a genuine tool-usage/backend failure. None on every
    # other outcome (success, and the denied/unmapped paths that never
    # executed a backend call). Nothing branches on it -- it exists to count
    # how often backends fail transiently before deciding whether the broker
    # should ever retry.
    error_class: str | None = None


async def write_audit(record: AuditRecord) -> None:
    """Emit *record* as one ``event: "audit"`` line through structlog.

    The line goes through the same processor chain as every other log line
    (ISO ``timestamp``, ``level``, ``logger``, and the request's
    ``correlation_id`` / ``subject`` contextvars), to the destination
    ``configure_logging`` gives the audit logger. The record's own epoch
    ``timestamp`` is emitted as ISO ``recorded_at`` -- the line's
    ``timestamp`` is when it was written, which for a queued record is later.

    A write failure propagates to the caller: an audit trail that silently
    loses lines is worse than a failed call.
    """
    payload = dataclasses.asdict(record)
    # Truncate the args summary defensively — it is caller-supplied.
    payload["args_summary"] = payload["args_summary"][:500]
    payload["recorded_at"] = datetime.fromtimestamp(
        payload.pop("timestamp"), tz=UTC
    ).isoformat()
    # The output can be a real file (or stdout redirected to one) whose
    # write/flush block — never do that on the event loop. to_thread copies
    # the current contextvars, so correlation_id/subject still merge in.
    await asyncio.to_thread(_emit, payload)


def _emit(payload: dict[str, Any]) -> None:
    # A fresh logger per call: structlog's cache_logger_on_first_use would
    # otherwise pin the logger to whatever configuration was active at the
    # first audit write.
    structlog.get_logger(AUDIT_LOGGER_NAME).info("audit", **payload)
