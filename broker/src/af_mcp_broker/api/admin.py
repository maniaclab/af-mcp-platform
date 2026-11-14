"""GET/POST /v1/admin/maintenance -- broker-wide maintenance mode.

GET carries no auth requirement at all (not even keycloak_dependency) so the
portal can show a maintenance banner to every visitor, including whoever is
currently blocked by it -- it must stay reachable precisely when everything
else is refusing traffic. POST requires admin-group membership
(require_admin); enabled_by/enabled_at are stamped server-side, never taken
from the request body, so an admin can't misattribute a toggle to someone
else.

Zero-auth exposure: whatever an admin puts in ``reason`` is broadcast, in
plain text, to the unauthenticated internet -- anyone who can reach the
broker at all, no credential of any kind, gets it back verbatim from GET.
This is a strictly larger audience than ``maintenance.check_not_maintenance``'s
own "treat state.reason like a public status-page message" warning
contemplates, since every one of *that* function's callers has already
presented a valid JWT/PAT. See ``SetMaintenanceRequest.reason``'s field
description, which is the copy an admin actually sees while filling out the
POST body -- unlike a docstring on a function three hops away, it can't be
missed.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Annotated, Literal

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field

from af_mcp_broker import metrics
from af_mcp_broker.api.permissions import _get_registry
from af_mcp_broker.identity import Principal, require_admin
from af_mcp_broker.maintenance import (
    MaintenanceModeStore,
    MaintenanceState,
    MaintenanceStateConflictError,
)
from af_mcp_broker.principal_cache import PrincipalUnavailableError

if TYPE_CHECKING:
    from af_mcp_broker.credmon.sync import CredmonSyncService
    from af_mcp_broker.mcp.lint_observations import (
        LintObservationStore,
        ServiceLintObservation,
    )

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/admin", tags=["admin"])

_DISABLED_DEFAULT = MaintenanceState(
    enabled=False, reason=None, enabled_by=None, enabled_at=None
)


class MaintenanceStatusResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    enabled: bool
    reason: str | None
    # An opaque Keycloak `sub` (not composed text), but still served to the
    # unauthenticated internet by GET -- same new exposure class as `reason`,
    # just lower severity since an admin never types this value directly.
    enabled_by: str | None
    enabled_at: float | None
    # Resolved from enabled_by via the principal cache -- same subject
    # you'd otherwise have to go look up yourself to know who actually
    # flipped the switch. None/"" (never omitted) when enabled_by is None
    # or the subject can't currently be resolved (e.g. a deleted user).
    enabled_by_unixname: str | None
    enabled_by_email: str


class SetMaintenanceRequest(BaseModel):
    enabled: bool
    reason: str | None = Field(
        default=None,
        description=(
            "Echoed back verbatim by GET /v1/admin/maintenance, which requires "
            "NO authentication at all -- this text is served to the "
            "unauthenticated internet, not merely to logged-in callers. Never "
            "put secrets or internal details in it."
        ),
    )


def _store(request: Request) -> MaintenanceModeStore | None:
    return getattr(request.app.state, "maintenance_mode_store", None)


async def _resolve_enabled_by(
    request: Request, enabled_by: str | None
) -> tuple[str | None, str]:
    """Resolve ``enabled_by`` (a bare Keycloak subject) to unixname/email for display.

    Mirrors ``get_usage_subjects``'s resolution shape exactly (same cache,
    same fallback) -- a `None` subject or an unresolvable one (e.g. a
    deleted Keycloak user) degrades to ``(None, "")`` rather than failing
    the request; the raw ``enabled_by`` subject is always shown regardless.
    """
    if enabled_by is None:
        return None, ""
    principal_cache = getattr(request.app.state, "principal_cache", None)
    if principal_cache is None:
        return None, ""
    try:
        attrs = await principal_cache.get(enabled_by)
    except PrincipalUnavailableError:
        return None, ""
    return attrs.unixname, attrs.email


@router.get(
    "/maintenance",
    response_model=MaintenanceStatusResponse,
    summary="Get the broker's maintenance-mode status (no auth required)",
    description=(
        "Reflects the current maintenance-mode record with no authentication "
        "requirement at all, so the portal can render a maintenance banner "
        "for every visitor -- including whoever is currently blocked by it "
        "on every other /v1 route. Fails open (reports disabled) rather than "
        "500ing if the backing store itself is unreachable, consistent with "
        "the rest of the maintenance-mode subsystem's fail-open behavior -- "
        "this route's whole point is to stay reachable when everything else "
        "is refusing traffic."
    ),
)
async def get_maintenance_status(request: Request) -> MaintenanceStatusResponse:
    store = _store(request)
    if store is None:
        state = _DISABLED_DEFAULT
    else:
        try:
            state = await store.get()
        except Exception as exc:
            # Same event name/shape as maintenance.check_not_maintenance_or_fail_open's
            # store-unavailability handling: ERROR level with a traceback, plus
            # the same counter, so an operator's dashboard doesn't need a
            # second signal for this route's store outages. Fails open (looks
            # disabled) rather than 500ing -- this route's entire reason to
            # exist is staying reachable precisely when everything else is
            # refusing traffic, so surfacing the outage as a 500 here would be
            # exactly backwards.
            logger.exception("maintenance_store_unavailable", error=str(exc))
            metrics.maintenance_store_unavailable_total.inc()
            state = _DISABLED_DEFAULT
    unixname, email = await _resolve_enabled_by(request, state.enabled_by)
    return MaintenanceStatusResponse(
        enabled=state.enabled,
        reason=state.reason,
        enabled_by=state.enabled_by,
        enabled_at=state.enabled_at,
        enabled_by_unixname=unixname,
        enabled_by_email=email,
    )


@router.post(
    "/maintenance",
    response_model=MaintenanceStatusResponse,
    summary="Toggle maintenance mode (admin only)",
    description=(
        "Requires membership in the configured admin group (403 otherwise). "
        "reason/enabled_by/enabled_at are all cleared to null when disabling "
        "-- enabled_by/enabled_at are stamped server-side from the caller's "
        "own principal and the current time, never taken from the request "
        "body, so an admin can't misattribute a toggle to someone else. On "
        "the Vault backend, a concurrent write from another admin can lose "
        "the compare-and-set race; that surfaces as 409 Conflict, and the "
        "caller should re-check GET /v1/admin/maintenance and retry."
    ),
)
async def set_maintenance_status(
    body: SetMaintenanceRequest,
    request: Request,
    principal: Annotated[Principal, Depends(require_admin)],
) -> MaintenanceStatusResponse:
    store = _store(request)
    state = MaintenanceState(
        enabled=body.enabled,
        # Cleared to None on disable, same as enabled_by/enabled_at just
        # below -- otherwise an admin's disable-time reason text would
        # persist forever, unauthenticated (GET requires no auth at all),
        # until the next POST happened to overwrite it.
        reason=body.reason if body.enabled else None,
        enabled_by=principal.subject if body.enabled else None,
        enabled_at=time.time() if body.enabled else None,
    )
    if store is not None:
        # The Vault backend's set() does a read-then-CAS-write with no retry
        # loop (see VaultMaintenanceModeStore.set()'s docstring) -- silently
        # retrying an admin's explicit lockdown/unlock decision behind their
        # back could commit them to a choice made with stale knowledge of the
        # current state. 409 is the standard HTTP semantic for "someone else
        # changed this concurrently, please retry" (there's no other
        # precedent for this in the codebase to match), so surface it as
        # such rather than letting it become an unhandled 500.
        try:
            await store.set(state)
        except MaintenanceStateConflictError as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "Another admin changed maintenance mode at the same "
                    "time. Re-check GET /v1/admin/maintenance and retry."
                ),
            ) from exc
    unixname, email = await _resolve_enabled_by(request, state.enabled_by)
    return MaintenanceStatusResponse(
        enabled=state.enabled,
        reason=state.reason,
        enabled_by=state.enabled_by,
        enabled_at=state.enabled_at,
        enabled_by_unixname=unixname,
        enabled_by_email=email,
    )


class AnnotationMismatchResponse(BaseModel):
    """One tool whose declared read_only_hint disagrees with policy.yaml's resolved action_type (issue #238 B.8).

    See mcp/registry.py's
    AnnotationMismatch, which this mirrors field-for-field.
    """

    model_config = ConfigDict(frozen=True)

    service: str
    tool: str
    declared_read_only_hint: bool
    resolved_action_type: str
    resolved_via: str
    permission: str


class LintServiceStatus(BaseModel):
    """When one service's tool listing was last linted, or None if no observation is on record."""

    model_config = ConfigDict(frozen=True)

    service: str
    # Epoch seconds. None means no observation is on record: either nobody has
    # listed the service within ``retention_seconds``, or the store lost it.
    last_observed: float | None


class AnnotationMismatchesResponse(BaseModel):
    """The annotation/policy mismatches on record, and which services that record covers."""

    model_config = ConfigDict(frozen=True)

    retention_seconds: float
    services: list[LintServiceStatus]
    mismatches: list[AnnotationMismatchResponse]


async def _lint_observations(request: Request) -> list[ServiceLintObservation | None]:
    """Each non-builtin service's last lint observation, in service-name order; None where there is none."""
    store: LintObservationStore = request.app.state.lint_observations
    names = sorted(
        s.name for s in _get_registry(request).all_services() if not s.builtin
    )
    return [await store.get(name) for name in names]


def _lint_service_statuses(
    request: Request, observations: list[ServiceLintObservation | None]
) -> list[LintServiceStatus]:
    names = sorted(
        s.name for s in _get_registry(request).all_services() if not s.builtin
    )
    return [
        LintServiceStatus(service=name, last_observed=obs.observed_at if obs else None)
        for name, obs in zip(names, observations, strict=True)
    ]


@router.get(
    "/annotation-mismatches",
    response_model=AnnotationMismatchesResponse,
    summary="List tools whose declared annotations disagree with policy.yaml (admin only)",
    description=(
        "Every tool whose declared read_only_hint annotation disagrees with "
        "policy.yaml's resolved action_type, as observed the last time a "
        "caller listed that service's tools through /mcp on any replica -- "
        "this is a read of EntitlementMiddleware's own lint (mcp/middleware/"
        "entitlement_mw.py), recorded in the shared state store, not a "
        "second, separately-probed comparison. Visibility only: policy.yaml "
        "stays authoritative for actual enforcement (issue #238 B.8's "
        "'forward + lint' decision) -- a mismatch here means the "
        "hand-maintained policy glob and the backend's own declaration "
        "disagree, not that either side is necessarily wrong. 'services' "
        "says when each service was last observed; a service with "
        "last_observed null has no observation on record (nobody has listed "
        "it within 'retention_seconds'), so an empty 'mismatches' says "
        "nothing about it."
    ),
)
async def get_annotation_mismatches(
    request: Request,
    _principal: Annotated[Principal, Depends(require_admin)],
) -> AnnotationMismatchesResponse:
    observations = await _lint_observations(request)
    store: LintObservationStore = request.app.state.lint_observations
    return AnnotationMismatchesResponse(
        retention_seconds=store.retention_seconds,
        services=_lint_service_statuses(request, observations),
        mismatches=[
            AnnotationMismatchResponse(
                service=m.service,
                tool=m.tool,
                declared_read_only_hint=m.declared_read_only_hint,
                resolved_action_type=m.resolved_action_type,
                resolved_via=m.resolved_via,
                permission=m.permission,
            )
            for obs in observations
            if obs is not None
            for m in sorted(obs.annotation_mismatches, key=lambda m: m.tool)
        ],
    )


class ToolMappingDriftResponse(BaseModel):
    """One service whose dict-form required_permission and advertised tools have drifted apart (issue #330).

    See mcp/registry.py's ToolMappingDrift, which this mirrors field-for-field.
    """

    model_config = ConfigDict(frozen=True)

    service: str
    prefix: str
    advertised: int
    routable: int
    unmapped: list[str]
    stale: list[str]
    unroutable: list[str]


class ToolMappingDriftReport(BaseModel):
    """The tool-mapping drift on record, and which services that record covers."""

    model_config = ConfigDict(frozen=True)

    retention_seconds: float
    services: list[LintServiceStatus]
    drift: list[ToolMappingDriftResponse]


@router.get(
    "/tool-mapping-drift",
    response_model=ToolMappingDriftReport,
    summary="List services whose tools and required_permission mapping have drifted (admin only)",
    description=(
        "Per service with a dict-form required_permission: 'unmapped' tools "
        "the backend advertises that have no entry and no __default__ (so "
        "they are implicitly disabled), and 'stale' keys the backend no "
        "longer advertises (typically a backend rename, which leaves every "
        "new tool unmapped). Per service of any form: 'unroutable' tools the "
        "backend advertises without the service's 'prefix' (an "
        "apply_namespace: false backend that renamed its tools), which no "
        "caller can reach; 'advertised'/'routable' count the listing with "
        "and without them. Names are wire (namespaced) tool names. Read "
        "from EntitlementMiddleware's own lint, as observed the last time a "
        "caller listed that service's tools through /mcp on any replica, "
        "recorded in the shared state store. 'services' says when each "
        "service was last observed; a service with last_observed null has no "
        "observation on record (nobody has listed it within "
        "'retention_seconds'), so an empty 'drift' says nothing about it. "
        "Visibility only."
    ),
)
async def get_tool_mapping_drift(
    request: Request,
    _principal: Annotated[Principal, Depends(require_admin)],
) -> ToolMappingDriftReport:
    observations = await _lint_observations(request)
    store: LintObservationStore = request.app.state.lint_observations
    return ToolMappingDriftReport(
        retention_seconds=store.retention_seconds,
        services=_lint_service_statuses(request, observations),
        drift=[
            ToolMappingDriftResponse(
                service=obs.tool_mapping_drift.service,
                prefix=obs.tool_mapping_drift.prefix,
                advertised=obs.tool_mapping_drift.advertised,
                routable=obs.tool_mapping_drift.routable,
                unmapped=list(obs.tool_mapping_drift.unmapped),
                stale=list(obs.tool_mapping_drift.stale),
                unroutable=list(obs.tool_mapping_drift.unroutable),
            )
            for obs in observations
            if obs is not None and obs.tool_mapping_drift is not None
        ],
    )


# ---------------------------------------------------------------------------
# HTCondor credmon sync (docs/credmon.md)
# ---------------------------------------------------------------------------


class CredmonRunResponse(BaseModel):
    """The last credmon sync cycle, as recorded by whichever replica held the cycle lease (credmon/sync.py)."""

    model_config = ConfigDict(frozen=True)

    outcome: Literal["success", "partial", "failed"]
    trigger: Literal["timer", "manual"]
    holder: str
    started_at: float
    finished_at: float
    # Last 'success' or 'partial' cycle -- None until the first one; a
    # 'failed' cycle never moves it forward.
    last_success_at: float | None
    stored: dict[str, int]
    not_linked: dict[str, int]
    skipped_no_posix: dict[str, int]
    failed: dict[str, int]
    errors: list[str]
    errors_truncated: int


class CredmonStatusResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    enabled: bool
    kinds: list[str]
    service_prefix: str
    interval_seconds: float | None
    last_run: CredmonRunResponse | None


def _credmon_sync(request: Request) -> CredmonSyncService | None:
    return getattr(request.app.state, "credmon_sync", None)


@router.get(
    "/credmon",
    response_model=CredmonStatusResponse,
    summary="HTCondor credmon sync status (admin only)",
    description=(
        "Whether the credmon integration is enabled and the last sync "
        "cycle's outcome: per-kind counts of top tokens stored in credd, "
        "users skipped (identity not linked, no POSIX unixname) and failed, "
        "plus the first errors. Every replica serves the same record -- only "
        "the replica holding the cycle lease writes it."
    ),
)
async def get_credmon_status(
    request: Request,
    _principal: Annotated[Principal, Depends(require_admin)],
) -> CredmonStatusResponse:
    settings = request.app.state.settings
    sync = _credmon_sync(request)
    if sync is None:
        return CredmonStatusResponse(
            enabled=False,
            kinds=[],
            service_prefix=settings.credmon_service_prefix,
            interval_seconds=None,
            last_run=None,
        )
    status_record = await sync.read_status()
    return CredmonStatusResponse(
        enabled=True,
        kinds=sync.kinds,
        service_prefix=settings.credmon_service_prefix,
        interval_seconds=sync.interval_seconds,
        last_run=CredmonRunResponse.model_validate(status_record)
        if status_record is not None
        else None,
    )


@router.post(
    "/credmon/sync",
    response_model=CredmonRunResponse,
    summary="Run an HTCondor credmon sync cycle now (admin only)",
    description=(
        "Runs one cycle immediately on the replica that receives the "
        "request, skipping the interval check. 409 when another replica "
        "holds the cycle lease (a cycle is already running)."
    ),
)
async def run_credmon_sync(
    request: Request,
    principal: Annotated[Principal, Depends(require_admin)],
) -> CredmonRunResponse:
    sync = _credmon_sync(request)
    if sync is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="The HTCondor credmon integration is not enabled (CREDMON_ENABLED).",
        )
    logger.info("credmon_sync.manual_trigger", triggered_by=principal.subject)
    result = await sync.run_now()
    if result is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A credmon sync cycle is already running on another replica -- retry shortly.",
        )
    return CredmonRunResponse.model_validate(result)
