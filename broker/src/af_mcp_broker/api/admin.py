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
from typing import Annotated

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field

from af_mcp_broker import metrics
from af_mcp_broker.identity import Principal, require_admin
from af_mcp_broker.maintenance import (
    MaintenanceModeStore,
    MaintenanceState,
    MaintenanceStateConflict,
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
    return MaintenanceStatusResponse(
        enabled=state.enabled,
        reason=state.reason,
        enabled_by=state.enabled_by,
        enabled_at=state.enabled_at,
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
        except MaintenanceStateConflict as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "Another admin changed maintenance mode at the same "
                    "time. Re-check GET /v1/admin/maintenance and retry."
                ),
            ) from exc
    return MaintenanceStatusResponse(
        enabled=state.enabled,
        reason=state.reason,
        enabled_by=state.enabled_by,
        enabled_at=state.enabled_at,
    )
