"""GET /v1/usage -- self-service usage accounting.

Serves the calling user their own tool-call usage -- the subject comes from
the authenticated principal by default, never a parameter, unless the caller
is in ``settings.admin_group``, in which case ``?subject=`` overrides which
subject's usage is returned (see ``is_admin()``) -- aggregated by the
UsageStore (``usage/``).

Honesty caveats (also in the route's OpenAPI description): the token
numbers are an ESTIMATE of what each tool result would inject into an LLM
client's context (``TOKEN_ESTIMATE_CAVEAT``) -- not provider-reported
usage, and not the user's full token volume (their prompts, the model's own
output, and every non-tool token are invisible to the broker).

The response models and the whole assembly (store query and aggregation
shaping) live in ``usage/summary.py``, shared with the
``af_usage`` MCP tool; this route is a thin HTTP wrapper over it.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, ConfigDict

from af_mcp_broker.api.auth import keycloak_dependency, require_admin
from af_mcp_broker.authorization import is_admin
from af_mcp_broker.broker_state import get_broker_state
from af_mcp_broker.principal import Principal
from af_mcp_broker.principal_cache import PrincipalUnavailableError
from af_mcp_broker.usage.summary import (
    TOKEN_ESTIMATE_CAVEAT,
    UsageResponse,
    build_usage_summary,
)

router = APIRouter(prefix="/usage", tags=["usage"])


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get(
    "",
    response_model=UsageResponse,
    summary="Get the caller's own usage, or (admins) another subject's",
    description=(
        "Per-service, per-day and per-content-type aggregates of the caller's "
        "tool calls over a trailing window. "
        f"{TOKEN_ESTIMATE_CAVEAT} A caller "
        "in the configured admin group may pass ``subject`` to view another "
        "subject's usage instead of their own; anyone else passing it is "
        "rejected."
    ),
)
async def get_usage(
    request: Request,
    principal: Annotated[Principal, Depends(keycloak_dependency)],
    days: Annotated[int, Query(ge=1, le=365)] = 30,
    subject: Annotated[
        str | None,
        Query(
            description=(
                "View this subject's usage instead of the caller's own. "
                "Requires the caller to be in the configured admin group."
            )
        ),
    ] = None,
) -> UsageResponse:
    """Return the caller's own usage, or an admin's chosen subject's.

    Scoped strictly to ``principal.subject`` unless an admin passes
    ``subject=`` to view another user's usage (see ``is_admin()``).

    Token counts are ESTIMATES of tool-result context injection only (see
    the module docstring's honesty caveats).
    """
    settings = get_broker_state(request).settings

    # Authz check must run before `subject` is used for anything below --
    # do not reorder this past the effective_subject assignment, or a
    # non-admin's `subject=` would silently become a read oracle for other
    # users' usage instead of being rejected.
    if subject is not None and not is_admin(principal, settings):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This action requires membership in the admin group.",
        )
    effective_subject = subject if subject is not None else principal.subject

    store = get_broker_state(request).usage_store
    return await build_usage_summary(store, effective_subject, days)


class UsageSubject(BaseModel):
    model_config = ConfigDict(frozen=True)

    subject: str
    unixname: str | None
    email: str


class UsageSubjectsResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    subjects: list[UsageSubject]


@router.get(
    "/subjects",
    response_model=UsageSubjectsResponse,
    summary="List subjects with recorded usage (admin only)",
)
async def get_usage_subjects(
    request: Request,
    _principal: Annotated[Principal, Depends(require_admin)],
    days: Annotated[int, Query(ge=1, le=365)] = 30,
) -> UsageSubjectsResponse:
    """Admin-only: distinct subjects with usage in the trailing window, resolved to unixname/email for display.

    Backs the portal's admin usage-view dropdown. Only ever lists people
    with broker activity -- never a full Keycloak user directory.
    """
    state = get_broker_state(request)
    subjects = await state.usage_store.list_subjects(days)
    principal_cache = state.principal_cache

    resolved: list[UsageSubject] = []
    for subject in subjects:
        unixname: str | None = None
        email = ""
        if principal_cache is not None:
            try:
                attrs = await principal_cache.get(subject)
                unixname = attrs.unixname
                email = attrs.email
            except PrincipalUnavailableError:
                pass  # unresolvable subject (e.g. deleted user) -- fall back to bare subject
        resolved.append(UsageSubject(subject=subject, unixname=unixname, email=email))

    return UsageSubjectsResponse(subjects=resolved)
