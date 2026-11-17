"""GET /v1/admin/users -- admin search over the users the platform has seen.

Gated by ``require_admin``. The population is the users with recorded usage
(never the whole Keycloak realm) and matching is server-side, so the portal
never loads a user list: it sends what the admin typed and renders the few
rows that come back. The cost model (bounded Keycloak lookups, cached
profiles) is in ``user_search.py``.
"""

from __future__ import annotations

import asyncio
import time
from datetime import (
    datetime,  # noqa: TC003 -- pydantic resolves the response model annotations at runtime
)
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, ConfigDict

from af_mcp_broker.api.auth import require_admin
from af_mcp_broker.api.tokens import get_token_registry
from af_mcp_broker.broker_state import get_broker_state
from af_mcp_broker.principal import Principal

router = APIRouter(prefix="/admin/users", tags=["admin"])

# The longest trailing window usage is queryable over (see GET /v1/usage).
USER_SEARCH_WINDOW_DAYS = 365
DEFAULT_LIMIT = 20
MAX_LIMIT = 50


class AdminUser(BaseModel):
    model_config = ConfigDict(frozen=True)

    subject: str
    # The POSIX unix name when the user has one, else the directory username;
    # empty (with email and display_name) for a user the directory no longer knows.
    username: str
    email: str
    display_name: str
    last_seen: datetime
    # Tokens that are neither revoked nor expired.
    pat_count: int


class AdminUserSearchResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    users: list[AdminUser]
    # More users matched than ``limit``: refine the search.
    more: bool
    # Some seen users could not be checked against their directory profile
    # (lookup budget spent or directory failure), so a name or email match may
    # be missing; retrying warms the profile cache.
    partial: bool


@router.get(
    "",
    response_model=AdminUserSearchResponse,
    summary="Search users the platform has seen (admin)",
    description=(
        "Case-insensitive substring match over username, email, display name "
        "and subject, among the users with recorded usage, most recently "
        "seen first. An empty ``search`` lists the most recently seen users."
    ),
)
async def search_users(
    request: Request,
    _admin: Annotated[Principal, Depends(require_admin)],
    search: Annotated[str, Query(max_length=200)] = "",
    limit: Annotated[int, Query(ge=1, le=MAX_LIMIT)] = DEFAULT_LIMIT,
) -> AdminUserSearchResponse:
    state = get_broker_state(request)
    activity = await state.usage_store.list_subject_activity(USER_SEARCH_WINDOW_DAYS)
    result = await state.user_search.search(activity, search, limit=limit)

    # One registry read per returned row: at most ``limit`` rows.
    registry = get_token_registry(request)
    token_lists = await asyncio.gather(
        *(registry.list_for_principal(u.subject) for u in result.users)
    )
    now = time.time()
    return AdminUserSearchResponse(
        users=[
            AdminUser(
                subject=u.subject,
                username=u.username,
                email=u.email,
                display_name=u.display_name,
                last_seen=u.last_seen,
                pat_count=sum(1 for t in tokens if t.is_active(now)),
            )
            for u, tokens in zip(result.users, token_lists, strict=True)
        ],
        more=result.more,
        partial=result.partial,
    )
