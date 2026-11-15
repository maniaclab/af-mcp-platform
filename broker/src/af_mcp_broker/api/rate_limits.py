from __future__ import annotations

# GET /v1/rate-limits -- the configured policy.yaml ``rate_limits`` rules and
# the caller's own usage of each. Separate from GET /v1/entitlements on
# purpose: that table is static policy, identical for every caller; this
# response is per caller (it reads a live counter), and it has a failure mode
# of its own (the shared state store being unreachable).
from typing import TYPE_CHECKING, Annotated

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, ConfigDict

from af_mcp_broker.api.app_state import get_policy
from af_mcp_broker.authorization.rate_limit import (
    RateLimitStatus,
    rate_limit_statuses,
    read_rate_limit_usage,
)
from af_mcp_broker.identity import keycloak_dependency
from af_mcp_broker.principal import Principal

if TYPE_CHECKING:
    from af_mcp_broker.authorization import EntitlementPolicy
    from af_mcp_broker.shared_state import SharedState

router = APIRouter(tags=["permissions"])


class RateLimitsResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    rate_limits: list[RateLimitStatus]
    # False when the store could not be read: every rule is still listed, with
    # usage unknown.
    usage_available: bool


async def build_rate_limits_response(
    policy: EntitlementPolicy, shared_state: SharedState | None, subject: str
) -> RateLimitsResponse:
    usage = await read_rate_limit_usage(policy.rate_limits, shared_state, subject)
    return RateLimitsResponse(
        rate_limits=rate_limit_statuses(policy.rate_limits, usage),
        usage_available=usage is not None,
    )


@router.get(
    "/rate-limits",
    response_model=RateLimitsResponse,
    summary="List the configured tool rate limits and the caller's usage of each",
)
async def get_rate_limits(
    request: Request,
    principal: Annotated[Principal, Depends(keycloak_dependency)],
) -> RateLimitsResponse:
    # The subject comes from the authenticated principal, never a parameter,
    # so a caller can only ever read their own counters.
    return await build_rate_limits_response(
        get_policy(request),
        getattr(request.app.state, "shared_state", None),
        principal.subject,
    )
