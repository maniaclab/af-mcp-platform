from __future__ import annotations

# GET /v1/rate-limits -- the configured policy.yaml ``rate_limits`` rules and
# the caller's own usage of each. Separate from GET /v1/entitlements on
# purpose: that table is static policy, identical for every caller; this
# response is per caller (it reads a live counter), and it has a failure mode
# of its own (the shared state store being unreachable).
import math
from typing import TYPE_CHECKING, Annotated

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, ConfigDict

from af_mcp_broker.api.permissions import _get_policy
from af_mcp_broker.authorization.rate_limit import read_rate_limit_usage
from af_mcp_broker.identity import Principal, keycloak_dependency

if TYPE_CHECKING:
    from af_mcp_broker.authorization import EntitlementPolicy, RateLimitRule
    from af_mcp_broker.shared_state import SharedState, WindowCount

router = APIRouter(tags=["permissions"])


class RateLimitStatus(BaseModel):
    """One configured rule and the caller's usage of it.

    A rule's selector is *action_type* and/or *tool* (an fnmatch glob over the
    wire tool name); a call is covered when every selector the rule sets
    matches. *used* and *resets_in_seconds* are ``None`` when usage could not
    be read; with a readable store, *used* is 0 and *resets_in_seconds*
    ``None`` while the caller has no open window.
    """

    model_config = ConfigDict(frozen=True)

    action_type: str | None
    tool: str | None
    limit: int
    window_seconds: int
    # Calls counted in the open window, which includes calls the limiter
    # refused, so it can exceed *limit*.
    used: int | None
    # Whole seconds (rounded up, as ``Retry-After`` is) until the window
    # closes and the count starts over.
    resets_in_seconds: int | None


class RateLimitsResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    rate_limits: list[RateLimitStatus]
    # False when the store could not be read: every rule is still listed, with
    # usage unknown.
    usage_available: bool


def rate_limit_statuses(
    rules: list[RateLimitRule], usage: list[WindowCount | None] | None
) -> list[RateLimitStatus]:
    """Pair *rules* with *usage* as ``read_rate_limit_usage`` returns it (``None`` meaning usage unknown)."""
    windows = usage if usage is not None else [None] * len(rules)
    return [
        RateLimitStatus(
            action_type=rule.action_type,
            tool=rule.tool,
            limit=rule.limit,
            window_seconds=rule.window_seconds,
            used=None if usage is None else (window.count if window else 0),
            resets_in_seconds=math.ceil(window.ttl_seconds) if window else None,
        )
        for rule, window in zip(rules, windows, strict=True)
    ]


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
        _get_policy(request),
        getattr(request.app.state, "shared_state", None),
        principal.subject,
    )
