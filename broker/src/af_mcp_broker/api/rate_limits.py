from __future__ import annotations

# GET /v1/rate-limits -- the configured policy.yaml ``rate_limits`` rules, the
# caller's own usage of each, and the caller's tools each rule covers.
# Separate from GET /v1/entitlements on purpose: that table is static policy,
# identical for every caller; this response is per caller (it reads a live
# counter and lists the caller's own tools), and it has failure modes of its
# own (the shared state store, or a backend, being unreachable).
import asyncio
from typing import TYPE_CHECKING, Annotated

import structlog
from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, ConfigDict

from af_mcp_broker.api.auth import keycloak_dependency
from af_mcp_broker.api.catalog_tools import list_service_tools
from af_mcp_broker.authorization.rate_limit import (
    RATE_LIMIT_MAX_TOOLS,
    RateLimitStatus,
    covered_tool_names,
    rate_limit_statuses,
    read_rate_limit_usage,
)
from af_mcp_broker.broker_state import get_broker_state
from af_mcp_broker.principal import Principal

if TYPE_CHECKING:
    from af_mcp_broker.broker_state import BrokerState

logger = structlog.get_logger(__name__)

router = APIRouter(tags=["permissions"])


class RateLimitRuleStatus(RateLimitStatus):
    """One configured rule, the caller's usage of it, and the caller's tools it covers."""

    # Wire names of the caller's tools the rule covers (see
    # RateLimitsResponse.unlisted_services for the services not searched),
    # sorted and capped at RATE_LIMIT_MAX_TOOLS; tool_count is the uncapped
    # number. Matched with the limiter's own RateLimitRule.matches.
    tools: list[str]
    tool_count: int


class RateLimitsResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    rate_limits: list[RateLimitRuleStatus]
    # False when the store could not be read: every rule is still listed, with
    # usage unknown.
    usage_available: bool
    # Services whose tools are missing from every rule's ``tools``: the caller
    # lacks the permission to see any of them, or the listing failed. Empty
    # when there are no rules, since no listing is made for them.
    unlisted_services: list[str]


async def _caller_tools(
    state: BrokerState, principal: Principal
) -> tuple[list[tuple[str, str]], list[str]]:
    """Return the caller's tools as ``(wire name, action type)`` pairs, and the names of services that could not be listed."""
    specs = state.service_registry.all_services()
    listings = await asyncio.gather(
        *(list_service_tools(state, principal, spec) for spec in specs),
        return_exceptions=True,
    )
    tools: list[tuple[str, str]] = []
    unlisted: list[str] = []
    for spec, listing in zip(specs, listings, strict=True):
        if isinstance(listing, BaseException):
            if not isinstance(listing, Exception):
                raise listing
            logger.warning(
                "rate_limits.service_tools_failed",
                subject=principal.subject,
                target=spec.name,
                error=repr(listing),
            )
            unlisted.append(spec.name)
        elif listing.status != "ok":
            unlisted.append(spec.name)
        else:
            tools.extend((tool.name, tool.action_type) for tool in listing.tools)
    return tools, unlisted


async def build_rate_limits_response(
    state: BrokerState, principal: Principal
) -> RateLimitsResponse:
    policy = state.entitlement_policy
    usage = await read_rate_limit_usage(
        policy.rate_limits, state.shared_state, principal.subject
    )
    statuses = rate_limit_statuses(policy.rate_limits, usage)
    # With no rules there is nothing to match, so no backend is contacted.
    # With at least one rule, every registered service is listed on every
    # request, concurrently (see _caller_tools). A service the caller lacks
    # the permission for costs no backend call. For the rest, a listing
    # served from the per-service tool-list cache (shared with
    # GET /v1/catalog/{service}/tools) skips the backend round trip; a cold
    # cache, or a service whose listing failed (failures are not cached),
    # costs one backend call, bounded by Settings.mcp_list_timeout_seconds,
    # so the slowest such service sets the response time.
    tools, unlisted = await _caller_tools(state, principal) if statuses else ([], [])
    rule_statuses: list[RateLimitRuleStatus] = []
    for rule, status in zip(policy.rate_limits, statuses, strict=True):
        covered = covered_tool_names(rule, tools)
        rule_statuses.append(
            RateLimitRuleStatus(
                **status.model_dump(),
                tools=covered[:RATE_LIMIT_MAX_TOOLS],
                tool_count=len(covered),
            )
        )
    return RateLimitsResponse(
        rate_limits=rule_statuses,
        usage_available=usage is not None,
        unlisted_services=unlisted,
    )


@router.get(
    "/rate-limits",
    response_model=RateLimitsResponse,
    summary="List the configured tool rate limits, the caller's usage of each, and the caller's tools each covers",
)
async def get_rate_limits(
    request: Request,
    principal: Annotated[Principal, Depends(keycloak_dependency)],
) -> RateLimitsResponse:
    # The subject comes from the authenticated principal, never a parameter,
    # so a caller can only ever read their own counters.
    return await build_rate_limits_response(get_broker_state(request), principal)
