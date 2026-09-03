from __future__ import annotations

# GET /v1/catalog/{service}/tools -- the portal's per-service tool listing
# (the fetch-on-expand companion to GET /v1/catalog). Lives in its own module
# rather than api/permissions.py because it imports mcp/aggregator.py's
# list-time helpers, and permissions.py importing the aggregator would be a
# straight import cycle (aggregator -> mcp/diagnostics -> permissions).
import time
from typing import TYPE_CHECKING, Annotated, Literal

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict

from af_mcp_broker.api.permissions import (
    _get_credential_registry,
    _get_policy,
    _get_registry,
    _holds_any_required_permission,
)
from af_mcp_broker.authorization import (
    DISABLED_PERMISSION,
    get_action_type,
    get_principal_permissions,
)
from af_mcp_broker.identity import Principal, keycloak_dependency
from af_mcp_broker.mcp.aggregator import (
    fetch_service_tool_listing,
    resolve_list_time_credential,
)

if TYPE_CHECKING:
    from af_mcp_broker.authorization import EntitlementPolicy
    from af_mcp_broker.mcp.registry import ServiceRegistry, ServiceSpec

logger = structlog.get_logger(__name__)

router = APIRouter(tags=["permissions"])

# The status vocabulary matches aggregator.py's _classify_failure one-to-one
# (plus "ok" and the locally-derived "permission_required"), so a portal
# status and an `aggregator.service_list_failed` log line for the same
# service always speak the same language. Sentences are short, human, and
# internals-free -- portal-facing, so unlike permissions.py's
# _STATUS_DETAILS they never name the af_* diagnostic tools.
ToolListingStatus = Literal[
    "ok",
    "not_linked",
    "unauthorized",
    "unavailable",
    "permission_required",
]

_STATUS_DETAILS: dict[str, str] = {
    "ok": "Methods listed.",
    "not_linked": "Link your identity to see this service's methods.",
    "unauthorized": "Your linked credential was rejected. Re-link your identity.",
    "unavailable": "Temporarily unavailable. Try again shortly.",
    "permission_required": (
        "Your account doesn't have the access this service requires. "
        "Contact the AF admins."
    ),
}


class ServiceTool(BaseModel):
    """One tool as a caller sees it through /mcp.

    Carries the (namespace-applied) name, the description, the same
    read/state_change action type real enforcement resolves, and the exact
    permission this tool requires (a dict-form required_permission can vary
    per tool -- see ServiceRegistry.required_permission_for) -- never the
    full input schema (the payload stays light; schemas belong to the MCP
    client, not the catalog).
    """

    model_config = ConfigDict(frozen=True)

    name: str
    description: str
    action_type: Literal["read", "state_change"]
    # "__none__" covers both the explicit opt-in and an omitted (credential-
    # layer-only) required_permission -- same convention as
    # CatalogServer.permission (api/permissions.py). Always a concrete value
    # here: a tool this caller can't hold a satisfying permission for
    # (denied, or DISABLED_PERMISSION) is never included in the response at
    # all -- see _respond's filtering.
    permission: str


class ServiceToolsResponse(BaseModel):
    """A service never vanishes from this endpoint for credential reasons.

    ``status``/``status_detail`` say why ``tools`` is empty instead (same
    issue #123 philosophy as GET /v1/catalog's per-server status).
    """

    model_config = ConfigDict(frozen=True)

    name: str
    display_name: str
    description: str
    status: ToolListingStatus
    status_detail: str
    tools: list[ServiceTool]


class ToolListingCache:
    """In-process TTL cache of successful tool listings, keyed by service.

    Tool schemas aren't user-specific (the same cross-user assumption
    fastmcp's ProxyProvider component cache already relies on -- see
    aggregator.py's _make_client_factory docstring; that cache itself can't
    be reused here because its client factories require an in-flight MCP
    request context), so one process-wide entry per service is safe. The TTL
    is the service's own ``tools_cache_ttl`` -- the same operator knob that
    governs the ProxyProvider cache, and 0 disables caching here too.
    Per-caller decisions (entitlement, linkage) are re-evaluated on every
    request; only the network fan-out is skipped. Each broker replica keeps
    its own copy -- acceptable divergence for a tool *catalog* (worst case a
    just-redeployed service's new tool appears on one replica up to one TTL
    before another), unlike per-caller status data which is never cached.
    """

    def __init__(self) -> None:
        # service name -> (monotonic fetch time, [(tool name, description)])
        self._entries: dict[str, tuple[float, list[tuple[str, str]]]] = {}

    def get(self, service: str, ttl: float) -> list[tuple[str, str]] | None:
        if ttl <= 0:
            return None
        entry = self._entries.get(service)
        if entry is None:
            return None
        fetched_at, tools = entry
        if time.monotonic() - fetched_at > ttl:
            return None
        return tools

    def put(self, service: str, tools: list[tuple[str, str]]) -> None:
        self._entries[service] = (time.monotonic(), tools)


def _get_cache(request: Request) -> ToolListingCache:
    # Lazily created on first use -- app.py's lifespan doesn't need to know
    # about it, and a fresh app (tests included) just starts cold.
    cache = getattr(request.app.state, "tool_listing_cache", None)
    if cache is None:
        cache = ToolListingCache()
        request.app.state.tool_listing_cache = cache
    return cache


def _respond(
    spec: ServiceSpec,
    status: str,
    tools: list[tuple[str, str]],
    policy: EntitlementPolicy,
    registry: ServiceRegistry,
    caps: set[str],
) -> ServiceToolsResponse:
    """Build the response, filtering *tools* to the ones *caps* actually satisfies.

    A dict-form required_permission can gate different tools of
    the same service differently (or disable one outright), so this mirrors
    EntitlementMiddleware's per-tool tools/list filtering rather than the
    single all-or-nothing gate get_service_tools applies before ever
    fetching *tools*.
    """
    visible: list[ServiceTool] = []
    for name, description in tools:
        permission = registry.required_permission_for(name, spec)
        if permission == DISABLED_PERMISSION:
            continue
        if (
            permission is not None
            and permission != "__none__"
            and permission not in caps
        ):
            continue  # a real permission this caller doesn't hold
        action_type = get_action_type(spec.name, name, permission, policy)
        visible.append(
            ServiceTool(
                name=name,
                description=description,
                action_type=action_type,  # type: ignore[arg-type]
                permission=permission if permission is not None else "__none__",
            )
        )
    return ServiceToolsResponse(
        name=spec.name,
        display_name=spec.display_name or spec.name,
        description=spec.description,
        status=status,  # type: ignore[arg-type]
        status_detail=_STATUS_DETAILS[status],
        tools=visible,
    )


@router.get(
    "/catalog/{service}/tools",
    response_model=ServiceToolsResponse,
    summary="List one service's tools as the caller would see them via /mcp",
)
async def get_service_tools(
    service: str,
    request: Request,
    principal: Annotated[Principal, Depends(keycloak_dependency)],
) -> ServiceToolsResponse:
    """Enumerate *service*'s tools as the caller would see them via /mcp.

    Uses the aggregator's own list-time credential logic
    (aggregator.resolve_list_time_credential / fetch_service_tool_listing),
    so what the portal shows always matches what a tools/list through /mcp
    would return for this caller.
    """
    registry = _get_registry(request)
    spec = registry.get(service)
    if spec is None:
        raise HTTPException(
            status_code=404, detail=f"service '{service}' is not registered"
        )
    policy = _get_policy(request)
    caps = get_principal_permissions(principal, policy)

    # Same pre-fetch gate /v1/catalog's status derivation applies (issue #60,
    # now per-tool-aware): if the caller holds none of the permissions this
    # service could possibly require, no tool of it could be visible either
    # -- skip the fetch entirely rather than probing the service (or the
    # cache) just to filter everything back out.
    if not _holds_any_required_permission(spec, caps):
        return _respond(spec, "permission_required", [], policy, registry, caps)

    if spec.builtin:
        # The builtin gateway service's methods (issue #240) are the
        # aggregator's own local tools (mcp/diagnostics.py) -- there is no
        # backend to HTTP-fetch and no credential to resolve, so list them
        # straight from the mounted FastMCP instance's local provider
        # (stamped onto app.state at mount time in app.py). A bare app
        # without one (misassembled test double) degrades to "unavailable"
        # rather than passing off an empty method list as the truth.
        aggregator = getattr(request.app.state, "mcp_aggregator", None)
        if aggregator is None:
            return _respond(spec, "unavailable", [], policy, registry, caps)
        local_tools = await aggregator.local_provider.list_tools()
        tools = sorted((tool.name, tool.description or "") for tool in local_tools)
        return _respond(spec, "ok", tools, policy, registry, caps)

    credential_registry = _get_credential_registry(request)
    broker_token_issuer = getattr(request.app.state, "broker_token_issuer", None)
    headers, skip_reason = await resolve_list_time_credential(
        spec, credential_registry, principal, broker_token_issuer
    )

    # The cache only ever short-circuits a caller whose credential
    # resolution succeeded (skip_reason None) -- a degraded caller
    # (not linked, provider unavailable) always goes to the live attempt so
    # their status reflects *their* credential state, never another
    # caller's cached success.
    cache = _get_cache(request)
    if skip_reason is None:
        cached = cache.get(spec.name, spec.tools_cache_ttl)
        if cached is not None:
            return _respond(spec, "ok", cached, policy, registry, caps)

    status, tools = await fetch_service_tool_listing(spec, headers, skip_reason)
    if status == "ok":
        if skip_reason is None:
            cache.put(spec.name, tools)
    else:
        logger.info(
            "catalog.tools_list_failed",
            subject=principal.subject,
            target=spec.name,
            status=status,
        )
    return _respond(spec, status, tools, policy, registry, caps)
