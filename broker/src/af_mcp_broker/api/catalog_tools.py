from __future__ import annotations

# GET /v1/catalog/{service}/tools -- the portal's per-service tool listing
# (the fetch-on-expand companion to GET /v1/catalog). Lives in its own module
# rather than api/permissions.py because it is the one route that opens a
# connection to a backend service, through backend_client.py's list-time
# helpers.
import asyncio
from typing import TYPE_CHECKING, Annotated, Literal

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request

# Runtime import (not TYPE_CHECKING): pydantic must resolve
# ServiceTool.annotations' annotation when the model class is built.
from mcp.types import ToolAnnotations  # noqa: TC002
from pydantic import BaseModel, ConfigDict

from af_mcp_broker.api.auth import keycloak_dependency
from af_mcp_broker.authorization import (
    DISABLED_PERMISSION,
    get_action_type,
    get_principal_permissions,
)
from af_mcp_broker.backend_client import (
    ToolListingEntry,
    fetch_service_tool_listing,
    resolve_list_time_credential,
)
from af_mcp_broker.backend_errors import NotLinkedForListingError
from af_mcp_broker.broker_state import get_broker_state
from af_mcp_broker.principal import Principal
from af_mcp_broker.service_status import holds_any_required_permission

if TYPE_CHECKING:
    from af_mcp_broker.authorization import EntitlementPolicy
    from af_mcp_broker.broker_state import BrokerState
    from af_mcp_broker.service_registry import ServiceRegistry, ServiceSpec

logger = structlog.get_logger(__name__)

router = APIRouter(tags=["permissions"])

# The status vocabulary matches backend_client.py's classify_failure one-to-one
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
    "timeout",
    "permission_required",
]

_STATUS_DETAILS: dict[str, str] = {
    "ok": "Methods listed.",
    "not_linked": "Link your identity to see this service's methods.",
    "unauthorized": "Your linked credential was rejected. Re-link your identity.",
    "unavailable": "Temporarily unavailable. Try again shortly.",
    # Distinct from "unavailable" (issue #280): a connection-level refusal
    # means the service couldn't even be reached, but this means a request
    # WAS sent and never got a correlated response back in time -- usually a
    # slow/unresponsive backend, though an mcp SDK gap in 1.x (a malformed
    # response never reached the caller) could also produce this exact
    # symptom. The pinned mcp 2.x delivers a JSON-RPC error for a malformed
    # response instead, but the wording still says "may be slow, or may
    # have sent something unexpected" rather than claiming certainty.
    "timeout": (
        "This service did not respond in time. It may be slow or "
        "temporarily down, or it may have returned something unexpected — "
        "contact the AF admins if this persists."
    ),
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
    client, not the catalog). ``annotations`` and ``has_output_schema``
    (issue #238 B.7) are the same metadata a real ``tools/list`` through
    /mcp carries, forwarded here so the portal can show a read/write badge
    (annotations.read_only_hint) once a backend declares one; ``policy.yaml``
    stays authoritative for actual enforcement (``action_type``/
    ``permission`` above) -- annotations are visibility only.
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
    annotations: ToolAnnotations | None
    has_output_schema: bool


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


def _respond(
    spec: ServiceSpec,
    status: str,
    tools: list[ToolListingEntry],
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
    for entry in tools:
        permission = registry.required_permission_for(entry.name, spec)
        if permission == DISABLED_PERMISSION:
            continue
        if (
            permission is not None
            and permission != "__none__"
            and permission not in caps
        ):
            continue  # a real permission this caller doesn't hold
        action_type = get_action_type(spec.name, entry.name, permission, policy)
        visible.append(
            ServiceTool(
                name=entry.name,
                description=entry.description,
                action_type=action_type,  # type: ignore[arg-type]
                permission=permission if permission is not None else "__none__",
                annotations=entry.annotations,
                has_output_schema=entry.has_output_schema,
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


async def list_service_tools(
    state: BrokerState, principal: Principal, spec: ServiceSpec
) -> ServiceToolsResponse:
    """Enumerate *spec*'s tools as *principal* would see them via /mcp, with the listing status when they cannot be listed."""
    registry = state.service_registry
    policy = state.entitlement_policy
    caps = get_principal_permissions(principal, policy)

    # Same pre-fetch gate /v1/catalog's status derivation applies (issue #60,
    # per-tool-aware): if the caller holds none of the permissions this
    # service could possibly require, no tool of it could be visible either
    # -- skip the fetch entirely rather than probing the service (or the
    # cache) just to filter everything back out.
    if not holds_any_required_permission(spec, caps):
        return _respond(spec, "permission_required", [], policy, registry, caps)

    if spec.builtin:
        # The builtin gateway service's methods (issue #240) are the
        # aggregator's own local tools (mcp/diagnostics.py) -- there is no
        # backend to HTTP-fetch and no credential to resolve, so list them
        # straight from the mounted FastMCP instance's local provider.
        local_tools = await state.mcp_aggregator.local_provider.list_tools()
        tools = sorted(
            (
                ToolListingEntry(
                    name=tool.name,
                    description=tool.description or "",
                    annotations=tool.annotations,
                    has_output_schema=tool.output_schema is not None,
                )
                for tool in local_tools
            ),
            key=lambda entry: entry.name,
        )
        return _respond(spec, "ok", tools, policy, registry, caps)

    # One deadline over the whole live attempt (credential resolution and the
    # backend round trip), the same Settings.mcp_list_timeout_seconds that
    # bounds a tools/list through /mcp, so a hung backend or credential store
    # cannot hold this request past the portal's own timeout.
    settings = state.settings
    deadline = asyncio.timeout(settings.mcp_list_timeout_seconds)
    try:
        async with deadline:
            credential_registry = state.credential_registry
            broker_token_issuer = state.broker_token_issuer
            try:
                credential = await resolve_list_time_credential(
                    spec, credential_registry, principal, broker_token_issuer
                )
            except NotLinkedForListingError as exc:
                # A rejected credential reads as "unauthorized" (re-link), matching
                # the catalog's "rejected" link state, not "not_linked".
                status = "unauthorized" if exc.rejected else "not_linked"
                logger.info(
                    "catalog.tools_list_failed",
                    subject=principal.subject,
                    target=spec.name,
                    status=status,
                )
                return _respond(spec, status, [], policy, registry, caps)
            skip_reason = credential.skip_reason

            # The cache only ever short-circuits a caller whose credential
            # resolution succeeded (skip_reason None) -- a degraded caller
            # (not linked, provider unavailable) always goes to the live attempt so
            # their status reflects *their* credential state, never another
            # caller's cached success.
            cache = state.tool_listing_cache
            if skip_reason is None:
                cached = cache.get(spec.name, spec.tools_cache_ttl)
                if cached is not None:
                    return _respond(spec, "ok", cached, policy, registry, caps)

            status, tools = await fetch_service_tool_listing(spec, credential)
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
    except TimeoutError:
        if not deadline.expired():
            raise
        logger.warning(
            "catalog.tools_list_failed",
            subject=principal.subject,
            target=spec.name,
            status="unavailable",
            reason="list_deadline_exceeded",
        )
        return _respond(spec, "unavailable", [], policy, registry, caps)


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
    state = get_broker_state(request)
    spec = state.service_registry.get(service)
    if spec is None:
        raise HTTPException(
            status_code=404, detail=f"service '{service}' is not registered"
        )
    return await list_service_tools(state, principal, spec)
