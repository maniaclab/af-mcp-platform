from __future__ import annotations

from typing import TYPE_CHECKING, Literal

import structlog

from af_mcp_broker.authorization import groups_granting_any
from af_mcp_broker.constants import BUILTIN_SERVICE_NAME
from af_mcp_broker.logging import current_request_id
from af_mcp_broker.service_registry import (
    LIST_IDENTITIES_TOOL_NAME,
    WHOAMI_TOOL_NAME,
)

if TYPE_CHECKING:
    from af_mcp_broker.authorization import EntitlementPolicy
    from af_mcp_broker.credentials import CredentialRegistry
    from af_mcp_broker.principal import Principal
    from af_mcp_broker.service_registry import ServiceRegistry, ServiceSpec

logger = structlog.get_logger(__name__)

# Per-service availability status for /v1/catalog (issue #123). A short,
# canned sentence per status -- never an upstream error body or policy/group
# detail (see service_status below).
ServiceStatus = Literal[
    "available",
    "link_required",
    "permission_required",
    "unavailable",
    "misconfigured",
]

# Why a "link_required" service needs a link: the caller never linked the
# identity ("not_linked"), or linked it and the backend rejected the stored
# credential ("rejected"). None for every other status.
LinkState = Literal["not_linked", "rejected"]

STATUS_DETAILS: dict[ServiceStatus, str] = {
    "available": "Available.",
    "link_required": (
        "Link your identity to use this service. Call the "
        f"{BUILTIN_SERVICE_NAME} service's `{LIST_IDENTITIES_TOOL_NAME}` "
        "method to see which identity provider it needs."
    ),
    "permission_required": (
        "Your account doesn't have the access this service requires. "
        f"Contact the AF admins. Call the {BUILTIN_SERVICE_NAME} service's "
        f"`{WHOAMI_TOOL_NAME}` method to see your current permissions."
    ),
    "unavailable": "Temporarily unavailable. Try again shortly.",
    "misconfigured": "This service is misconfigured. Contact the AF admins.",
}

# A stored credential that was itself rejected (a recorded "unauthorized"
# listing failure -- see aggregator.py's _classify_list_failure) still maps
# to "link_required" (re-linking is the fix, same as never having linked at
# all), but the sentence should say "re-link", not "link for the first time".
RELINK_DETAIL = (
    "Your linked credential was rejected. Re-link your identity. Call the "
    f"{BUILTIN_SERVICE_NAME} service's `{LIST_IDENTITIES_TOOL_NAME}` method "
    "to see which identity provider to re-link."
)

# "misconfigured" for a service whose backend advertises tools but none the
# broker can route (see service_status) -- distinct from the generic
# sentence so the catalog says why the service shows no tools.
NO_ROUTABLE_TOOLS_DETAIL = (
    "No routable tools: the service advertises tools the gateway cannot "
    "route ({advertised} advertised, 0 routable). Contact the AF admins."
)


def holds_any_required_permission(spec: ServiceSpec, caps: set[str]) -> bool:
    """Return whether *spec* has no permission gate, or *caps* holds one it can require.

    True if *spec* has no permission gate at all (nothing declared -- an
    omitted, "__none__", or degenerate empty-dict required_permission), or
    the caller holds at least one of the permissions it can require.

    Shared between service_status (GET /v1/catalog's per-service rollup) and
    catalog_tools.get_service_tools' pre-fetch gate (GET /v1/catalog/{service}
    /tools) -- both need the same "is at least one tool possibly reachable"
    check before deciding whether it's worth fetching/filtering a live tool
    listing at all.
    """
    required = spec.all_required_permissions()
    return not required or bool(required & caps)


def granting_groups_for(
    spec: ServiceSpec, status: ServiceStatus, policy: EntitlementPolicy
) -> list[str]:
    """Return the groups granting a permission *spec* requires: empty unless *status* is "permission_required"."""
    if status != "permission_required":
        return []
    return groups_granting_any(policy, spec.all_required_permissions())


async def service_status(
    spec: ServiceSpec,
    principal: Principal,
    caps: set[str],
    credential_registry: CredentialRegistry,
    registry: ServiceRegistry,
) -> tuple[ServiceStatus, str, str | None, LinkState | None]:
    """Derive one service's per-caller availability status for /v1/catalog (issue #123) from data the broker already has -- never an upstream probe of the service itself, an upstream error body, or a policy internal (see STATUS_DETAILS's canned sentences). The groups that would grant a missing permission travel separately, as CatalogServer.granting_groups.

    Precedence mirrors the real enforcement order (AuthorizationMiddleware
    checks entitlement before a client_factory ever attempts to mint a
    credential -- see aggregator.py's _bearer_factory): a missing permission
    is reported before a credential problem, since the credential is moot
    until the permission gate is fixed. Returns
    ``(status, status_detail, request_id, link_state)`` --
    request_id is set only for the two admin-actionable statuses and
    link_state only for "link_required".

    For a dict-form required_permission a service can require several
    different permissions across its tools -- "available" here means the
    caller holds at least one of them (some tool is callable), matching
    EntitlementMiddleware's per-tool tools/list filtering rather than an
    all-or-nothing gate on a single value.
    """
    if not holds_any_required_permission(spec, caps):
        request_id = current_request_id()
        logger.info(
            "catalog.service_status_flagged",
            subject=principal.subject,
            target=spec.name,
            status="permission_required",
            request_id=request_id,
        )
        return (
            "permission_required",
            STATUS_DETAILS["permission_required"],
            request_id,
            None,
        )

    # A backend whose every advertised tool lost the service's prefix (a
    # rename under apply_namespace: false -- ToolRouting, recorded by
    # aggregator.py's _ObservableProxyProvider) leaves callers with zero
    # tools however linked they are: a platform misconfiguration, checked
    # before the credential like the missing-provider case below.
    routing = registry.tool_routing(spec.name)
    if routing is not None and routing.advertised > 0 and routing.routable == 0:
        request_id = current_request_id()
        logger.info(
            "catalog.service_status_flagged",
            subject=principal.subject,
            target=spec.name,
            status="misconfigured",
            request_id=request_id,
        )
        return (
            "misconfigured",
            NO_ROUTABLE_TOOLS_DETAIL.format(advertised=routing.advertised),
            request_id,
            None,
        )

    if spec.auth_type == "none":
        # No permission gate (or one just satisfied) and no user credential
        # needed at all -- nothing left to block on except a backend that is
        # down. Only the service-wide "unavailable" record applies: the
        # caller-specific reasons are about a per-user credential this
        # service has none of.
        if registry.recent_list_failure(spec.name, principal.subject) == "unavailable":
            return "unavailable", STATUS_DETAILS["unavailable"], None, None
        return "available", STATUS_DETAILS["available"], None, None

    try:
        provider = await credential_registry.resolve(spec.name)
    except KeyError:
        # auth_type is "bearer"/"x509" (a credential IS expected) but no
        # provider resolves for this target -- a platform misconfiguration,
        # not something the caller can fix themselves.
        request_id = current_request_id()
        logger.info(
            "catalog.service_status_flagged",
            subject=principal.subject,
            target=spec.name,
            status="misconfigured",
            request_id=request_id,
        )
        return "misconfigured", STATUS_DETAILS["misconfigured"], request_id, None

    if not await provider.is_linked(principal):
        if await provider.is_rejected(principal):
            return "link_required", RELINK_DETAIL, None, "rejected"
        return "link_required", STATUS_DETAILS["link_required"], None, "not_linked"

    # Permission satisfied, provider resolves, and linked -- the live checks
    # above all say "available". Factor in a recent classified tools/list
    # failure (ServiceRegistry.record_list_failure, written by aggregator.py's
    # _ObservableProxyProvider) as a best-effort refinement, without an extra
    # live probe of the service itself. "not_linked" can't appear here (the
    # live is_linked() check above already accounts for it); "unauthorized"
    # means the stored credential itself was rejected, so re-linking (not
    # waiting it out) is the fix. A provider that tracks rejection itself
    # already answered above through is_rejected(): its credential may have
    # been refreshed or re-linked since the 401 behind the record, so the
    # record doesn't count for it.
    failure = registry.recent_list_failure(spec.name, principal.subject)
    if failure == "unavailable":
        return "unavailable", STATUS_DETAILS["unavailable"], None, None
    if failure == "unauthorized" and not provider.tracks_rejection:
        return "link_required", RELINK_DETAIL, None, "rejected"

    return "available", STATUS_DETAILS["available"], None, None
