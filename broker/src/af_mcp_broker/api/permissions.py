from __future__ import annotations

import uuid
from typing import TYPE_CHECKING, Annotated, Any, Literal

import structlog
from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, ConfigDict

from af_mcp_broker.authorization import (
    PERMISSIONS,
    EntitlementPolicy,
    check_entitlement,
    get_action_type,
    get_principal_permissions,
)
from af_mcp_broker.credentials import CredentialRegistry
from af_mcp_broker.identity import Principal, keycloak_dependency
from af_mcp_broker.mcp.registry import (
    BUILTIN_SERVICE_NAME,
    LIST_IDENTITIES_TOOL_NAME,
    WHOAMI_TOOL_NAME,
    ServiceRegistry,
)

if TYPE_CHECKING:
    from af_mcp_broker.mcp.registry import ServiceSpec

logger = structlog.get_logger(__name__)

# Per-service availability status for /v1/catalog (issue #123). A short,
# canned sentence per status -- never an upstream error body or policy/group
# detail (see _service_status below).
ServiceStatus = Literal[
    "available",
    "link_required",
    "permission_required",
    "unavailable",
    "misconfigured",
]

_STATUS_DETAILS: dict[ServiceStatus, str] = {
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
_RELINK_DETAIL = (
    "Your linked credential was rejected. Re-link your identity. Call the "
    f"{BUILTIN_SERVICE_NAME} service's `{LIST_IDENTITIES_TOOL_NAME}` method "
    "to see which identity provider to re-link."
)

router = APIRouter(tags=["permissions"])

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class PermissionGrant(BaseModel):
    model_config = ConfigDict(frozen=True)

    permission: str
    targets: list[str]
    action_types: list[Literal["read", "state_change"]]


class PermissionsResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    subject: str
    grants: list[PermissionGrant]


class AuthorizeRequest(BaseModel):
    model_config = ConfigDict(frozen=True)

    target: str
    # The concrete tool name being invoked; used to resolve the action type.
    action: str
    context: dict[str, Any] = {}


class AuthorizeResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    allow: bool
    reason: str
    action_type: Literal["read", "state_change"]
    obligations: list[str] = []


class CatalogServer(BaseModel):
    """One registered MCP server, including ones the caller can't currently use -- ``status``/``status_detail`` say why instead of the caller silently never seeing the entry (issue #123).

    Per-server tool enumeration deliberately does NOT live here: the catalog
    stays a single cheap request, and the portal fetches one server's tools
    on demand via GET /v1/catalog/{service}/tools (api/catalog_tools.py),
    which fans out to that service alone.
    """

    model_config = ConfigDict(frozen=True)

    name: str
    display_name: str
    description: str
    permission: str
    auth_type: str
    action_type: Literal["read", "state_change"]
    credential_provider: str | None
    # Per-caller availability (issue #123) -- see _service_status. Always
    # populated; status_detail is a short, human, internals-free sentence.
    status: ServiceStatus
    status_detail: str
    # Set only for admin-actionable statuses (permission_required,
    # misconfigured) -- a correlation id the caller can quote in a ticket so
    # an admin can grep the audit log for it. None otherwise.
    correlation_id: str | None
    # True only for the broker's own gateway service entry (ServiceSpec.builtin,
    # issue #240) -- the portal's cue to drop the identity-link/credential
    # affordances that don't apply to the gateway itself.
    builtin: bool
    # The service's declared Elwood v5 / Shannon trust tier (ServiceSpec.
    # trust_tier -- see docs/architecture.md's "Trust tiers"), or None when
    # the registry entry leaves it undeclared. Surfaced as a machine-readable
    # field so a catalog consumer can reason about a service's governance
    # posture; the authoritative per-deployment assignment lives in the GitOps
    # repo (maniaclab/flux_apps#32).
    trust_tier: str | None


class CatalogResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    servers: list[CatalogServer]


# ---------------------------------------------------------------------------
# Helpers — all decisions run through the authorization/ policy engine, which
# is the schema shipped in policy.yaml.
# ---------------------------------------------------------------------------


def _empty_policy() -> EntitlementPolicy:
    return EntitlementPolicy()


def _get_policy(request: Request) -> EntitlementPolicy:
    return getattr(request.app.state, "entitlement_policy", None) or _empty_policy()


def _get_registry(request: Request) -> ServiceRegistry:
    return getattr(request.app.state, "service_registry", None) or ServiceRegistry()


def _get_target_to_alias(request: Request) -> dict[str, str]:
    return getattr(request.app.state, "target_to_alias", None) or {}


def _get_credential_registry(request: Request) -> CredentialRegistry:
    return (
        getattr(request.app.state, "credential_registry", None) or CredentialRegistry()
    )


def _action_type_for_permission(
    permission: str | None,
) -> Literal["read", "state_change"]:
    cap = PERMISSIONS.get(permission) if permission is not None else None
    return cap.action_type if cap else "read"  # type: ignore[return-value]


def _action_type_for_service(
    target: str, permission: str | None, policy: EntitlementPolicy
) -> Literal["read", "state_change"]:
    """Server-level read/write badge for a service target.

    Real enforcement (``get_action_type`` in authorization/base.py) resolves
    ``policy.target_action_types[target]`` glob overrides per tool. The
    catalog has no per-tool enumeration yet (issue #58), so this reports the
    safe rollup: "state_change" if the permission's default action type is
    already "state_change", or if *any* per-tool override for this target
    maps to "state_change" (i.e. the server has at least one state-changing
    tool available) — otherwise "read".
    """
    if _action_type_for_permission(permission) == "state_change":
        return "state_change"
    overrides = policy.target_action_types.get(target, {})
    if any(action_type == "state_change" for action_type in overrides.values()):
        return "state_change"
    return "read"


def _grants_for(
    principal: Principal, policy: EntitlementPolicy, registry: ServiceRegistry
) -> list[PermissionGrant]:
    """Build per-permission grants from the principal's permissions.

    For each granted permission we list the targets that require it, per the
    service registry's ``required_permission`` (services.yaml is the sole
    source of truth for that mapping -- see issue #60).
    """
    caps = get_principal_permissions(principal, policy)
    grants: list[PermissionGrant] = []
    for cap in sorted(caps):
        targets = sorted(
            spec.name
            for spec in registry.all_services()
            if spec.required_permission == cap
        )
        grants.append(
            PermissionGrant(
                permission=cap,
                targets=targets,
                action_types=[_action_type_for_permission(cap)],
            )
        )
    return grants


async def _service_status(
    spec: ServiceSpec,
    principal: Principal,
    caps: set[str],
    credential_registry: CredentialRegistry,
    registry: ServiceRegistry,
) -> tuple[ServiceStatus, str, str | None]:
    """Derive one service's per-caller availability status for /v1/catalog (issue #123) from data the broker already has -- never an upstream probe of the service itself, an upstream error body, a policy internal, or a group list (see _STATUS_DETAILS's canned sentences).

    Precedence mirrors the real enforcement order (AuthorizationMiddleware
    checks entitlement before a client_factory ever attempts to mint a
    credential -- see aggregator.py's _bearer_factory): a missing permission
    is reported before a credential problem, since the credential is moot
    until the permission gate is fixed. Returns
    ``(status, status_detail, correlation_id)`` -- correlation_id is set
    only for the two admin-actionable statuses.
    """
    required = spec.required_permission
    if required not in (None, "__none__") and required not in caps:
        correlation_id = uuid.uuid4().hex
        logger.info(
            "catalog.service_status_flagged",
            subject=principal.subject,
            target=spec.name,
            status="permission_required",
            request_id=correlation_id,
        )
        return (
            "permission_required",
            _STATUS_DETAILS["permission_required"],
            correlation_id,
        )

    if spec.auth_type == "none":
        # No permission gate (or one just satisfied) and no user credential
        # needed at all -- nothing left to block on.
        return "available", _STATUS_DETAILS["available"], None

    try:
        provider = await credential_registry.resolve(spec.name)
    except KeyError:
        # auth_type is "bearer"/"x509" (a credential IS expected) but no
        # provider resolves for this target -- a platform misconfiguration,
        # not something the caller can fix themselves.
        correlation_id = uuid.uuid4().hex
        logger.info(
            "catalog.service_status_flagged",
            subject=principal.subject,
            target=spec.name,
            status="misconfigured",
            request_id=correlation_id,
        )
        return "misconfigured", _STATUS_DETAILS["misconfigured"], correlation_id

    if not await provider.is_linked(principal):
        return "link_required", _STATUS_DETAILS["link_required"], None

    # Permission satisfied, provider resolves, and linked -- the live checks
    # above all say "available". Factor in a recent classified tools/list
    # failure (ServiceRegistry.record_list_failure, written by aggregator.py's
    # _ObservableProxyProvider) as a best-effort refinement, without an extra
    # live probe of the service itself. "not_linked" can't appear here (the
    # live is_linked() check above already accounts for it); "unauthorized"
    # means the stored credential itself was rejected, so re-linking (not
    # waiting it out) is the fix.
    failure = registry.recent_list_failure(spec.name)
    if failure == "unavailable":
        return "unavailable", _STATUS_DETAILS["unavailable"], None
    if failure == "unauthorized":
        return "link_required", _RELINK_DETAIL, None

    return "available", _STATUS_DETAILS["available"], None


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get(
    "/permissions",
    response_model=PermissionsResponse,
    summary="List caller's granted permissions",
)
async def get_permissions(
    request: Request,
    principal: Annotated[Principal, Depends(keycloak_dependency)],
) -> PermissionsResponse:
    policy = _get_policy(request)
    registry = _get_registry(request)
    return PermissionsResponse(
        subject=principal.subject, grants=_grants_for(principal, policy, registry)
    )


@router.post(
    "/authorize",
    response_model=AuthorizeResponse,
    summary="Check a single entitlement",
)
async def authorize(
    body: AuthorizeRequest,
    request: Request,
    principal: Annotated[Principal, Depends(keycloak_dependency)],
) -> AuthorizeResponse:
    """Derive the required permission server-side from the service registry (``body.target`` -> ``ServiceSpec.required_permission``) rather than trusting a permission supplied by the caller -- a client used to be able to claim any permission for any target and have it evaluated at face value (see issue #60)."""
    policy = _get_policy(request)
    registry = _get_registry(request)
    service = registry.get(body.target)
    if service is None:
        reason = f"target '{body.target}' is not a registered service"
        logger.info(
            "authorize_decision",
            subject=principal.subject,
            target=body.target,
            action=body.action,
            allow=False,
            reason=reason,
        )
        return AuthorizeResponse(
            allow=False, reason=reason, action_type="read", obligations=[]
        )

    allow, reason = check_entitlement(
        principal, service.required_permission, service.name, policy
    )
    action_type = get_action_type(
        service.name, body.action, service.required_permission, policy
    )
    logger.info(
        "authorize_decision",
        subject=principal.subject,
        permission=service.required_permission,
        target=body.target,
        action=body.action,
        action_type=action_type,
        allow=allow,
        reason=reason,
    )
    return AuthorizeResponse(
        allow=allow,
        reason=reason,
        action_type=action_type,  # type: ignore[arg-type]
        obligations=[],
    )


@router.get(
    "/catalog",
    response_model=CatalogResponse,
    summary="List visible MCP servers post-entitlement filtering",
)
async def get_catalog(
    request: Request,
    principal: Annotated[Principal, Depends(keycloak_dependency)],
) -> CatalogResponse:
    policy = _get_policy(request)
    registry = _get_registry(request)
    credential_registry = _get_credential_registry(request)
    caps = get_principal_permissions(principal, policy)
    target_to_alias = _get_target_to_alias(request)

    servers: list[CatalogServer] = []
    for spec in registry.all_services():
        required = spec.required_permission
        # Every registered service is listed, even one this caller can't
        # currently use -- status/status_detail say why instead of a silent
        # omission (issue #123: a hidden, permission-gated service left the
        # portal unable to explain an empty tools/list).
        status, status_detail, correlation_id = await _service_status(
            spec, principal, caps, credential_registry, registry
        )
        servers.append(
            CatalogServer(
                name=spec.name,
                display_name=spec.display_name or spec.name,
                description=spec.description,
                # Omitted required_permission means no permission gate (the
                # credential layer gates it instead -- see registry.py); the
                # catalog reports that the same way as the explicit "__none__"
                # opt-in, since neither implies a permission requirement.
                permission=required if required is not None else "__none__",
                auth_type=spec.auth_type,
                action_type=_action_type_for_service(spec.name, required, policy),
                credential_provider=target_to_alias.get(spec.name),
                status=status,
                status_detail=status_detail,
                correlation_id=correlation_id,
                builtin=spec.builtin,
                trust_tier=spec.trust_tier,
            )
        )
    return CatalogResponse(servers=servers)
