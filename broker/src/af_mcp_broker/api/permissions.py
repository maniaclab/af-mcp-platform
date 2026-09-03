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
    # The caller's raw Keycloak group membership -- alongside `grants`
    # (what those groups resolve to) so the portal can show both halves of
    # "why do/don't I have access" without a second round trip (issue:
    # ops-platform-usability, 2026-09-01).
    groups: list[str]
    grants: list[PermissionGrant]


class EntitlementsResponse(BaseModel):
    """The static group -> permission table, verbatim from policy.yaml.

    Not caller-scoped -- unlike PermissionsResponse, this is the same for
    every authenticated caller. Lets the portal show "here's what each
    group grants" as a standing reference, not just the caller's own
    resolved grants.
    """

    model_config = ConfigDict(frozen=True)

    group_permissions: dict[str, list[str]]


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
    # "__none__" for open access (including an omitted required_permission,
    # preserving the historical convention); a real permission name for a
    # scalar required_permission or a dict form's "__default__"; None for a
    # dict form with no "__default__" -- no single representative value,
    # check GET /v1/catalog/{service}/tools' per-tool permission instead.
    permission: str | None
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
    spec: ServiceSpec, policy: EntitlementPolicy
) -> Literal["read", "state_change"]:
    """Server-level read/write badge for a service target.

    Real enforcement (``get_action_type`` in authorization/base.py) resolves
    ``policy.target_action_types[target]`` glob overrides per tool. The
    catalog has no per-tool enumeration yet (issue #58; per-tool `permission`
    now does exist at GET /v1/catalog/{service}/tools -- see
    api/catalog_tools.py -- but not a per-tool action_type rollup here), so
    this reports the safe rollup: "state_change" if *any* permission the
    service can require (across every tool, dict-form included) defaults to
    "state_change", or if *any* per-tool override for this target maps to
    "state_change" (i.e. the server has at least one state-changing tool
    available) — otherwise "read".
    """
    if any(
        _action_type_for_permission(perm) == "state_change"
        for perm in spec.all_required_permissions()
    ):
        return "state_change"
    overrides = policy.target_action_types.get(spec.name, {})
    if any(action_type == "state_change" for action_type in overrides.values()):
        return "state_change"
    return "read"


def _grants_for(
    principal: Principal, policy: EntitlementPolicy, registry: ServiceRegistry
) -> list[PermissionGrant]:
    """Build per-permission grants from the principal's permissions.

    For each granted permission we list the targets that require it, per the
    service registry's ``required_permission`` (services.yaml is the sole
    source of truth for that mapping -- see issue #60). A dict-form
    required_permission can require different permissions for different
    tools, so a service can legitimately appear as a target under more than
    one grant (see ``ServiceSpec.all_required_permissions``).
    """
    caps = get_principal_permissions(principal, policy)
    grants: list[PermissionGrant] = []
    for cap in sorted(caps):
        targets = sorted(
            spec.name
            for spec in registry.all_services()
            if cap in spec.all_required_permissions()
        )
        grants.append(
            PermissionGrant(
                permission=cap,
                targets=targets,
                action_types=[_action_type_for_permission(cap)],
            )
        )
    return grants


def _holds_any_required_permission(spec: ServiceSpec, caps: set[str]) -> bool:
    """Return whether *spec* has no permission gate, or *caps* holds one it can require.

    True if *spec* has no permission gate at all (nothing declared -- an
    omitted, "__none__", or degenerate empty-dict required_permission), or
    the caller holds at least one of the permissions it can require.

    Shared between _service_status (GET /v1/catalog's per-service rollup) and
    catalog_tools.get_service_tools' pre-fetch gate (GET /v1/catalog/{service}
    /tools) -- both need the same "is at least one tool possibly reachable"
    check before deciding whether it's worth fetching/filtering a live tool
    listing at all.
    """
    required = spec.all_required_permissions()
    return not required or bool(required & caps)


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

    For a dict-form required_permission a service can require several
    different permissions across its tools -- "available" here means the
    caller holds at least one of them (some tool is callable), matching
    EntitlementMiddleware's per-tool tools/list filtering rather than an
    all-or-nothing gate on a single value.
    """
    if not _holds_any_required_permission(spec, caps):
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
        subject=principal.subject,
        groups=principal.groups,
        grants=_grants_for(principal, policy, registry),
    )


@router.get(
    "/entitlements",
    response_model=EntitlementsResponse,
    summary="Get the group -> permission reference table",
)
async def get_entitlements(
    request: Request,
    _principal: Annotated[Principal, Depends(keycloak_dependency)],
) -> EntitlementsResponse:
    policy = _get_policy(request)
    return EntitlementsResponse(group_permissions=policy.group_permissions)


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
    """Derive the required permission server-side from the service registry (``body.target``/``body.action`` -> ``ServiceRegistry.required_permission_for``) rather than trusting a permission supplied by the caller -- a client used to be able to claim any permission for any target and have it evaluated at face value (see issue #60)."""
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

    permission = registry.required_permission_for(body.action, service)
    allow, reason = check_entitlement(principal, permission, service.name, policy)
    action_type = get_action_type(service.name, body.action, permission, policy)
    logger.info(
        "authorize_decision",
        subject=principal.subject,
        permission=permission,
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
                # "__none__" for an omitted required_permission preserves the
                # historical convention (indistinguishable there from an
                # explicit "__none__"); None means a dict-form
                # required_permission with no single representative
                # permission -- see per-tool GET /v1/catalog/{service}/tools
                # (api/catalog_tools.py) instead.
                permission=spec.default_permission_label(),
                auth_type=spec.auth_type,
                action_type=_action_type_for_service(spec, policy),
                credential_provider=target_to_alias.get(spec.name),
                status=status,
                status_detail=status_detail,
                correlation_id=correlation_id,
                builtin=spec.builtin,
                trust_tier=spec.trust_tier,
            )
        )
    return CatalogResponse(servers=servers)
