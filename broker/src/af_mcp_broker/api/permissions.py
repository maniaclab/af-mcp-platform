from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, Any, Literal

import structlog
from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, ConfigDict

from af_mcp_broker.api.app_state import (
    get_credential_registry,
    get_policy,
    get_registry,
    get_target_to_alias,
)
from af_mcp_broker.authorization import (
    PERMISSIONS,
    EntitlementPolicy,
    check_entitlement,
    get_action_type,
    get_principal_permissions,
)
from af_mcp_broker.identity import keycloak_dependency
from af_mcp_broker.principal import Principal
from af_mcp_broker.service_status import (
    LinkState,
    ServiceStatus,
    granting_groups_for,
    service_status,
)

if TYPE_CHECKING:
    from af_mcp_broker.service_registry import ServiceRegistry, ServiceSpec

logger = structlog.get_logger(__name__)

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


class PermissionCatalogEntry(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str
    action_type: Literal["read", "state_change"]
    # None for a permission the policy declares without prose (every
    # custom_permissions entry).
    description: str | None


class EntitlementsResponse(BaseModel):
    """The static group -> permission table, verbatim from policy.yaml.

    Not caller-scoped -- unlike PermissionsResponse, this is the same for
    every authenticated caller. Lets the portal show "here's what each
    group grants" as a standing reference, not just the caller's own
    resolved grants.
    """

    model_config = ConfigDict(frozen=True)

    group_permissions: dict[str, list[str]]
    # Every permission the policy knows, in display order: built-ins in
    # PERMISSIONS order, then custom_permissions in policy order, then any
    # name only group_permissions grants. Lets the portal show each one's
    # kind and description without a hard-coded copy of this list.
    permissions: list[PermissionCatalogEntry]


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
    # Per-caller availability (issue #123) -- see service_status. Always
    # populated; status_detail is a short, human, internals-free sentence.
    status: ServiceStatus
    status_detail: str
    # Why a link is required: set only when status is "link_required" --
    # "not_linked" (never linked) or "rejected" (linked, but the backend
    # rejected the stored credential). None for every other status.
    link_state: LinkState | None
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
    # The service's own documentation link (ServiceSpec.docs_url), returned
    # for every status; None when the registry entry sets none.
    docs_url: str | None
    # Keycloak groups whose membership grants a permission this service
    # requires -- the answer to "which group do I ask to join?". Set only
    # when status is "permission_required" (empty otherwise). For a per-tool
    # required_permission map this is the union across every tool's
    # permission: "permission_required" means the caller holds none of them,
    # so any listed group unlocks at least one tool (per-tool groups are in
    # the permission-denied tool error). Group names are Keycloak paths users
    # already see on their own profile and in GET /v1/entitlements, and this
    # response is authenticated-only.
    granting_groups: list[str]


class CatalogResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    servers: list[CatalogServer]


# ---------------------------------------------------------------------------
# Helpers — all decisions run through the authorization/ policy engine, which
# is the schema shipped in policy.yaml.
# ---------------------------------------------------------------------------


def _action_type_for_permission(
    permission: str, policy: EntitlementPolicy
) -> Literal["read", "state_change"]:
    # No target, so no target_action_types override can apply: this is the
    # permission's own built-in or custom_permissions action type.
    return get_action_type("", "", permission, policy)  # type: ignore[return-value]


def _permission_catalog(policy: EntitlementPolicy) -> list[PermissionCatalogEntry]:
    """List built-in, then custom, then group-granted-only permissions.

    startup validation (app.py) only checks the permissions *services*
    require, so a group may grant a name that is neither built-in nor
    custom; it is listed last, with the action type the shared resolver
    yields for an unknown name ("read").
    """
    # dict keys: de-duplicate while keeping first-seen order.
    granted = dict.fromkeys(
        name for names in policy.group_permissions.values() for name in names
    )
    names = dict.fromkeys([*PERMISSIONS, *policy.custom_permissions, *granted])
    return [
        PermissionCatalogEntry(
            name=name,
            action_type=_action_type_for_permission(name, policy),
            description=PERMISSIONS[name].description if name in PERMISSIONS else None,
        )
        for name in names
    ]


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
        _action_type_for_permission(perm, policy) == "state_change"
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
                action_types=[_action_type_for_permission(cap, policy)],
            )
        )
    return grants


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
    policy = get_policy(request)
    registry = get_registry(request)
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
    policy = get_policy(request)
    return EntitlementsResponse(
        group_permissions=policy.group_permissions,
        permissions=_permission_catalog(policy),
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
    """Derive the required permission server-side from the service registry (``body.target``/``body.action`` -> ``ServiceRegistry.required_permission_for``) rather than trusting a permission supplied by the caller -- a client used to be able to claim any permission for any target and have it evaluated at face value (see issue #60)."""
    policy = get_policy(request)
    registry = get_registry(request)
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
    policy = get_policy(request)
    registry = get_registry(request)
    credential_registry = get_credential_registry(request)
    caps = get_principal_permissions(principal, policy)
    target_to_alias = get_target_to_alias(request)

    servers: list[CatalogServer] = []
    for spec in registry.all_services():
        # Every registered service is listed, even one this caller can't
        # currently use -- status/status_detail say why instead of a silent
        # omission (issue #123: a hidden, permission-gated service left the
        # portal unable to explain an empty tools/list).
        status, status_detail, correlation_id, link_state = await service_status(
            spec, principal, caps, credential_registry, registry
        )
        granting_groups = granting_groups_for(spec, status, policy)
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
                link_state=link_state,
                correlation_id=correlation_id,
                builtin=spec.builtin,
                trust_tier=spec.trust_tier,
                docs_url=spec.docs_url,
                granting_groups=granting_groups,
            )
        )
    return CatalogResponse(servers=servers)
