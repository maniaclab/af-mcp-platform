from __future__ import annotations

import uuid
from typing import TYPE_CHECKING, Annotated, Any, Literal

import structlog
from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, ConfigDict

from af_mcp_broker.authorization import (
    CAPABILITIES,
    EntitlementPolicy,
    check_entitlement,
    get_action_type,
    get_principal_capabilities,
)
from af_mcp_broker.credentials import CredentialRegistry
from af_mcp_broker.identity import Principal, keycloak_dependency
from af_mcp_broker.mcp.registry import BackendRegistry

if TYPE_CHECKING:
    from af_mcp_broker.mcp.registry import BackendSpec

logger = structlog.get_logger(__name__)

# Per-backend availability status for /v1/catalog (issue #123). A short,
# canned sentence per status -- never an upstream error body or policy/group
# detail (see _backend_status below).
BackendStatus = Literal[
    "available",
    "link_required",
    "capability_required",
    "unavailable",
    "misconfigured",
]

_STATUS_DETAILS: dict[BackendStatus, str] = {
    "available": "Available.",
    "link_required": "Link your identity to use this backend.",
    "capability_required": (
        "Your account doesn't have the access this backend requires. "
        "Contact the AF admins."
    ),
    "unavailable": "Temporarily unavailable. Try again shortly.",
    "misconfigured": "This backend is misconfigured. Contact the AF admins.",
}

# A stored credential that was itself rejected (a recorded "unauthorized"
# listing failure -- see aggregator.py's _classify_list_failure) still maps
# to "link_required" (re-linking is the fix, same as never having linked at
# all), but the sentence should say "re-link", not "link for the first time".
_RELINK_DETAIL = "Your linked credential was rejected. Re-link your identity."

router = APIRouter(tags=["capabilities"])

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class CapabilityGrant(BaseModel):
    model_config = ConfigDict(frozen=True)

    capability: str
    targets: list[str]
    action_types: list[Literal["read", "state_change"]]


class CapabilitiesResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    subject: str
    grants: list[CapabilityGrant]


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
    """One registered MCP server, including ones the caller can't currently
    use -- ``status``/``status_detail`` say why instead of the caller
    silently never seeing the entry (issue #123).

    ``tools`` is an empty placeholder until the /mcp aggregator can enumerate
    real subtools per server (issue #58); it exists now so the portal's
    per-server tool listing has a stable field to render once populated,
    rather than needing a second response-shape change later.
    """

    model_config = ConfigDict(frozen=True)

    name: str
    display_name: str
    description: str
    capability: str
    auth_type: str
    action_type: Literal["read", "state_change"]
    credential_provider: str | None
    # Per-caller availability (issue #123) -- see _backend_status. Always
    # populated; status_detail is a short, human, internals-free sentence.
    status: BackendStatus
    status_detail: str
    # Set only for admin-actionable statuses (capability_required,
    # misconfigured) -- a correlation id the caller can quote in a ticket so
    # an admin can grep the audit log for it. None otherwise.
    correlation_id: str | None
    tools: list[Any] = []


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


def _get_registry(request: Request) -> BackendRegistry:
    return getattr(request.app.state, "backend_registry", None) or BackendRegistry()


def _get_target_to_alias(request: Request) -> dict[str, str]:
    return getattr(request.app.state, "target_to_alias", None) or {}


def _get_credential_registry(request: Request) -> CredentialRegistry:
    return getattr(
        request.app.state, "credential_registry", None
    ) or CredentialRegistry()


def _action_type_for_capability(
    capability: str | None,
) -> Literal["read", "state_change"]:
    cap = CAPABILITIES.get(capability) if capability is not None else None
    return cap.action_type if cap else "read"  # type: ignore[return-value]


def _action_type_for_backend(
    target: str, capability: str | None, policy: EntitlementPolicy
) -> Literal["read", "state_change"]:
    """Server-level read/write badge for a backend target.

    Real enforcement (``get_action_type`` in authorization/base.py) resolves
    ``policy.target_action_types[target]`` glob overrides per tool. The
    catalog has no per-tool enumeration yet (issue #58), so this reports the
    safe rollup: "state_change" if the capability's default action type is
    already "state_change", or if *any* per-tool override for this target
    maps to "state_change" (i.e. the server has at least one state-changing
    tool available) — otherwise "read".
    """
    if _action_type_for_capability(capability) == "state_change":
        return "state_change"
    overrides = policy.target_action_types.get(target, {})
    if any(action_type == "state_change" for action_type in overrides.values()):
        return "state_change"
    return "read"


def _grants_for(
    principal: Principal, policy: EntitlementPolicy, registry: BackendRegistry
) -> list[CapabilityGrant]:
    """Build per-capability grants from the principal's capabilities.

    For each granted capability we list the targets that require it, per the
    backend registry's ``required_capability`` (backends.yaml is the sole
    source of truth for that mapping -- see issue #60).
    """
    caps = get_principal_capabilities(principal, policy)
    grants: list[CapabilityGrant] = []
    for cap in sorted(caps):
        targets = sorted(
            spec.name
            for spec in registry.all_backends()
            if spec.required_capability == cap
        )
        grants.append(
            CapabilityGrant(
                capability=cap,
                targets=targets,
                action_types=[_action_type_for_capability(cap)],
            )
        )
    return grants


async def _backend_status(
    spec: BackendSpec,
    principal: Principal,
    caps: set[str],
    credential_registry: CredentialRegistry,
    registry: BackendRegistry,
) -> tuple[BackendStatus, str, str | None]:
    """Derive one backend's per-caller availability status for /v1/catalog
    (issue #123) from data the broker already has -- never an upstream
    probe of the backend itself, an upstream error body, a policy internal,
    or a group list (see _STATUS_DETAILS's canned sentences).

    Precedence mirrors the real enforcement order (AuthorizationMiddleware
    checks entitlement before a client_factory ever attempts to mint a
    credential -- see aggregator.py's _bearer_factory): a missing capability
    is reported before a credential problem, since the credential is moot
    until the capability gate is fixed. Returns
    ``(status, status_detail, correlation_id)`` -- correlation_id is set
    only for the two admin-actionable statuses.
    """
    required = spec.required_capability
    if required not in (None, "__none__") and required not in caps:
        correlation_id = uuid.uuid4().hex
        logger.info(
            "catalog.backend_status_flagged",
            subject=principal.subject,
            target=spec.name,
            status="capability_required",
            request_id=correlation_id,
        )
        return (
            "capability_required",
            _STATUS_DETAILS["capability_required"],
            correlation_id,
        )

    if spec.auth_type == "none":
        # No capability gate (or one just satisfied) and no user credential
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
            "catalog.backend_status_flagged",
            subject=principal.subject,
            target=spec.name,
            status="misconfigured",
            request_id=correlation_id,
        )
        return "misconfigured", _STATUS_DETAILS["misconfigured"], correlation_id

    if not await provider.is_linked(principal):
        return "link_required", _STATUS_DETAILS["link_required"], None

    # Capability satisfied, provider resolves, and linked -- the live checks
    # above all say "available". Factor in a recent classified tools/list
    # failure (BackendRegistry.record_list_failure, written by aggregator.py's
    # _ObservableProxyProvider) as a best-effort refinement, without an extra
    # live probe of the backend itself. "not_linked" can't appear here (the
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
    "/capabilities",
    response_model=CapabilitiesResponse,
    summary="List caller's granted capabilities",
)
async def get_capabilities(
    request: Request,
    principal: Annotated[Principal, Depends(keycloak_dependency)],
) -> CapabilitiesResponse:
    policy = _get_policy(request)
    registry = _get_registry(request)
    return CapabilitiesResponse(
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
    """Derives the required capability server-side from the backend registry
    (``body.target`` -> ``BackendSpec.required_capability``) rather than
    trusting a capability supplied by the caller -- a client used to be able
    to claim any capability for any target and have it evaluated at face
    value (see issue #60).
    """
    policy = _get_policy(request)
    registry = _get_registry(request)
    backend = registry.get(body.target)
    if backend is None:
        reason = f"target '{body.target}' is not a registered backend"
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
        principal, backend.required_capability, backend.name, policy
    )
    action_type = get_action_type(
        backend.name, body.action, backend.required_capability, policy
    )
    logger.info(
        "authorize_decision",
        subject=principal.subject,
        capability=backend.required_capability,
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
    caps = get_principal_capabilities(principal, policy)
    target_to_alias = _get_target_to_alias(request)

    servers: list[CatalogServer] = []
    for spec in registry.all_backends():
        required = spec.required_capability
        # Every registered backend is listed, even one this caller can't
        # currently use -- status/status_detail say why instead of a silent
        # omission (issue #123: a hidden, capability-gated backend left the
        # portal unable to explain an empty tools/list).
        status, status_detail, correlation_id = await _backend_status(
            spec, principal, caps, credential_registry, registry
        )
        servers.append(
            CatalogServer(
                name=spec.name,
                display_name=spec.display_name or spec.name,
                description=spec.description,
                # Omitted required_capability means no capability gate (the
                # credential layer gates it instead -- see registry.py); the
                # catalog reports that the same way as the explicit "__none__"
                # opt-in, since neither implies a capability requirement.
                capability=required if required is not None else "__none__",
                auth_type=spec.auth_type,
                action_type=_action_type_for_backend(spec.name, required, policy),
                credential_provider=target_to_alias.get(spec.name),
                status=status,
                status_detail=status_detail,
                correlation_id=correlation_id,
                tools=[],
            )
        )
    return CatalogResponse(servers=servers)
