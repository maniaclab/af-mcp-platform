from __future__ import annotations

from typing import Annotated, Any, Literal

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
from af_mcp_broker.identity import Principal, keycloak_dependency
from af_mcp_broker.mcp.registry import BackendRegistry

logger = structlog.get_logger(__name__)

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

    capability: str
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
    """One MCP server visible to the caller post-entitlement filtering.

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


def _action_type_for_capability(capability: str) -> Literal["read", "state_change"]:
    cap = CAPABILITIES.get(capability)
    return cap.action_type if cap else "read"  # type: ignore[return-value]


def _action_type_for_backend(
    target: str, capability: str, policy: EntitlementPolicy
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
    principal: Principal, policy: EntitlementPolicy
) -> list[CapabilityGrant]:
    """Build per-capability grants from the principal's capabilities.

    For each granted capability we list the targets that require it (from
    ``target_capabilities``) and the capability's action type.
    """
    caps = get_principal_capabilities(principal, policy)
    grants: list[CapabilityGrant] = []
    for cap in sorted(caps):
        targets = sorted(
            t for t, req in policy.target_capabilities.items() if req == cap
        )
        grants.append(
            CapabilityGrant(
                capability=cap,
                targets=targets,
                action_types=[_action_type_for_capability(cap)],
            )
        )
    return grants


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
    return CapabilitiesResponse(
        subject=principal.subject, grants=_grants_for(principal, policy)
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
    policy = _get_policy(request)
    allow, reason = check_entitlement(principal, body.capability, body.target, policy)
    action_type = get_action_type(body.target, body.action, policy)
    logger.info(
        "authorize_decision",
        subject=principal.subject,
        capability=body.capability,
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
    caps = get_principal_capabilities(principal, policy)
    target_to_alias = _get_target_to_alias(request)

    servers: list[CatalogServer] = []
    for spec in registry.all_backends():
        required = spec.required_capability
        if required != "__none__" and required not in caps:
            continue
        servers.append(
            CatalogServer(
                name=spec.name,
                display_name=spec.display_name or spec.name,
                description=spec.description,
                capability=required,
                auth_type=spec.auth_type,
                action_type=_action_type_for_backend(spec.name, required, policy),
                credential_provider=target_to_alias.get(spec.name),
                tools=[],
            )
        )
    return CatalogResponse(servers=servers)
