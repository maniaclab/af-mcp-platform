from __future__ import annotations

from typing import Any, Literal

import structlog
from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, ConfigDict

from af_mcp_broker.authorization import (
    CAPABILITIES,
    EntitlementPolicy,
    _get_action_type,
    check_entitlement,
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


class CatalogTool(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str
    backend: str
    description: str
    capability: str
    action_type: Literal["read", "state_change"]


class CatalogResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    tools: list[CatalogTool]


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


def _action_type_for_capability(capability: str) -> Literal["read", "state_change"]:
    cap = CAPABILITIES.get(capability)
    return cap.action_type if cap else "read"  # type: ignore[return-value]


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
    principal: Principal = Depends(keycloak_dependency),
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
    principal: Principal = Depends(keycloak_dependency),
) -> AuthorizeResponse:
    policy = _get_policy(request)
    allow, reason = check_entitlement(principal, body.capability, body.target, policy)
    action_type = _get_action_type(body.target, body.action, policy)
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
    summary="List visible tools post-entitlement filtering",
)
async def get_catalog(
    request: Request,
    principal: Principal = Depends(keycloak_dependency),
) -> CatalogResponse:
    policy = _get_policy(request)
    registry = _get_registry(request)
    caps = get_principal_capabilities(principal, policy)

    tools: list[CatalogTool] = []
    for spec in registry.all_backends():
        required = spec.required_capability
        if required != "__none__" and required not in caps:
            continue
        tools.append(
            CatalogTool(
                name=spec.prefix,
                backend=spec.name,
                description="",
                capability=required,
                action_type=_action_type_for_capability(required),
            )
        )
    return CatalogResponse(tools=tools)
