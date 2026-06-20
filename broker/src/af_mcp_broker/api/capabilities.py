from __future__ import annotations

import fnmatch
from typing import Any, Literal

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict

from af_mcp_broker.identity import Principal, keycloak_dependency

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
    action: str
    context: dict[str, Any] = {}


class AuthorizeResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    allow: bool
    reason: str
    obligations: list[str]


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
# Authorization logic — thin wrapper around the policy engine loaded at startup.
# ---------------------------------------------------------------------------


def check_entitlement(
    principal: Principal,
    capability: str,
    target: str,
    action: str,
    policy: dict[str, Any],
) -> AuthorizeResponse:
    """Evaluate a single capability/target/action triple against the loaded policy.

    The policy dict is expected to contain a top-level "rules" list where each
    entry is:

        - capability: <str>
          targets: ["*"] | [<glob>, ...]
          actions: ["*"] | [<str>, ...]
          groups: ["*"] | [<group>, ...]
          obligations: [<str>, ...]

    Returns deny-by-default when no rule matches.
    """
    rules: list[dict[str, Any]] = policy.get("rules", [])

    caller_groups = set(principal.groups)

    for rule in rules:
        if rule.get("capability") != capability:
            continue

        # Target match
        targets: list[str] = rule.get("targets", [])
        if not any(fnmatch.fnmatch(target, t) for t in targets):
            continue

        # Action match
        actions: list[str] = rule.get("actions", [])
        if "*" not in actions and action not in actions:
            continue

        # Group membership match
        allowed_groups: list[str] = rule.get("groups", [])
        if "*" not in allowed_groups and not caller_groups.intersection(allowed_groups):
            continue

        obligations: list[str] = rule.get("obligations", [])
        return AuthorizeResponse(
            allow=True,
            reason=f"Matched rule for capability '{capability}'",
            obligations=obligations,
        )

    return AuthorizeResponse(
        allow=False,
        reason=f"No policy rule grants '{action}' on '{target}' for capability '{capability}'",
        obligations=[],
    )


def _get_grants(
    principal: Principal, policy: dict[str, Any]
) -> list[CapabilityGrant]:
    """Collect all capability grants for the caller from the policy."""
    caller_groups = set(principal.groups)
    # Aggregate per-capability targets and action_types.
    grants: dict[str, dict[str, Any]] = {}

    for rule in policy.get("rules", []):
        cap: str = rule.get("capability", "")
        if not cap:
            continue

        allowed_groups: list[str] = rule.get("groups", [])
        if "*" not in allowed_groups and not caller_groups.intersection(allowed_groups):
            continue

        entry = grants.setdefault(cap, {"targets": set(), "action_types": set()})
        entry["targets"].update(rule.get("targets", []))
        for action in rule.get("actions", []):
            # Classify actions coarsely: reads are non-mutating
            if action in {"read", "get", "list", "*"}:
                entry["action_types"].add("read")
            else:
                entry["action_types"].add("state_change")

    return [
        CapabilityGrant(
            capability=cap,
            targets=sorted(v["targets"]),
            action_types=sorted(v["action_types"]),  # type: ignore[arg-type]
        )
        for cap, v in grants.items()
    ]


def _filter_catalog(
    principal: Principal,
    backends: list[dict[str, Any]],
    policy: dict[str, Any],
) -> list[CatalogTool]:
    """Return tools from backends that the principal is entitled to see."""
    result: list[CatalogTool] = []
    grants = _get_grants(principal, policy)
    granted_caps = {g.capability for g in grants}

    for backend in backends:
        backend_name: str = backend.get("name", "")
        for tool in backend.get("tools", []):
            cap: str = tool.get("capability", "")
            if cap not in granted_caps:
                continue
            result.append(
                CatalogTool(
                    name=tool.get("name", ""),
                    backend=backend_name,
                    description=tool.get("description", ""),
                    capability=cap,
                    action_type=tool.get("action_type", "read"),
                )
            )
    return result


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
    policy: dict[str, Any] = getattr(request.app.state, "policy", {})
    grants = _get_grants(principal, policy)
    return CapabilitiesResponse(subject=principal.subject, grants=grants)


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
    policy: dict[str, Any] = getattr(request.app.state, "policy", {})
    result = check_entitlement(
        principal, body.capability, body.target, body.action, policy
    )
    logger.info(
        "authorize_decision",
        subject=principal.subject,
        capability=body.capability,
        target=body.target,
        action=body.action,
        allow=result.allow,
        reason=result.reason,
    )
    return result


@router.get(
    "/catalog",
    response_model=CatalogResponse,
    summary="List visible tools post-entitlement filtering",
)
async def get_catalog(
    request: Request,
    principal: Principal = Depends(keycloak_dependency),
) -> CatalogResponse:
    policy: dict[str, Any] = getattr(request.app.state, "policy", {})
    backends: list[dict[str, Any]] = getattr(request.app.state, "backends", [])
    tools = _filter_catalog(principal, backends, policy)
    return CatalogResponse(tools=tools)
