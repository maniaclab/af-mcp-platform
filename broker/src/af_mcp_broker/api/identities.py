from __future__ import annotations

from typing import Annotated

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict

from af_mcp_broker.identity import Principal, keycloak_dependency

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/identities", tags=["identities"])

# ---------------------------------------------------------------------------
# Response / request models
# ---------------------------------------------------------------------------


class LinkedAccount(BaseModel):
    model_config = ConfigDict(frozen=True)

    provider: str
    sub: str


class AvailableProvider(BaseModel):
    model_config = ConfigDict(frozen=True)

    provider: str
    display_name: str
    # Human-readable description of what linking this provider enables.
    enables: str


class IdentitiesResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    subject: str
    email: str
    unixname: str
    uid: int
    gid: int
    groups: list[str]
    linked_accounts: list[LinkedAccount]
    available_providers: list[AvailableProvider]


# ---------------------------------------------------------------------------
# Known provider metadata
# ---------------------------------------------------------------------------

_PROVIDERS: dict[str, AvailableProvider] = {
    "atlas-iam": AvailableProvider(
        provider="atlas-iam",
        display_name="ATLAS IAM",
        enables="VOMS proxy generation and grid certificate credential brokering",
    ),
    "cern": AvailableProvider(
        provider="cern",
        display_name="CERN SSO",
        enables="CERN resource access and CMS/ATLAS experiment datasets",
    ),
}


async def _build_linked_accounts(
    request: Request, principal: Principal
) -> list[LinkedAccount]:
    """Probe each configured provider's ``is_linked()`` to determine linkage.

    This reflects reality (Keycloak's actual stored-linkage state) rather
    than trusting a JWT claim that may simply be absent from the token.

    Only "atlas-iam" is backed by a real provider today (``OIDCProvider``,
    which owns the Keycloak stored-brokered-token check). "cern" remains in
    ``_PROVIDERS`` as a not-yet-linkable placeholder — there is no dedicated
    credential provider for it yet, so it can never appear in
    ``linked_accounts`` until one exists.
    """
    accounts: list[LinkedAccount] = []
    oidc_provider = getattr(request.app.state, "oidc_provider", None)
    if oidc_provider is not None and await oidc_provider.is_linked(principal):
        # is_linked() only reports True/False — it has no federated `sub`
        # claim to surface, so this is intentionally empty (the portal
        # already treats an empty/missing `sub` as "no subject to display").
        accounts.append(LinkedAccount(provider="atlas-iam", sub=""))
    return accounts


def _available_to_link(linked: list[LinkedAccount]) -> list[AvailableProvider]:
    linked_ids = {a.provider for a in linked}
    return [p for pid, p in _PROVIDERS.items() if pid not in linked_ids]


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("", response_model=IdentitiesResponse, summary="Get caller identity")
async def get_identities(
    request: Request,
    principal: Annotated[Principal, Depends(keycloak_dependency)],
) -> IdentitiesResponse:
    linked = await _build_linked_accounts(request, principal)
    return IdentitiesResponse(
        subject=principal.subject,
        email=principal.email,
        unixname=principal.unixname,
        uid=principal.uid,
        gid=principal.gid,
        groups=principal.groups,
        linked_accounts=linked,
        available_providers=_available_to_link(linked),
    )


@router.delete(
    "/link/{provider}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Revoke a linked identity",
)
async def unlink_identity(
    provider: str,
    principal: Annotated[Principal, Depends(keycloak_dependency)],
) -> None:
    if provider not in _PROVIDERS:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Unknown provider '{provider}'",
        )

    # Full IDP unlink requires Keycloak admin REST API calls. That integration
    # is deferred — surface a clear 501 rather than silently succeeding.
    logger.info(
        "identity_unlink_requested",
        subject=principal.subject,
        provider=provider,
    )
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail=(
            "Identity unlinking via admin API is not yet implemented. "
            "Use the Keycloak account console to remove linked accounts."
        ),
    )
