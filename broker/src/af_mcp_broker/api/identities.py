from __future__ import annotations

from typing import Annotated
from urllib.parse import urlencode

import structlog
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict

from af_mcp_broker.config import Settings, get_settings
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


class LinkIdentityRequest(BaseModel):
    model_config = ConfigDict(frozen=True)

    provider: str


class LinkIdentityResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    redirect_url: str


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


def _build_linked_accounts(principal: Principal) -> list[LinkedAccount]:
    accounts: list[LinkedAccount] = []
    if principal.iam_sub:
        accounts.append(LinkedAccount(provider="atlas-iam", sub=principal.iam_sub))
    if principal.cern_sub:
        accounts.append(LinkedAccount(provider="cern", sub=principal.cern_sub))
    return accounts


def _available_to_link(linked: list[LinkedAccount]) -> list[AvailableProvider]:
    linked_ids = {a.provider for a in linked}
    return [p for pid, p in _PROVIDERS.items() if pid not in linked_ids]


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("", response_model=IdentitiesResponse, summary="Get caller identity")
async def get_identities(
    principal: Annotated[Principal, Depends(keycloak_dependency)],
) -> IdentitiesResponse:
    linked = _build_linked_accounts(principal)
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


@router.post(
    "/link",
    response_model=LinkIdentityResponse,
    summary="Initiate identity linking",
)
async def link_identity(
    body: LinkIdentityRequest,
    principal: Annotated[Principal, Depends(keycloak_dependency)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> LinkIdentityResponse:
    if body.provider not in _PROVIDERS:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Unknown provider '{body.provider}'. "
            f"Available: {list(_PROVIDERS.keys())}",
        )

    # Application-initiated action: a full OIDC auth request with
    # kc_action=LINK_IDP. Keycloak rejects the request without client_id,
    # redirect_uri, response_type, and scope. provider_id must be the
    # Keycloak IdP alias, which for ATLAS differs from the public name.
    alias = settings.oidc_idp_alias if body.provider == "atlas-iam" else body.provider
    base = settings.oidc_issuer.rstrip("/")
    params = urlencode(
        {
            "client_id": settings.oidc_audience,
            "redirect_uri": f"{settings.portal_url.rstrip('/')}/identities",
            "response_type": "code",
            "scope": "openid",
            "kc_action": "LINK_IDP",
            "provider_id": alias,
        }
    )
    redirect_url = f"{base}/protocol/openid-connect/auth?{params}"

    logger.info(
        "identity_link_initiated",
        subject=principal.subject,
        provider=body.provider,
    )
    return LinkIdentityResponse(redirect_url=redirect_url)


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
