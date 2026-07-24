from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, Literal
from urllib.parse import urlencode

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict

from af_mcp_broker.identity import Principal, keycloak_dependency

if TYPE_CHECKING:
    from af_mcp_broker.config import IdentityProviderConfig
    from af_mcp_broker.credentials import CredentialProvider

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/identities", tags=["identities"])

# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------

# "keycloak-brokered" — Keycloak's stored-broker-token pattern (OIDCProvider);
# "oauth21-direct" — the broker acting as a direct OAuth 2.1 client
# (OAuth21Provider).
ProviderType = Literal["keycloak-brokered", "oauth21-direct"]


class IdentityProvider(BaseModel):
    """One row on the portal's Identities page.

    ``id`` is the ``alias`` configured in ``Settings.identity_providers`` —
    the same value doubles as the portal-facing identifier and the internal
    provider key (issue #66 PR4 — no separate id-to-alias mapping).
    ``link_url`` is always null for a ``keycloak-brokered`` entry: the portal
    re-runs its own client-side ``startIdpLink()`` flow for those (Keycloak's
    ``kc_action=LINK_IDP`` callback only completes via oidc-client-ts's
    locally-stored PKCE/state, so a bare top-level navigation to a
    broker-built URL can't complete it — see docs/auth.md). An
    ``oauth21-direct`` entry carries a full URL to the broker's own
    ``/v1/oauth/authorize/{alias}``, which the portal navigates to directly.
    """

    model_config = ConfigDict(frozen=True)

    id: str
    type: ProviderType
    display_name: str
    # Human-readable description of what linking this provider enables.
    enables: str
    linked: bool
    link_url: str | None


class IdentitiesResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    subject: str
    email: str
    unixname: str
    uid: int
    gid: int
    groups: list[str]
    providers: list[IdentityProvider]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _oauth21_link_url(request: Request, alias: str) -> str:
    """Full URL (the broker's own origin) the portal navigates to in order
    to begin an OAuth 2.1 linking flow — see ``api/oauth21.py``'s
    ``authorize`` route.

    Returned as a full URL rather than a bare path since the portal is
    served from a different origin than the broker (``request.url``/
    ``request.base_url`` report the client-visible scheme+host thanks to the
    proxy-headers middleware in ``app.py``).
    """
    base = str(request.base_url).rstrip("/")
    query = urlencode({"return": "/identities/"})
    return f"{base}/v1/oauth/authorize/{alias}?{query}"


async def _build_providers(
    request: Request, principal: Principal
) -> list[IdentityProvider]:
    """Probe each configured provider's ``is_linked()`` to determine linkage.

    This reflects reality (Keycloak's actual stored-linkage state, or the
    OAuth 2.1 ``TokenStore``'s state) rather than trusting a JWT claim that
    may simply be absent from the token.

    Both the provider instances and their metadata are read from
    ``app.state`` (populated together, in config order, by ``app.py``'s
    lifespan) rather than re-consulting ``Settings`` here — this keeps the
    two in lockstep even if a cached ``Settings`` instance elsewhere in the
    process ever diverges from what was actually wired at startup.
    """
    identity_providers: dict[str, CredentialProvider] = (
        getattr(request.app.state, "identity_providers", None) or {}
    )
    identity_provider_configs: dict[str, IdentityProviderConfig] = (
        getattr(request.app.state, "identity_provider_configs", None) or {}
    )

    providers: list[IdentityProvider] = []
    for alias, provider in identity_providers.items():
        cfg = identity_provider_configs[alias]
        link_url = (
            _oauth21_link_url(request, alias) if cfg.type == "oauth21-direct" else None
        )
        providers.append(
            IdentityProvider(
                id=alias,
                type=cfg.type,
                display_name=cfg.display_name,
                enables=cfg.enables,
                linked=await provider.is_linked(principal),
                link_url=link_url,
            )
        )

    return providers


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("", response_model=IdentitiesResponse, summary="Get caller identity")
async def get_identities(
    request: Request,
    principal: Annotated[Principal, Depends(keycloak_dependency)],
) -> IdentitiesResponse:
    providers = await _build_providers(request, principal)
    return IdentitiesResponse(
        subject=principal.subject,
        email=principal.email,
        unixname=principal.unixname,
        uid=principal.uid,
        gid=principal.gid,
        groups=principal.groups,
        providers=providers,
    )


@router.delete(
    "/link/{provider}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Revoke a linked identity",
)
async def unlink_identity(
    provider: str,
    request: Request,
    principal: Annotated[Principal, Depends(keycloak_dependency)],
) -> None:
    known_ids = set(getattr(request.app.state, "identity_provider_configs", None) or {})
    if provider not in known_ids:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Unknown provider '{provider}'",
        )

    # Full IDP unlink requires Keycloak admin REST API calls (keycloak-
    # brokered) or a TokenStore.delete() (oauth21-direct); neither is wired
    # up yet — surface a clear 501 rather than silently succeeding.
    logger.info(
        "identity_unlink_requested",
        subject=principal.subject,
        provider=provider,
    )
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail=(
            "Identity unlinking is not yet implemented. Use the Keycloak "
            "account console to remove a linked keycloak-brokered account, "
            "or re-link to overwrite a stored OAuth 2.1 token in place."
        ),
    )
