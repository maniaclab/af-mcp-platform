from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, Literal
from urllib.parse import urlencode

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict

from af_mcp_broker.config import Settings, get_settings
from af_mcp_broker.identity import Principal, keycloak_dependency

if TYPE_CHECKING:
    from af_mcp_broker.credentials.oauth21 import OAuth21Provider

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

    Flattens the old ``linked_accounts``/``available_providers`` split into a
    single list with a ``linked`` bool — simpler for the portal to render
    (one list, not two) and uniform across both linking mechanisms. ``id`` is
    the portal-facing stable identifier (a Keycloak-brokered provider id like
    "atlas-iam", or an OAuth 2.1 provider's alias). ``link_url`` may be null
    when the provider has no real backing (a placeholder) or the broker is
    missing the config it would need to build a working link — the portal
    renders no Link button in either case.
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
# Keycloak-brokered provider metadata
# ---------------------------------------------------------------------------


class _KeycloakProviderMeta(BaseModel):
    model_config = ConfigDict(frozen=True)

    display_name: str
    enables: str
    # The Keycloak IdP alias to pass as kc_action=LINK_IDP's `provider_id`,
    # or None for a placeholder with no real backing IdP to link against.
    idp_alias: str | None


def _keycloak_providers(settings: Settings) -> dict[str, _KeycloakProviderMeta]:
    """Keycloak-brokered provider metadata, keyed by portal-facing id.

    "atlas-iam"'s ``idp_alias`` is ``settings.oidc_idp_alias`` rather than a
    literal so it always matches whichever alias ``OIDCProvider`` is actually
    configured to probe.
    """
    return {
        "atlas-iam": _KeycloakProviderMeta(
            display_name="ATLAS IAM",
            enables="VOMS proxy generation and grid certificate credential brokering",
            idp_alias=settings.oidc_idp_alias,
        ),
        "cern": _KeycloakProviderMeta(
            display_name="CERN SSO",
            enables="CERN resource access and CMS/ATLAS experiment datasets",
            # No dedicated credential provider exists for CERN SSO yet, so
            # there is no Keycloak IdP alias to link against — always a
            # placeholder (see _keycloak_link_url).
            idp_alias=None,
        ),
    }


def _keycloak_link_url(settings: Settings, idp_alias: str | None) -> str | None:
    """Build the Keycloak ``kc_action=LINK_IDP`` URL for a keycloak-brokered
    provider — computed broker-side (mirroring what
    ``portal/src/lib/auth.ts::startIdpLink()`` builds client-side) so the
    portal doesn't need Keycloak details to render a Link button.

    Returns None when there's no real IdP to link against (*idp_alias* is
    None) or ``settings.identities_link_client_id`` is unset — the broker
    admits it can't help and the portal renders no Link button.
    """
    if idp_alias is None or not settings.identities_link_client_id:
        return None
    redirect_uri = f"{settings.portal_url.rstrip('/')}/callback"
    query = urlencode(
        {
            "client_id": settings.identities_link_client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": "openid",
            "kc_action": "LINK_IDP",
            "provider_id": idp_alias,
            "prompt": "login",
        }
    )
    return f"{settings.oidc_issuer.rstrip('/')}/protocol/openid-connect/auth?{query}"


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
    request: Request, principal: Principal, settings: Settings
) -> list[IdentityProvider]:
    """Probe each configured provider's ``is_linked()`` to determine linkage.

    This reflects reality (Keycloak's actual stored-linkage state, or the
    OAuth 2.1 ``TokenStore``'s state) rather than trusting a JWT claim that
    may simply be absent from the token.
    """
    providers: list[IdentityProvider] = []

    # --- Keycloak-brokered providers. Only "atlas-iam" has a real backing
    # CredentialProvider (OIDCProvider) today — "cern" is a placeholder with
    # no is_linked() to probe, so it always reports unlinked.
    oidc_provider = getattr(request.app.state, "oidc_provider", None)
    for provider_id, meta in _keycloak_providers(settings).items():
        linked = (
            provider_id == "atlas-iam"
            and oidc_provider is not None
            and await oidc_provider.is_linked(principal)
        )
        providers.append(
            IdentityProvider(
                id=provider_id,
                type="keycloak-brokered",
                display_name=meta.display_name,
                enables=meta.enables,
                linked=linked,
                link_url=_keycloak_link_url(settings, meta.idp_alias),
            )
        )

    # --- OAuth 2.1-direct providers. Metadata (display_name/enables) comes
    # from settings.oauth21_providers; the live provider instance (for
    # is_linked()) comes from app.state, keyed the same way.
    oauth21_providers: dict[str, OAuth21Provider] = (
        getattr(request.app.state, "oauth21_providers", None) or {}
    )
    oauth21_meta = {cfg.alias: cfg for cfg in settings.oauth21_providers}
    for alias, provider in oauth21_providers.items():
        cfg = oauth21_meta.get(alias)
        providers.append(
            IdentityProvider(
                id=alias,
                type="oauth21-direct",
                display_name=cfg.display_name if cfg else alias,
                enables=cfg.enables if cfg else "",
                linked=await provider.is_linked(principal),
                link_url=_oauth21_link_url(request, alias),
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
    settings: Annotated[Settings, Depends(get_settings)],
) -> IdentitiesResponse:
    providers = await _build_providers(request, principal, settings)
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
    principal: Annotated[Principal, Depends(keycloak_dependency)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> None:
    known_ids = set(_keycloak_providers(settings)) | {
        cfg.alias for cfg in settings.oauth21_providers
    }
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
