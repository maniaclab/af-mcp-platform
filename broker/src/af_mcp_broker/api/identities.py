from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Annotated, Literal
from urllib.parse import urlencode

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict

from af_mcp_broker.authorization import is_admin
from af_mcp_broker.config import get_settings
from af_mcp_broker.credentials import OIDCProvider, X509Provider
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
# (OAuth21Provider); "broker-issued" — the broker signing its own AF Broker
# Identity Tokens for AF-native backends (BrokerIssuedProvider, issue #162);
# "condor-token" — HTCondor IDTOKENs exchanged at condor-token-service
# (CondorTokenProvider, issue #169). The native entries (broker-issued,
# condor-token) are always `linked` with no `link_url`: the broker is
# authoritative, there is no linking step and no portal action.
# "x509" — X509Provider (grid certificate / VOMS proxy), an ordinary
# `identity_providers` entry: every `auth_type: x509` backend must be
# covered by an explicit entry (app.py's lifespan refuses to start
# otherwise), so this row is always registry-sourced.
ProviderType = Literal[
    "keycloak-brokered", "oauth21-direct", "broker-issued", "condor-token", "x509"
]

# How the portal starts a linking flow for an entry: "redirect" — a browser
# navigation (keycloak-brokered's client-side startIdpLink() flow, or
# oauth21-direct's `link_url`); "passphrase" — an in-portal form that POSTs
# the user's Globus passphrase to /v1/x509/proxy (x509 only — there is no
# URL to redirect to, so this is deliberately a distinct mechanism rather
# than an overloaded `link_url`); "none" — no linking step exists
# (broker-issued, condor-token: the broker is authoritative).
LinkMechanism = Literal["redirect", "passphrase", "none"]

_LINK_MECHANISM_BY_TYPE: dict[str, LinkMechanism] = {
    "keycloak-brokered": "redirect",
    "oauth21-direct": "redirect",
    "broker-issued": "none",
    "condor-token": "none",
    "x509": "passphrase",
}


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
    An ``x509`` entry carries no ``link_url`` either — its
    ``link_mechanism`` is ``"passphrase"``: the portal renders an in-page
    form that POSTs the user's Globus passphrase to ``/v1/x509/proxy``.
    """

    model_config = ConfigDict(frozen=True)

    id: str
    type: ProviderType
    display_name: str
    # Human-readable description of what linking this provider enables.
    enables: str
    linked: bool
    link_url: str | None
    link_mechanism: LinkMechanism
    # Expiry (ISO-8601) of the caller's x509/VOMS proxy — populated only on
    # "x509" entries. In voms-token-service mode the Vault record is
    # authoritative (the same probe that decides `linked`); legacy mode
    # falls back to the in-memory ProxyMeta GET /v1/x509/proxy/status serves.
    # Null on every other entry, and on an x509 entry with no valid proxy.
    proxy_expires_at: str | None = None
    # Custody mode of an x509 entry's link (X509Provider.link_status):
    # "auto-renew" — the Globus passphrase is stored in Vault, proxies
    # re-mint hands-free; "until-expiry" — only the proxy is stored (the
    # user declined passphrase custody at link time), so the link lasts
    # exactly as long as proxy_expires_at. Null when not linked, on legacy
    # x509 entries (filesystem linkage has no custody concept), and on
    # every non-x509 entry.
    x509_link_mode: Literal["auto-renew", "until-expiry"] | None = None
    # True only for a "keycloak-brokered" entry whose last link_status()
    # probe got a 403 from Keycloak's stored-broker-token endpoint -- the
    # caller's own access token lacks the `read-token` client role Keycloak
    # requires there (see docs/auth.md's "Required Keycloak role" section),
    # distinct from an ordinary not-yet-linked `linked=False`. A user in
    # this state may have already completed the IdP linking flow and would
    # otherwise see an indistinguishable "not linked" with no indication
    # that a missing role, not a missing link, is the actual blocker.
    # Always False for every other provider type.
    link_permission_denied: bool = False


class IdentitiesResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    subject: str
    email: str
    # POSIX identity is optional (issue #148) -- null on the portal's
    # Identities page for a principal whose account has no filesystem/grid
    # identity, rather than the request failing outright.
    unixname: str | None
    uid: int | None
    gid: int | None
    groups: list[str]
    providers: list[IdentityProvider]
    # True when the caller is a member of Settings.admin_group -- gates the
    # portal's Admin nav entry and admin-only views. False whenever
    # admin_group is unconfigured.
    is_admin: bool


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _oauth21_link_url(request: Request, alias: str) -> str:
    """Full URL (the broker's own origin) the portal navigates to in order to begin an OAuth 2.1 linking flow — see ``api/oauth21.py``'s ``authorize`` route.

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
        link_permission_denied = False
        if isinstance(provider, X509Provider):
            # One probe answers linked + custody mode + expiry together. In
            # service mode the Vault record is authoritative for the expiry;
            # legacy mode reports no proxy_not_after, so fall back to the
            # in-memory ProxyMeta GET /v1/x509/proxy/status serves.
            x509_status = await provider.link_status(principal)
            linked = x509_status.linked
            x509_link_mode = x509_status.mode
            if x509_status.proxy_not_after is not None:
                proxy_expires_at = datetime.fromtimestamp(
                    x509_status.proxy_not_after, tz=UTC
                ).isoformat()
            elif provider.uses_voms_service:
                # Vault answered "no valid proxy" — a stale in-memory meta
                # must not override the authoritative store.
                proxy_expires_at = None
            else:
                proxy_expires_at = _x509_proxy_expires_at(request, principal, cfg)
        elif isinstance(provider, OIDCProvider):
            oidc_status = await provider.link_status(principal)
            linked = oidc_status.linked
            link_permission_denied = oidc_status.permission_denied
            x509_link_mode = None
            proxy_expires_at = None
        else:
            linked = await provider.is_linked(principal)
            x509_link_mode = None
            proxy_expires_at = None
        providers.append(
            IdentityProvider(
                id=alias,
                type=cfg.type,
                display_name=cfg.display_name,
                enables=cfg.enables,
                linked=linked,
                link_url=link_url,
                link_mechanism=_LINK_MECHANISM_BY_TYPE[cfg.type],
                proxy_expires_at=proxy_expires_at,
                x509_link_mode=x509_link_mode,
                link_permission_denied=link_permission_denied,
            )
        )

    return providers


def _x509_proxy_expires_at(
    request: Request, principal: Principal, cfg: IdentityProviderConfig
) -> str | None:
    """Expiry of the caller's cached VOMS proxy for an x509 entry, or None.

    Read from the in-memory ``ProxyMeta`` of the entry's FIRST target — the
    same default ``GET /v1/x509/proxy/status`` resolves to — so it stays a
    cheap in-process lookup (no Vault round trip). Always None for non-x509
    entries, and for an x509 entry with nothing cached.
    """
    if cfg.type != "x509" or not cfg.targets:
        return None
    credential_cache = getattr(request.app.state, "credential_cache", None)
    if credential_cache is None:
        return None
    meta = credential_cache.get_proxy_meta(principal.subject, cfg.targets[0])
    if meta is None:
        return None
    return datetime.fromtimestamp(meta.not_after, tz=UTC).isoformat()


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("", response_model=IdentitiesResponse, summary="Get caller identity")
async def get_identities(
    request: Request,
    principal: Annotated[Principal, Depends(keycloak_dependency)],
) -> IdentitiesResponse:
    providers = await _build_providers(request, principal)
    settings = getattr(request.app.state, "settings", None) or get_settings()
    return IdentitiesResponse(
        subject=principal.subject,
        email=principal.email,
        unixname=principal.unixname,
        uid=principal.uid,
        gid=principal.gid,
        groups=principal.groups,
        providers=providers,
        is_admin=is_admin(principal, settings),
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
    identity_provider_configs: dict[str, IdentityProviderConfig] = (
        getattr(request.app.state, "identity_provider_configs", None) or {}
    )
    cfg = identity_provider_configs.get(provider)
    if cfg is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"Unknown provider '{provider}'",
        )

    if cfg.type == "oauth21-direct":
        identity_providers: dict[str, CredentialProvider] = (
            getattr(request.app.state, "identity_providers", None) or {}
        )
        await identity_providers[provider].revoke(principal, provider)

        credential_cache = getattr(request.app.state, "credential_cache", None)
        if credential_cache is not None:
            for target in cfg.targets:
                await credential_cache.revoke(principal.subject, target)

        logger.info(
            "identity_unlink_completed",
            subject=principal.subject,
            provider=provider,
        )
        return

    # Keycloak-brokered unlink requires the Keycloak Admin REST API
    # (DELETE /admin/realms/{realm}/users/{id}/federated-identity/{alias}),
    # which the broker doesn't hold credentials for — surface a clear 501
    # rather than silently succeeding. Out of scope per issue #86.
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
