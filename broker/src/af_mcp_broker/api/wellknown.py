from __future__ import annotations

from typing import cast

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict

from af_mcp_broker.config import Settings

# Not mounted under /v1 — CIMD is served at the well-known root path required
# by draft-ietf-oauth-client-id-metadata-document, not the broker's own API
# boundary. Registered directly on the app in app.py.
router = APIRouter(tags=["wellknown"])


def _require_settings(request: Request) -> Settings:
    return cast("Settings", getattr(request.app.state, "settings", None)) or Settings()


def _require_public_origin(settings: Settings) -> str:
    if not settings.broker_public_origin:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="MCP OAuth discovery metadata is not configured",
        )
    return settings.broker_public_origin.rstrip("/")


class CimdResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    client_id: str
    client_name: str
    redirect_uris: list[str]
    token_endpoint_auth_method: str
    grant_types: list[str]
    response_types: list[str]
    scope: str


@router.get(
    "/.well-known/cimd",
    response_model=CimdResponse,
    summary="Client ID Metadata Document",
)
async def get_cimd(request: Request) -> CimdResponse:
    """Serve the broker's CIMD (draft-ietf-oauth-client-id-metadata-document).

    Unauthenticated by design — CIMD documents are public per spec, fetched by
    backend OAuth 2.1 authorization servers to identify this client without
    per-backend Dynamic Client Registration. ``client_id`` is self-referential:
    it must equal the exact URL the client used to fetch this document, so it
    is read from the incoming request rather than hardcoded.
    """
    settings: Settings = (
        cast("Settings", getattr(request.app.state, "settings", None)) or Settings()
    )

    public_origin = settings.broker_public_origin.rstrip("/")
    redirect_uris = [
        f"{public_origin}/v1/oauth/callback/{p.alias}"
        for p in settings.identity_providers
        if p.type == "oauth21-direct"
    ]

    return CimdResponse(
        client_id=str(request.url),
        client_name=settings.cimd_client_name,
        redirect_uris=redirect_uris,
        token_endpoint_auth_method="none",
        grant_types=["authorization_code", "refresh_token"],
        response_types=["code"],
        scope="openid profile email",
    )


# ---------------------------------------------------------------------------
# MCP OAuth discovery (issue #140): RFC 9728 protected-resource metadata and
# RFC 8414 authorization-server metadata, both naming the broker itself as
# the authorization server -- see api/mcp_oauth.py's module docstring for why
# ("the broker is not an authorization server in the identity sense", issue
# #144's resolution). An early comment on #140 had this metadata point at
# the Keycloak realm instead; that was superseded before implementation.
# ---------------------------------------------------------------------------


class ProtectedResourceMetadataResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    resource: str
    authorization_servers: list[str]


class AuthorizationServerMetadataResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    response_types_supported: list[str]
    grant_types_supported: list[str]
    code_challenge_methods_supported: list[str]
    token_endpoint_auth_methods_supported: list[str]
    # draft-ietf-oauth-client-id-metadata-document -- advertises that MCP
    # clients register with the broker via CIMD rather than DCR or a
    # pre-registered client_id (issue #140's settled client-registration
    # decision; mirrors rucio-mcp's own AS metadata augmentation).
    client_id_metadata_document_supported: bool


def _protected_resource_metadata(request: Request) -> ProtectedResourceMetadataResponse:
    settings = _require_settings(request)
    origin = _require_public_origin(settings)
    return ProtectedResourceMetadataResponse(
        resource=f"{origin}/mcp",
        authorization_servers=[origin],
    )


@router.get(
    "/.well-known/oauth-protected-resource",
    response_model=ProtectedResourceMetadataResponse,
    summary="RFC 9728 protected-resource metadata (root form)",
)
async def get_protected_resource_metadata_root(
    request: Request,
) -> ProtectedResourceMetadataResponse:
    """Serve RFC 9728 metadata at the root well-known path.

    MCP clients try both this path and the ``/mcp``-suffixed form below (the
    installed mcp SDK's own discovery helper,
    ``build_protected_resource_metadata_discovery_urls``, falls back to this
    root form when the ``/mcp``-suffixed one isn't reachable) -- serve
    identical content at both rather than pick one.
    """
    return _protected_resource_metadata(request)


@router.get(
    "/.well-known/oauth-protected-resource/mcp",
    response_model=ProtectedResourceMetadataResponse,
    summary="RFC 9728 protected-resource metadata (/mcp-suffixed form)",
)
async def get_protected_resource_metadata_mcp(
    request: Request,
) -> ProtectedResourceMetadataResponse:
    """Serve RFC 9728 metadata at the path RFC 9728 §3.1 actually specifies for a resource at ``/mcp`` (insert ``/.well-known/oauth-protected-resource`` between host and resource path) -- see ``get_protected_resource_metadata_root``'s docstring for why both forms are served."""
    return _protected_resource_metadata(request)


@router.get(
    "/.well-known/oauth-authorization-server",
    response_model=AuthorizationServerMetadataResponse,
    summary="RFC 8414 authorization-server metadata for the broker's own /authorize and /token",
)
async def get_authorization_server_metadata(
    request: Request,
) -> AuthorizationServerMetadataResponse:
    """Describe the broker's own ``/v1/oauth/authorize``/``/v1/oauth/token`` (api/mcp_oauth.py).

    Unauthenticated by design, like every other well-known document here --
    an MCP client must be able to fetch this before it has any credential at
    all.
    """
    settings = _require_settings(request)
    origin = _require_public_origin(settings)
    return AuthorizationServerMetadataResponse(
        issuer=origin,
        authorization_endpoint=f"{origin}/v1/oauth/authorize",
        token_endpoint=f"{origin}/v1/oauth/token",
        response_types_supported=["code"],
        grant_types_supported=["authorization_code"],
        code_challenge_methods_supported=["S256"],
        token_endpoint_auth_methods_supported=["none"],
        client_id_metadata_document_supported=True,
    )
