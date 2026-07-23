from __future__ import annotations

from typing import cast

from fastapi import APIRouter, Request
from pydantic import BaseModel, ConfigDict

from af_mcp_broker.config import Settings

# Not mounted under /v1 — CIMD is served at the well-known root path required
# by draft-ietf-oauth-client-id-metadata-document, not the broker's own API
# boundary. Registered directly on the app in app.py.
router = APIRouter(tags=["wellknown"])


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
    """Serves the broker's CIMD (draft-ietf-oauth-client-id-metadata-document).

    Unauthenticated by design — CIMD documents are public per spec, fetched by
    backend OAuth 2.1 authorization servers to identify this client without
    per-backend Dynamic Client Registration. ``client_id`` is self-referential:
    it must equal the exact URL the client used to fetch this document, so it
    is read from the incoming request rather than hardcoded.
    """
    settings: Settings = (
        cast("Settings", getattr(request.app.state, "settings", None)) or Settings()
    )

    issuer = settings.oidc_issuer.rstrip("/")
    redirect_uris = [
        f"{issuer}/broker/{alias}/endpoint" for alias in settings.cimd_idp_aliases
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
