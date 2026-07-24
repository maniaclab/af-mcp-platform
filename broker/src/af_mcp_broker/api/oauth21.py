from __future__ import annotations

from typing import TYPE_CHECKING, Annotated
from urllib.parse import urlencode

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import RedirectResponse

from af_mcp_broker.config import Settings, get_settings
from af_mcp_broker.credentials.oauth21 import (
    OAuth21Provider,
    TokenStore,
    VersionConflict,
    normalize_token_response,
)
from af_mcp_broker.http import get_http_client
from af_mcp_broker.identity import Principal, keycloak_dependency
from af_mcp_broker.oauth_state import (
    NONCE_COOKIE_NAME,
    NONCE_COOKIE_PATH,
    STATE_TOKEN_TTL_SECONDS,
    StateTokenError,
    build_state_token,
    decrypt_state_token,
    generate_nonce,
    generate_pkce_pair,
    sanitize_return_url,
)

if TYPE_CHECKING:
    from cryptography.fernet import Fernet
    from fastapi import Response

log = structlog.get_logger(__name__)

router = APIRouter(tags=["oauth21"])


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _oauth21_providers(request: Request) -> dict[str, OAuth21Provider]:
    providers = getattr(request.app.state, "oauth21_providers", None)
    if not providers:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="No OAuth 2.1 providers are configured",
        )
    return providers


def _resolve_provider(request: Request, alias: str) -> OAuth21Provider:
    provider = _oauth21_providers(request).get(alias)
    if provider is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Unknown OAuth 2.1 provider alias {alias!r}",
        )
    return provider


def _token_store(request: Request) -> TokenStore:
    store = getattr(request.app.state, "oauth21_token_store", None)
    if store is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="OAuth 2.1 token store is not configured",
        )
    return store


def _state_cipher(request: Request) -> Fernet:
    cipher = getattr(request.app.state, "oauth21_state_cipher", None)
    if cipher is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="OAuth 2.1 state encryption is not configured",
        )
    return cipher


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get(
    "/oauth/authorize/{alias}",
    summary="Begin an OAuth 2.1 account-linking flow",
)
async def authorize(
    alias: str,
    request: Request,
    principal: Annotated[Principal, Depends(keycloak_dependency)],
    settings: Annotated[Settings, Depends(get_settings)],
    return_path: Annotated[str | None, Query(alias="return")] = None,
) -> Response:
    """Redirect the browser to *alias*'s backend authorization server.

    Generates a PKCE verifier/challenge pair and a random nonce, encrypts
    them (plus the initiating principal's subject and the sanitized return
    path) into the ``state`` parameter, sets the nonce as an HttpOnly cookie,
    and 302s to the backend's ``authorization_endpoint``.
    """
    provider = _resolve_provider(request, alias)

    try:
        return_url = sanitize_return_url(return_path)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc

    verifier, challenge = generate_pkce_pair()
    nonce = generate_nonce()
    state = build_state_token(
        _state_cipher(request),
        iss=settings.oauth21_effective_state_issuer,
        sub=principal.subject,
        alias=alias,
        pkce_verifier=verifier,
        return_url=return_url,
        nonce=nonce,
    )

    redirect_uri = str(request.url_for("oauth21_callback", alias=alias))
    query = urlencode(
        {
            "client_id": settings.oauth21_client_id,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": state,
            "redirect_uri": redirect_uri,
            "scope": provider.scope,
            "response_type": "code",
        }
    )

    response = RedirectResponse(
        url=f"{provider.authorization_endpoint}?{query}",
        status_code=status.HTTP_302_FOUND,
    )
    response.set_cookie(
        NONCE_COOKIE_NAME,
        nonce,
        max_age=STATE_TOKEN_TTL_SECONDS,
        httponly=True,
        secure=True,
        samesite="lax",
        path=NONCE_COOKIE_PATH,
    )
    return response


@router.get(
    "/oauth/callback/{alias}",
    name="oauth21_callback",
    summary="Complete an OAuth 2.1 account-linking flow",
)
async def callback(
    alias: str,
    code: str,
    state: str,
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
) -> Response:
    """Receive the authorization code from a backend AS and store the
    resulting token pair.

    Unlike every other ``/v1`` route, this one carries no ``Authorization:
    Bearer`` header and is **not** gated by ``keycloak_dependency``. It
    cannot be: the redirect back from a third-party authorization server has
    no way to attach the user's Keycloak bearer token, and the browser may
    land here in a context that never held one. Per issue #66's state-token
    design, this route authenticates *continuity of an already-authenticated
    flow*, not the user directly — possession of a ``state`` token that
    decrypts under the broker's own key, has not expired, is self-audienced
    (``iss == aud`` == this deployment), and whose embedded nonce matches the
    ``oauth_state_nonce`` cookie set by ``/v1/oauth/authorize/{alias}`` in
    the same browser together prove this callback continues a flow that
    *was* authenticated at authorize-time. It is not an authentication
    endpoint in its own right.
    """
    provider = _resolve_provider(request, alias)

    cookie_nonce = request.cookies.get(NONCE_COOKIE_NAME)
    if cookie_nonce is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing OAuth state nonce cookie",
        )

    try:
        payload = decrypt_state_token(
            _state_cipher(request),
            state,
            expected_iss=settings.oauth21_effective_state_issuer,
        )
    except StateTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc

    if payload.nonce != cookie_nonce:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="OAuth state nonce does not match cookie",
        )
    if payload.alias != alias:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="OAuth state alias does not match callback URL",
        )

    redirect_uri = str(request.url_for("oauth21_callback", alias=alias))
    resp = await get_http_client().post(
        provider.token_endpoint,
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "code_verifier": payload.pkce_verifier,
            "client_id": settings.oauth21_client_id,
        },
        timeout=10.0,
    )
    if resp.status_code >= status.HTTP_400_BAD_REQUEST:
        log.warning(
            "oauth21.callback.token_exchange_failed",
            alias=alias,
            status_code=resp.status_code,
        )
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Backend authorization server rejected the token exchange",
        )

    cred = normalize_token_response(
        resp.json(),
        alias=alias,
        subject=payload.sub,
        issuer=provider.issuer,
        token_endpoint=provider.token_endpoint,
    )

    store = _token_store(request)
    try:
        await store.write_cas(payload.sub, alias, cred, expected_version=None)
    except VersionConflict:
        # User already had an entry for this alias (re-linking). Treat it as
        # an in-place update against whatever version is currently stored.
        existing = await store.get(payload.sub, alias)
        expected_version = existing[1] if existing is not None else None
        await store.write_cas(
            payload.sub, alias, cred, expected_version=expected_version
        )

    log.info("oauth21.callback.linked", alias=alias, subject=payload.sub)

    response = RedirectResponse(
        url=payload.return_url, status_code=status.HTTP_302_FOUND
    )
    response.delete_cookie(NONCE_COOKIE_NAME, path=NONCE_COOKIE_PATH)
    return response
