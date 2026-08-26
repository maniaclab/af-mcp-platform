"""The broker as an OAuth-facing authorization server for MCP clients (issue #140).

``/mcp`` accepts a broker-issued PAT (``pat.py``/``pat_auth.py``), but until
now the only way to obtain one was the portal's ``POST /v1/tokens`` -- which
requires an already-authenticated Keycloak session, i.e. a human copy-pasting
a token into a client config. This module is the missing bootstrap: an MCP
client with *no* credential at all can point at ``/v1/oauth/authorize``, get
redirected through a real Keycloak login, and come back with a working PAT.

The broker is emphatically **not** becoming an identity provider here -- see
issue #144's "the broker is not an authorization server in the identity
sense" resolution. It delegates authentication to Keycloak and mints its own
credential once Keycloak has vouched for the human:

    MCP client --/authorize--> broker --redirect--> Keycloak login
    Keycloak --code--> broker's own callback (as Keycloak's OAuth client)
    broker exchanges that code, checks the access token carries the
    `mcp-gateway` audience (issue #245), learns `sub`, mints an MCP-facing
    auth code
    broker --redirect w/ that code--> MCP client
    MCP client --code + PKCE verifier--> broker's /token
    broker mints a PAT, returns it as `access_token`

Two independent PKCE/state pairs are in flight simultaneously and must not be
confused:

* The MCP client's own ``code_challenge``/``state`` (their exchange with
  *this* broker, standard OAuth 2.1 client behaviour) -- carried inside the
  encrypted state token below across the round trip to Keycloak and back,
  since nothing else survives that hop.
* The broker's own ``code_challenge``/``state`` (its exchange with
  *Keycloak*, where the broker itself is the OAuth client) -- reuses
  ``oauth_state.py``'s existing Fernet-cipher/nonce-cookie machinery
  (``McpAuthorizePayload``/``build_mcp_authorize_state``/
  ``decrypt_mcp_authorize_state``), the same shape ``api/oauth21.py`` already
  uses for the (unrelated) backend-account-linking flow.

Client registration is CIMD (``cimd_client.py``), mirroring rucio-mcp's
in-house reference implementation: ``client_id`` is an https URL the broker
dereferences at authorize time, self-referential, carrying the client's
``redirect_uris`` -- no ``/register`` endpoint, no per-client database.

The PAT minted at ``/token`` is transported in the ``access_token`` field
because that is the shape OAuth clients understand -- see issue #144's
"the returned PAT is not an OAuth access token in the security architecture"
framing. It authorizes nothing on ``/v1`` (still Keycloak-JWT-only); it is
only ever valid on ``/mcp``, exactly like a PAT minted via the portal.
"""

from __future__ import annotations

import base64
import hashlib
import time
from typing import TYPE_CHECKING, Annotated
from urllib.parse import urlencode

import httpx
import jwt
import structlog
from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse, RedirectResponse

from af_mcp_broker.cimd_client import (
    CimdError,
    redirect_uri_matches,
    resolve_cimd_client,
)
from af_mcp_broker.config import Settings, get_settings
from af_mcp_broker.http import get_http_client
from af_mcp_broker.identity import decode_broker_bearer, get_jwks
from af_mcp_broker.mcp_auth_codes import McpAuthCodeRecord
from af_mcp_broker.oauth_state import (
    MCP_NONCE_COOKIE_NAME,
    MCP_NONCE_COOKIE_PATH,
    STATE_TOKEN_TTL_SECONDS,
    StateTokenError,
    build_mcp_authorize_state,
    decrypt_mcp_authorize_state,
    generate_nonce,
    generate_pkce_pair,
)
from af_mcp_broker.pat import mint_pat
from af_mcp_broker.token_registry import (
    DuplicateNameError,
    TokenRecord,
    default_token_name,
)

if TYPE_CHECKING:
    from cryptography.fernet import Fernet
    from fastapi import Response

    from af_mcp_broker.mcp_auth_codes import McpAuthCodeStore

log = structlog.get_logger(__name__)

router = APIRouter(tags=["mcp-oauth"])

# PKCE code_challenge_method this broker accepts from MCP clients and always
# uses itself against Keycloak -- "plain" is deliberately not supported (RFC
# 7636 §4.2 allows it, but it defeats the point of PKCE against an attacker
# who can observe the authorize request).
_CODE_CHALLENGE_METHOD = "S256"

# Scope requested from Keycloak for the login exchange: `openid` yields an
# id_token carrying `sub` (who logged in), and `mcp-gateway` asks for the
# broker's resource-server audience on the accompanying access token -- the
# same audience identity.py's keycloak_dependency validates every /v1 bearer
# against. The callback refuses to proceed (access_denied) when that audience
# is missing (issue #245), so a plain Keycloak login by a user Keycloak won't
# mint the audience for can no longer bootstrap a PAT. Operators attach the
# `mcp-gateway` client scope to the login client as a *Default* scope (see
# docs/auth.md's operator setup reference), which makes this explicit request
# redundant -- it is kept so the flow still works if that attachment is ever
# flipped to Optional.
_KEYCLOAK_LOGIN_SCOPE = "openid mcp-gateway"


def _oauth_error_redirect(redirect_uri: str, error: str, state: str) -> Response:
    query = urlencode({"error": error, "state": state})
    return RedirectResponse(
        url=f"{redirect_uri}?{query}", status_code=status.HTTP_302_FOUND
    )


def _bad_request(detail: str) -> HTTPException:
    return HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=detail)


def _state_cipher(request: Request) -> Fernet:
    cipher = getattr(request.app.state, "oauth21_state_cipher", None)
    if cipher is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="MCP OAuth bootstrap is not configured",
        )
    return cipher


def _auth_code_store(request: Request) -> McpAuthCodeStore:
    store = getattr(request.app.state, "mcp_auth_code_store", None)
    if store is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="MCP OAuth bootstrap is not configured",
        )
    return store


def _require_keycloak_login_configured(settings: Settings) -> None:
    if not settings.keycloak_login_client_id:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="MCP OAuth bootstrap is not configured",
        )


def _keycloak_authorization_endpoint(settings: Settings) -> str:
    """Keycloak's standard OIDC authorization endpoint -- Keycloak's ``/protocol/openid-connect/*`` paths are a fixed convention already relied on elsewhere in this codebase, not something discovered per deployment. Front-channel (a browser redirect), so it stays on ``oidc_issuer``, never ``oidc_backchannel_url``."""
    return f"{settings.oidc_issuer.rstrip('/')}/protocol/openid-connect/auth"


def _keycloak_token_endpoint(settings: Settings) -> str:
    """Back-channel (the broker POSTs the code exchange itself), so it follows ``oidc_backchannel_url`` -- unlike the authorization endpoint above."""
    return f"{settings.oidc_backchannel_url.rstrip('/')}/protocol/openid-connect/token"


def _keycloak_login_redirect_uri(settings: Settings) -> str:
    """Return the broker's own callback URL for the Keycloak login leg.

    On ``broker_public_origin``, not request-relative, for the same reason
    ``api/oauth21.py``'s ``_callback_url`` is: it must match what Keycloak has
    registered for this client and share an origin with the host-only nonce
    cookie set at authorize time.
    """
    return (
        f"{settings.broker_public_origin.rstrip('/')}/v1/oauth/keycloak-login/callback"
    )


def _b64url_no_pad(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _pkce_challenge_matches(verifier: str, challenge: str) -> bool:
    """Return True if S256(*verifier*) == *challenge* (RFC 7636 §4.6)."""
    return (
        _b64url_no_pad(hashlib.sha256(verifier.encode("ascii")).digest()) == challenge
    )


async def _access_token_denial_reason(
    access_token: str | None, settings: Settings
) -> str | None:
    """Return why the login exchange's access token fails the broker-audience gate, or None when it passes.

    The bootstrap's entitlement check (issue #245): the id_token proves *who*
    logged in, but only the access token carries the `mcp-gateway` audience
    Keycloak's client-scope filter mints exclusively for entitled users --
    verified with the same decode `identity.get_principal` applies to every
    /v1 bearer (`decode_broker_bearer`), so this path cannot drift from the
    platform's one audience gate. Fails closed: a token response with no
    access token at all is a denial, not a pass -- which is also the symptom
    of the operator forgetting to attach the `mcp-gateway` client scope to
    the login client (see docs/auth.md's operator setup reference).

    The returned reason is safe to log: it never contains token material.
    """
    if not access_token:
        return "token response carries no access_token"
    keys = await get_jwks(settings)
    try:
        decode_broker_bearer(access_token, keys, settings)
    except jwt.InvalidAudienceError:
        return "access token lacks the broker audience"
    except (jwt.InvalidTokenError, ValueError) as exc:
        return f"access token failed verification: {exc}"
    return None


async def _verify_keycloak_id_token(id_token: str, settings: Settings) -> str:
    """Verify *id_token*'s signature/issuer/expiry and return its `sub` claim.

    Audience is the broker's own login client id, not `settings.oidc_audience`
    (the resource-server audience `identity.get_principal` validates a normal
    bearer against) -- this id_token proves who logged in via the broker's
    *login* client, a different relying party than the resource server.
    Entitlement to the platform is checked separately, against the exchange's
    access token -- see `_access_token_denial_reason`.
    """
    keys = await get_jwks(settings)
    header = jwt.get_unverified_header(id_token)
    kid = header.get("kid")
    key_data = next((k for k in keys if k.get("kid") == kid), None)
    if key_data is None and kid is None and len(keys) == 1:
        key_data = keys[0]
    if key_data is None:
        raise _bad_request("Keycloak id_token key not found in JWKS")
    try:
        public_key = jwt.algorithms.RSAAlgorithm.from_jwk(key_data)  # type: ignore[arg-type]
        claims = jwt.decode(
            id_token,
            public_key,  # type: ignore[arg-type]
            algorithms=["RS256"],
            audience=settings.keycloak_login_client_id,
            issuer=settings.oidc_issuer,
            options={"verify_exp": True},
        )
    except jwt.InvalidTokenError as exc:
        raise _bad_request(f"Keycloak id_token is invalid: {exc}") from exc
    sub = claims.get("sub")
    if not sub:
        raise _bad_request("Keycloak id_token has no sub claim")
    return str(sub)


def _pick_pat_name(client_name: str | None, lookup_id: str, created_at: float) -> str:
    """Prefer the MCP client's own CIMD ``client_name`` (issue #140's "sensible default name"), falling back to the standard dated default when absent."""
    return client_name or default_token_name(lookup_id, created_at)


async def _mint_bootstrap_pat(
    request: Request, settings: Settings, principal_id: str, client_name: str | None
) -> str:
    """Mint a fresh PAT for *principal_id* via the existing token-registry machinery (``pat.mint_pat`` + ``TokenRegistry.put``) -- the same primitives ``POST /v1/tokens`` uses, not a second minting path.

    Always mints a *new* PAT (issue #140's "create a new PAT per successful
    bootstrap rather than reusing one" decision) -- never looks up or reuses
    an existing record for this principal.
    """
    registry = request.app.state.token_registry
    plaintext, lookup_id, secret_hash = mint_pat()
    now = time.time()
    expires_at = now + settings.pat_default_expiry_days * 86400
    name = _pick_pat_name(client_name, lookup_id, now)
    record = TokenRecord(
        lookup_id=lookup_id,
        principal_id=principal_id,
        secret_hash=secret_hash,
        name=name,
        created_at=now,
        expires_at=expires_at,
        revoked_at=None,
        last_used_at=None,
        note="Created automatically when you connected an MCP client.",
    )
    try:
        await registry.put(record)
    except DuplicateNameError:
        # The client-name candidate collided with an existing live PAT for
        # this principal (e.g. a second bootstrap from the same MCP client) --
        # retry with the guaranteed-unique dated default rather than failing
        # the whole flow over a cosmetic name clash.
        record = TokenRecord(
            lookup_id=lookup_id,
            principal_id=principal_id,
            secret_hash=secret_hash,
            name=default_token_name(lookup_id, now),
            created_at=now,
            expires_at=expires_at,
            revoked_at=None,
            last_used_at=None,
            note=record.note,
        )
        await registry.put(record)
    log.info("mcp_oauth.pat_minted", lookup_id=lookup_id, principal_id=principal_id)
    return plaintext


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get(
    "/oauth/authorize",
    summary="Begin the MCP OAuth discovery bootstrap flow",
)
async def authorize(
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    response_type: Annotated[str, Query()] = "code",
    client_id: Annotated[str | None, Query()] = None,
    redirect_uri: Annotated[str | None, Query()] = None,
    state: Annotated[str, Query()] = "",
    code_challenge: Annotated[str | None, Query()] = None,
    code_challenge_method: Annotated[str | None, Query()] = None,
) -> Response:
    """Resolve the MCP client's CIMD ``client_id``, then redirect the browser to Keycloak.

    No credential is required (or possible) here -- this is the *start* of
    authentication, not a request this broker can already authorize.
    ``client_id``/``redirect_uri`` are validated against the client's CIMD
    document before anything else, since nothing else in this handler may
    safely redirect the browser to an unvalidated URI.
    """
    _require_keycloak_login_configured(settings)

    if not client_id or not redirect_uri:
        raise _bad_request("client_id and redirect_uri are required")

    try:
        cimd_client = await resolve_cimd_client(client_id, client=get_http_client())
    except CimdError as exc:
        raise _bad_request(f"Invalid client_id: {exc}") from exc

    if not any(
        redirect_uri_matches(redirect_uri, declared)
        for declared in cimd_client.redirect_uris
    ):
        raise _bad_request("redirect_uri is not registered for this client_id")

    # redirect_uri is now validated against the client's own CIMD document --
    # every error from here on can be safely reported by redirecting there
    # (OAuth 2.1 §4.1.2.1), rather than as a bare 400.
    if response_type != "code":
        return _oauth_error_redirect(redirect_uri, "unsupported_response_type", state)
    if code_challenge_method != _CODE_CHALLENGE_METHOD or not code_challenge:
        return _oauth_error_redirect(redirect_uri, "invalid_request", state)

    cipher = _state_cipher(request)
    broker_verifier, broker_challenge = generate_pkce_pair()
    nonce = generate_nonce()
    mcp_state_token = build_mcp_authorize_state(
        cipher,
        iss=settings.oauth21_effective_state_issuer,
        pkce_verifier=broker_verifier,
        mcp_client_id=client_id,
        mcp_redirect_uri=redirect_uri,
        mcp_state=state,
        mcp_code_challenge=code_challenge,
        mcp_client_name=cimd_client.client_name or "",
        nonce=nonce,
    )

    query = urlencode(
        {
            "client_id": settings.keycloak_login_client_id,
            "redirect_uri": _keycloak_login_redirect_uri(settings),
            "response_type": "code",
            "scope": _KEYCLOAK_LOGIN_SCOPE,
            "code_challenge": broker_challenge,
            "code_challenge_method": _CODE_CHALLENGE_METHOD,
            "state": mcp_state_token,
        }
    )
    response = RedirectResponse(
        url=f"{_keycloak_authorization_endpoint(settings)}?{query}",
        status_code=status.HTTP_302_FOUND,
    )
    response.set_cookie(
        MCP_NONCE_COOKIE_NAME,
        nonce,
        max_age=STATE_TOKEN_TTL_SECONDS,
        httponly=True,
        secure=True,
        samesite="lax",
        path=MCP_NONCE_COOKIE_PATH,
    )
    return response


@router.get(
    "/oauth/keycloak-login/callback",
    name="mcp_oauth_keycloak_login_callback",
    summary="Receive the Keycloak login result and hand an MCP auth code back to the client",
)
async def keycloak_login_callback(
    request: Request,
    state: str,
    settings: Annotated[Settings, Depends(get_settings)],
    code: str | None = None,
    error: str | None = None,
) -> Response:
    """Complete the broker's own login to Keycloak, then redirect the MCP client back with a broker-minted authorization code.

    Carries no Authorization header (this is a third-party redirect back into
    a not-yet-authenticated flow) -- authenticated instead by possession of a
    ``state`` token that decrypts under the broker's own key, has not
    expired, is self-audienced, and whose embedded nonce matches the
    ``MCP_NONCE_COOKIE_NAME`` cookie set by ``/oauth/authorize`` in the same
    browser -- exactly the pattern ``api/oauth21.py``'s callback already
    uses for the unrelated backend-linking flow.
    """
    cipher = _state_cipher(request)
    cookie_nonce = request.cookies.get(MCP_NONCE_COOKIE_NAME)
    if cookie_nonce is None:
        raise _bad_request("Missing OAuth state nonce cookie")

    try:
        payload = decrypt_mcp_authorize_state(
            cipher, state, expected_iss=settings.oauth21_effective_state_issuer
        )
    except StateTokenError as exc:
        raise _bad_request(str(exc)) from exc

    if payload.nonce != cookie_nonce:
        raise _bad_request("OAuth state nonce does not match cookie")

    if error is not None:
        log.warning("mcp_oauth.keycloak_login_failed", error=error)
        response = _oauth_error_redirect(
            payload.mcp_redirect_uri, "access_denied", payload.mcp_state
        )
        response.delete_cookie(MCP_NONCE_COOKIE_NAME, path=MCP_NONCE_COOKIE_PATH)
        return response

    if code is None:
        raise _bad_request("Missing code or error in callback")

    try:
        resp = await get_http_client().post(
            _keycloak_token_endpoint(settings),
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": _keycloak_login_redirect_uri(settings),
                "code_verifier": payload.pkce_verifier,
                "client_id": settings.keycloak_login_client_id,
                "client_secret": settings.keycloak_login_client_secret.get_secret_value(),
            },
            timeout=10.0,
        )
        resp.raise_for_status()
        token_response = resp.json()
        id_token = token_response["id_token"]
    except (httpx.HTTPError, KeyError) as exc:
        log.warning("mcp_oauth.keycloak_token_exchange_failed", error=str(exc))
        response = _oauth_error_redirect(
            payload.mcp_redirect_uri, "server_error", payload.mcp_state
        )
        response.delete_cookie(MCP_NONCE_COOKIE_NAME, path=MCP_NONCE_COOKIE_PATH)
        return response

    # The mcp-gateway audience gate (issue #245) -- see
    # _access_token_denial_reason. Refused here, before the id_token is even
    # looked at: no auth code is stored, so no PAT can ever be redeemed from
    # this login. access_denied, not server_error -- the platform worked; the
    # user is not entitled, symmetric with the TokenAudienceError a JWT
    # caller gets on /mcp.
    denial_reason = await _access_token_denial_reason(
        token_response.get("access_token"), settings
    )
    if denial_reason is not None:
        log.warning("mcp_oauth.bootstrap_not_entitled", reason=denial_reason)
        response = _oauth_error_redirect(
            payload.mcp_redirect_uri, "access_denied", payload.mcp_state
        )
        response.delete_cookie(MCP_NONCE_COOKIE_NAME, path=MCP_NONCE_COOKIE_PATH)
        return response

    principal_id = await _verify_keycloak_id_token(id_token, settings)

    auth_code_store = _auth_code_store(request)
    mcp_code = auth_code_store.put(
        McpAuthCodeRecord(
            principal_id=principal_id,
            client_id=payload.mcp_client_id,
            redirect_uri=payload.mcp_redirect_uri,
            code_challenge=payload.mcp_code_challenge,
            client_name=payload.mcp_client_name or None,
        )
    )

    log.info("mcp_oauth.keycloak_login_succeeded", principal_id=principal_id)
    query = urlencode({"code": mcp_code, "state": payload.mcp_state})
    response = RedirectResponse(
        url=f"{payload.mcp_redirect_uri}?{query}", status_code=status.HTTP_302_FOUND
    )
    response.delete_cookie(MCP_NONCE_COOKIE_NAME, path=MCP_NONCE_COOKIE_PATH)
    return response


@router.post(
    "/oauth/token",
    summary="Redeem an MCP OAuth bootstrap authorization code for a PAT",
)
async def token(
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    grant_type: Annotated[str, Form()],
    code: Annotated[str, Form()],
    redirect_uri: Annotated[str, Form()],
    client_id: Annotated[str, Form()],
    code_verifier: Annotated[str, Form()],
) -> Response:
    """Validate the redeemed code, PKCE verifier, and client/redirect_uri match, then mint and return a PAT as ``access_token``.

    The PAT is minted here -- on redemption -- not eagerly at the Keycloak
    callback, so a code that is never redeemed (browser closed, network
    failure) never produces an unclaimed credential.
    """
    if grant_type != "authorization_code":
        return JSONResponse(
            {"error": "unsupported_grant_type"}, status_code=status.HTTP_400_BAD_REQUEST
        )

    record = _auth_code_store(request).consume(code)
    if record is None:
        return JSONResponse(
            {"error": "invalid_grant"}, status_code=status.HTTP_400_BAD_REQUEST
        )
    if record.client_id != client_id or record.redirect_uri != redirect_uri:
        return JSONResponse(
            {"error": "invalid_grant"}, status_code=status.HTTP_400_BAD_REQUEST
        )
    if not _pkce_challenge_matches(code_verifier, record.code_challenge):
        return JSONResponse(
            {"error": "invalid_grant"}, status_code=status.HTTP_400_BAD_REQUEST
        )

    pat = await _mint_bootstrap_pat(
        request, settings, record.principal_id, record.client_name
    )
    return JSONResponse(
        {
            "access_token": pat,
            "token_type": "Bearer",
            "expires_in": settings.pat_default_expiry_days * 86400,
        }
    )
