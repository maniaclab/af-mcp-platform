"""Manual Bearer token bootstrap — POST/GET/DELETE /v1/tokens (issue #24).

MCP clients that don't yet support OAuth discovery (Claude Desktop today)
need a static Bearer to paste into their client config. This module mints
one on demand via Keycloak RFC 8693 token exchange, keeps process-local
bookkeeping so the caller can list and revoke what they've issued, and never
re-exposes a token's value once it has been returned once.

Design notes / known limitations (see the PR description for the full
writeup — these are real gaps, not oversights):

* Minting targets the broker's OWN audience (``settings.keycloak_audience``,
  i.e. ``mcp-gateway``). This is deliberately "Path B" from docs/auth.md
  (AF-internal token exchange) — the "atlas-auth.cern.ch rejects this token"
  caveat does not apply here because the token only ever needs to satisfy
  ``identity.keycloak_dependency``, not an external ATLAS service.
* ``ttl_seconds`` is advisory. RFC 8693 has no standard mechanism for the
  calling client to force a shorter/longer access-token lifespan than the
  target client's configured Access Token Lifespan in Keycloak; the response
  reports whatever ``exp`` Keycloak actually put on the token.
* Revocation is best-effort. ``identity.keycloak_dependency`` validates
  tokens via local JWT signature verification against the JWKS, not via
  Keycloak introspection, so Keycloak accepting a revoke call does not, by
  itself, make the broker reject the token before its natural expiry. True
  early revocation would require wiring jti-denylist enforcement into
  ``keycloak_dependency``, which is out of scope for this change (identity.py
  is not touched here). DELETE still removes the row from OUR list and best-
  effort revokes upstream — it's a real (if partial) safety improvement.
* Listing only covers tokens minted through this endpoint. Keycloak's admin
  REST API exposes sessions and IdP consents, not per-token metadata for
  RFC 8693 token-exchange output (which isn't tied to a browser session), so
  tokens issued via oauth2-proxy's interactive flow or a future MCP OAuth
  flow cannot be enumerated here today. That gap is surfaced in the route
  docstring/response description rather than silently omitted.
"""

from __future__ import annotations

import os
import time
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Annotated, Any

import jwt
import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field

from af_mcp_broker.audit import AuditRecord, write_audit
from af_mcp_broker.config import Settings, get_settings
from af_mcp_broker.http import get_http_client
from af_mcp_broker.identity import Principal, keycloak_dependency

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/tokens", tags=["tokens"])

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# The confidential Keycloak client used to authenticate the *broker* when it
# performs RFC 8693 token exchange on the caller's behalf. Deliberately read
# straight from the environment rather than added to the shared pydantic
# Settings model — this mirrors credentials/service.py's ServiceProvider,
# which keeps service-account secrets out of Settings for the same reason:
# they're operational secrets, not general configuration. Unset disables
# minting (503); list/revoke still work against whatever is already cached.
_TOKEN_MINT_CLIENT_ID_ENV = "TOKEN_MINT_CLIENT_ID"
_TOKEN_MINT_CLIENT_SECRET_ENV = "TOKEN_MINT_CLIENT_SECRET"

_MIN_TTL_SECONDS = 60
_MAX_TTL_SECONDS = 86400
_DEFAULT_TTL_SECONDS = 3600
_MAX_NOTE_LENGTH = 200

# Rate limit is per-uid and intentionally separate from
# CredentialCache's failed-unlock limiter (credentials/cache.py) — that one
# guards against passphrase brute-forcing; this one guards against unbounded
# token issuance, a different threat with a different sane threshold.
_MAX_MINTS_PER_HOUR = 10
_MINT_RATE_WINDOW_SECONDS = 60 * 60

# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------


class MintTokenRequest(BaseModel):
    model_config = ConfigDict(frozen=True)

    ttl_seconds: int = Field(
        default=_DEFAULT_TTL_SECONDS, ge=_MIN_TTL_SECONDS, le=_MAX_TTL_SECONDS
    )
    note: str | None = Field(default=None, max_length=_MAX_NOTE_LENGTH)


class MintTokenResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    # Present ONLY in this response — never returned again by GET /v1/tokens.
    token: str
    jti: str
    issued_at: str
    expires_at: str
    note: str | None = None


class TokenSummary(BaseModel):
    model_config = ConfigDict(frozen=True)

    jti: str
    issued_at: str
    expires_at: str
    source: str
    note: str | None = None
    last_used_at: str | None = None


class RevokeTokenResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    jti: str
    revoked: bool


# ---------------------------------------------------------------------------
# In-memory registry
# ---------------------------------------------------------------------------


class RateLimitError(Exception):
    """Raised when a principal exceeds the mint-rate limit."""


@dataclass
class _TokenRecord:
    jti: str
    uid: int
    issued_at: float
    expires_at: float
    note: str | None
    source: str
    # Retained only to support the best-effort Keycloak-side revoke call
    # below — never logged, never re-exposed via the API.
    raw_token: str
    last_used_at: float | None = None


@dataclass
class _RateWindow:
    count: int = 0
    window_start: float = field(default_factory=time.monotonic)


class TokenRegistry:
    """Process-local bookkeeping for manually-minted bearer tokens.

    Deliberately NOT a durable store: Keycloak (not this registry) is the
    source of truth for whether a JWT is still cryptographically valid.
    Losing this registry on a broker restart just means old rows stop
    appearing in the portal's list — it does not affect whether previously
    minted tokens keep working, which is a property of the JWT alone.
    """

    def __init__(self) -> None:
        self._by_jti: dict[str, _TokenRecord] = {}
        self._rate: dict[int, _RateWindow] = {}
        self._log = structlog.get_logger(__name__).bind(component="TokenRegistry")

    def _sweep_expired(self) -> None:
        now = time.time()
        expired = [jti for jti, r in self._by_jti.items() if r.expires_at <= now]
        for jti in expired:
            del self._by_jti[jti]

    def check_mint_rate_limit(self, uid: int) -> None:
        """Raise RateLimitError if *uid* has hit the per-hour mint cap."""
        now = time.monotonic()
        window = self._rate.get(uid)
        if window is None or (now - window.window_start) > _MINT_RATE_WINDOW_SECONDS:
            return
        if window.count >= _MAX_MINTS_PER_HOUR:
            remaining = int(_MINT_RATE_WINDOW_SECONDS - (now - window.window_start))
            raise RateLimitError(
                f"Too many tokens minted for uid={uid}. Try again in {remaining}s."
            )

    def record_mint(self, uid: int) -> None:
        now = time.monotonic()
        window = self._rate.get(uid)
        if window is None or (now - window.window_start) > _MINT_RATE_WINDOW_SECONDS:
            window = _RateWindow(count=0, window_start=now)
            self._rate[uid] = window
        window.count += 1

    def put(self, record: _TokenRecord) -> None:
        self._sweep_expired()
        self._by_jti[record.jti] = record
        self._log.info(
            "token_registry.minted",
            jti=record.jti,
            uid=record.uid,
            expires_at=record.expires_at,
        )

    def list_for_uid(self, uid: int) -> list[_TokenRecord]:
        self._sweep_expired()
        rows = [r for r in self._by_jti.values() if r.uid == uid]
        rows.sort(key=lambda r: r.issued_at, reverse=True)
        return rows

    def get(self, jti: str) -> _TokenRecord | None:
        return self._by_jti.get(jti)

    def remove(self, jti: str) -> None:
        self._by_jti.pop(jti, None)
        self._log.info("token_registry.revoked", jti=jti)


def _registry(request: Request) -> TokenRegistry:
    registry = getattr(request.app.state, "token_registry", None)
    if registry is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Token registry is not configured",
        )
    return registry


def _iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=UTC).isoformat()


def _decode_unverified(token: str) -> dict[str, Any]:
    # We just received this token directly from Keycloak's token endpoint
    # over an authenticated HTTPS call — re-verifying its signature here buys
    # nothing; we only need iat/exp/jti for our own bookkeeping.
    return jwt.decode(token, options={"verify_signature": False})


# ---------------------------------------------------------------------------
# Keycloak calls
# ---------------------------------------------------------------------------


async def _exchange_for_bearer(
    settings: Settings, principal: Principal
) -> tuple[str, dict[str, Any]]:
    """Mint a static bearer via RFC 8693 token exchange, self-audience.

    Raises HTTPException(503) if no client credentials are configured, or
    HTTPException(502) if Keycloak rejects the exchange.
    """
    client_id = os.environ.get(_TOKEN_MINT_CLIENT_ID_ENV)
    client_secret = os.environ.get(_TOKEN_MINT_CLIENT_SECRET_ENV)
    if not client_id or not client_secret:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "Token minting is not configured. Set TOKEN_MINT_CLIENT_ID and "
                "TOKEN_MINT_CLIENT_SECRET for a confidential Keycloak client "
                "granted 'Standard Token Exchange' permission."
            ),
        )

    token_endpoint = (
        f"{settings.keycloak_issuer.rstrip('/')}/protocol/openid-connect/token"
    )
    try:
        resp = await get_http_client().post(
            token_endpoint,
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                "client_id": client_id,
                "client_secret": client_secret,
                "subject_token": principal.raw_token.get_secret_value(),
                "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
                "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
                "audience": settings.keycloak_audience,
            },
            timeout=10.0,
        )
    except Exception as exc:
        # Mirrors identity._fetch_jwks: an unreachable Keycloak is a 502 for
        # our caller, not an unhandled 500.
        logger.exception("token_exchange_unreachable", uid=principal.uid)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Unable to reach Keycloak token endpoint: {token_endpoint}",
        ) from exc
    if resp.status_code >= 400:
        logger.warning(
            "token_exchange_failed",
            status_code=resp.status_code,
            uid=principal.uid,
        )
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Keycloak rejected the token-exchange request",
        )
    data = resp.json()
    access_token: str = data["access_token"]
    claims = _decode_unverified(access_token)
    return access_token, claims


async def _best_effort_keycloak_revoke(settings: Settings, raw_token: str) -> None:
    """Best-effort RFC 7009 revoke call — see the module docstring for why
    this alone does not guarantee the broker itself will reject the token
    before natural expiry."""
    client_id = os.environ.get(_TOKEN_MINT_CLIENT_ID_ENV)
    client_secret = os.environ.get(_TOKEN_MINT_CLIENT_SECRET_ENV)
    if not client_id or not client_secret:
        return
    revoke_endpoint = (
        f"{settings.keycloak_issuer.rstrip('/')}/protocol/openid-connect/revoke"
    )
    try:
        await get_http_client().post(
            revoke_endpoint,
            data={
                "client_id": client_id,
                "client_secret": client_secret,
                "token": raw_token,
            },
            timeout=10.0,
        )
    except Exception as exc:  # noqa: BLE001 — best-effort, must not block the local revoke
        logger.warning("keycloak_revoke_call_failed", error=str(exc))


# ---------------------------------------------------------------------------
# Audit helper
# ---------------------------------------------------------------------------


async def _audit(
    principal: Principal, action: str, jti: str, args_summary: str
) -> None:
    await write_audit(
        AuditRecord(
            principal_sub=principal.subject,
            principal_uid=principal.uid,
            capability="tokens",
            target="mcp-gateway",
            action=action,
            action_type="state_change",
            args_summary=args_summary,
            timestamp=time.time(),
            request_id=jti,
            audit_id=jti,
        )
    )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.post(
    "",
    response_model=MintTokenResponse,
    summary="Mint a new Bearer token for programmatic-client bootstrap",
)
async def mint_token(
    body: MintTokenRequest,
    request: Request,
    principal: Annotated[Principal, Depends(keycloak_dependency)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> MintTokenResponse:
    registry = _registry(request)
    try:
        registry.check_mint_rate_limit(principal.uid)
    except RateLimitError as exc:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=str(exc)
        ) from exc

    access_token, claims = await _exchange_for_bearer(settings, principal)

    jti = claims.get("jti")
    if not jti:
        jti = uuid.uuid4().hex
        logger.warning(
            "token_exchange_response_missing_jti",
            uid=principal.uid,
            synthetic_jti=jti,
        )

    issued_at = float(claims.get("iat", time.time()))
    expires_at = float(claims.get("exp", time.time() + body.ttl_seconds))

    registry.put(
        _TokenRecord(
            jti=jti,
            uid=principal.uid,
            issued_at=issued_at,
            expires_at=expires_at,
            note=body.note,
            source="manual",
            raw_token=access_token,
        )
    )
    registry.record_mint(principal.uid)

    # Log jti-only — never the token itself.
    await _audit(
        principal,
        "token.minted",
        jti,
        args_summary=f"jti={jti} ttl_requested={body.ttl_seconds} note={body.note!r}",
    )

    return MintTokenResponse(
        token=access_token,
        jti=jti,
        issued_at=_iso(issued_at),
        expires_at=_iso(expires_at),
        note=body.note,
    )


@router.get(
    "",
    response_model=list[TokenSummary],
    summary="List Bearer tokens issued to the caller",
)
async def list_tokens(
    request: Request,
    principal: Annotated[Principal, Depends(keycloak_dependency)],
) -> list[TokenSummary]:
    """List tokens the caller owns.

    Only covers tokens minted via POST /v1/tokens (``source: "manual"``).
    Keycloak's admin REST API surfaces sessions and IdP consents, not
    per-token metadata for RFC 8693 token-exchange output, so tokens issued
    through oauth2-proxy's interactive flow or a future MCP OAuth flow are
    not enumerable here yet — that is a real gap, not a silent omission; see
    docs/auth.md and the PR description for the follow-up.
    """
    registry = _registry(request)
    rows = registry.list_for_uid(principal.uid)
    return [
        TokenSummary(
            jti=r.jti,
            issued_at=_iso(r.issued_at),
            expires_at=_iso(r.expires_at),
            source=r.source,
            note=r.note,
            last_used_at=_iso(r.last_used_at) if r.last_used_at else None,
        )
        for r in rows
    ]


@router.delete(
    "/{jti}",
    response_model=RevokeTokenResponse,
    summary="Revoke a token before its natural expiry",
)
async def revoke_token(
    jti: str,
    request: Request,
    principal: Annotated[Principal, Depends(keycloak_dependency)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> RevokeTokenResponse:
    registry = _registry(request)
    record = registry.get(jti)
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Unknown token"
        )
    if record.uid != principal.uid:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Not your token"
        )

    await _best_effort_keycloak_revoke(settings, record.raw_token)
    registry.remove(jti)

    await _audit(principal, "token.revoked", jti, args_summary=f"jti={jti}")

    return RevokeTokenResponse(jti=jti, revoked=True)
