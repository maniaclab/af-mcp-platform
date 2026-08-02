"""Manual Bearer token bootstrap — POST/GET/DELETE /v1/tokens (issue #24),
backed by a durable, HA-safe token registry with enforced revocation
(issue #115).

MCP clients that don't yet support OAuth discovery (Claude Desktop today)
need a static Bearer to paste into their client config. This module mints
one on demand via Keycloak RFC 8693 token exchange, persists metadata (never
the token itself — see token_registry.py) so the caller can list and revoke
what they've issued across any broker replica, and never re-exposes a
token's value once it has been returned once.

Design notes / known limitations (see the PR description for the full
writeup — these are real gaps, not oversights):

* Minting targets the broker's OWN audience (``settings.oidc_audience``,
  i.e. ``mcp-gateway``). This is deliberately "Path B" from docs/auth.md
  (AF-internal token exchange) — the "atlas-auth.cern.ch rejects this token"
  caveat does not apply here because the token only ever needs to satisfy
  ``identity.keycloak_dependency``, not an external ATLAS service.
* ``ttl_seconds`` is advisory. RFC 8693 has no standard mechanism for the
  calling client to force a shorter/longer access-token lifespan than the
  target client's configured Access Token Lifespan in Keycloak; the response
  reports whatever ``exp`` Keycloak actually put on the token.
* Revocation is enforced, with bounded staleness. DELETE marks the jti
  revoked in the registry; ``identity.get_principal`` consults
  ``RevokedJtiCache`` (refreshed on an interval, default 30s — see
  ``Settings.revoked_jti_cache_refresh_seconds``) on every request, on both
  ``/v1`` and ``/mcp``. This broker never held a Keycloak-side revocation
  call in the first place that would help here: ``keycloak_dependency``
  validates via local JWT signature verification against the JWKS, not
  Keycloak introspection, so an RFC 7009 revoke call would not by itself
  have made Keycloak's signature still verify-but-then-get-rejected before
  natural expiry. The jti-denylist above is what actually makes revocation
  take effect early.
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
from af_mcp_broker.token_registry import (
    TokenRecord,
    TokenRegistryBackend,
    default_token_name,
)

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/tokens", tags=["tokens"])

# Recorded on every TokenRecord minted here -- distinguishes this mint path
# from any future one (e.g. a CLI) that might write to the same registry.
_MINTED_VIA = "portal"

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
_MAX_NAME_LENGTH = 200

# Rate limit is per-uid and intentionally separate from
# CredentialCache's failed-unlock limiter (credentials/cache.py) — that one
# guards against passphrase brute-forcing; this one guards against unbounded
# token issuance, a different threat with a different sane threshold.
#
# Deliberately kept in-process (not written to the same KV record the
# TokenRegistryBackend uses) even though that means the effective limit at
# replicaCount=2 is up to 2x the configured value: this is a soft anti-abuse
# counter, not a security boundary (CredentialCache's unlock rate limiter --
# which guards actual brute-forcing -- is exactly the same in-memory-only
# shape), and moving it into Vault would add a write on every single mint
# attempt (including ones that get rejected) purely to guard a convenience
# threshold. See the PR description for the full tradeoff (issue #115
# requirement 4).
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
    # Optional; a server-generated default (see default_token_name) is used
    # when absent so every record always has a displayable name.
    name: str | None = Field(default=None, max_length=_MAX_NAME_LENGTH)


class MintTokenResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    # Present ONLY in this response — never returned again by GET /v1/tokens.
    token: str
    jti: str
    issued_at: str
    expires_at: str
    name: str


class TokenSummary(BaseModel):
    model_config = ConfigDict(frozen=True)

    jti: str
    name: str
    issued_at: str
    expires_at: str
    # None until revoked; once set, the portal shows a "revoked" status
    # instead of removing the row (see docs/auth.md and issue #115 -- PR #28
    # used to drop the row entirely on revoke, which no longer happens).
    revoked_at: str | None
    source: str


class RevokeTokenResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    jti: str
    revoked: bool


# ---------------------------------------------------------------------------
# Registry orchestration -- rate limiting + the durable TokenRegistryBackend.
# ---------------------------------------------------------------------------


class RateLimitError(Exception):
    """Raised when a principal exceeds the mint-rate limit."""


@dataclass
class _RateWindow:
    count: int = 0
    window_start: float = field(default_factory=time.monotonic)


class TokenRegistry:
    """Process-facing API for the manual bearer-token bootstrap routes.

    Delegates durable metadata storage to a ``TokenRegistryBackend`` (in-
    memory or Vault/OpenBao -- see token_registry.py, chosen by
    ``settings.token_registry_backend``); keeps the per-uid mint-rate-limit
    window in-process regardless of backend (see the constant above for why
    that's a deliberate, documented tradeoff rather than an oversight).
    """

    def __init__(self, backend: TokenRegistryBackend) -> None:
        self._backend = backend
        self._rate: dict[int, _RateWindow] = {}
        self._log = structlog.get_logger(__name__).bind(component="TokenRegistry")

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

    async def put(self, record: TokenRecord) -> None:
        await self._backend.add(record)
        self._log.info(
            "token_registry.minted",
            jti=record.jti,
            uid=record.uid,
            expires_at=record.expires_at,
        )

    async def list_for_uid(self, uid: int) -> list[TokenRecord]:
        return await self._backend.list_for_uid(uid)

    async def owner_uid(self, jti: str) -> int | None:
        return await self._backend.owner_uid(jti)

    async def revoke(self, uid: int, jti: str) -> TokenRecord | None:
        record = await self._backend.revoke(uid, jti, revoked_at=time.time())
        if record is not None:
            self._log.info("token_registry.revoked", jti=jti, uid=uid)
        return record


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

    token_endpoint = f"{settings.oidc_issuer.rstrip('/')}/protocol/openid-connect/token"
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
                "audience": settings.oidc_audience,
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
    name = (body.name or "").strip() or default_token_name(jti, issued_at)

    await registry.put(
        TokenRecord(
            jti=jti,
            uid=principal.uid,
            subject=principal.subject,
            name=name,
            issued_at=issued_at,
            expires_at=expires_at,
            revoked_at=None,
            minted_via=_MINTED_VIA,
        )
    )
    registry.record_mint(principal.uid)

    # Log jti-only — never the token itself.
    await _audit(
        principal,
        "token.minted",
        jti,
        args_summary=f"jti={jti} ttl_requested={body.ttl_seconds} name={name!r}",
    )

    return MintTokenResponse(
        token=access_token,
        jti=jti,
        issued_at=_iso(issued_at),
        expires_at=_iso(expires_at),
        name=name,
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
    docs/auth.md and the PR description for the follow-up. Revoked rows stay
    listed (``revoked_at`` set) rather than disappearing, so the portal can
    show a revoked/active/expired status.
    """
    registry = _registry(request)
    rows = await registry.list_for_uid(principal.uid)
    return [
        TokenSummary(
            jti=r.jti,
            name=r.name,
            issued_at=_iso(r.issued_at),
            expires_at=_iso(r.expires_at),
            revoked_at=_iso(r.revoked_at) if r.revoked_at is not None else None,
            source="manual",
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
) -> RevokeTokenResponse:
    registry = _registry(request)

    # owner_uid() distinguishes "unknown token" (404) from "exists but
    # belongs to someone else" (403) without a uid-scoped lookup first --
    # see token_registry.TokenRegistryBackend.owner_uid.
    owner_uid = await registry.owner_uid(jti)
    if owner_uid is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Unknown token"
        )
    if owner_uid != principal.uid:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Not your token"
        )

    record = await registry.revoke(principal.uid, jti)
    if record is None:  # pragma: no cover - guarded by the ownership check above
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Unknown token"
        )

    await _audit(principal, "token.revoked", jti, args_summary=f"jti={jti}")

    return RevokeTokenResponse(jti=jti, revoked=True)
