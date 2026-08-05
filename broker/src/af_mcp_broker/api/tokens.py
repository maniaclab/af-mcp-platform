"""Broker-issued identity PAT bootstrap — POST/GET/DELETE /v1/tokens (issue #144 step 2a).

Replaces the RFC 8693 token-exchange design (issue #24/#115/#116, PR #28
and successors): instead of exchanging the caller's Keycloak JWT for another
JWT via Standard Token Exchange, ``POST /v1/tokens`` now mints a broker-
issued PAT directly (``pat.mint_pat`` -- 256-bit random secret, SHA-256
hashed for storage, plaintext returned exactly once). No Keycloak round trip
is needed to mint one, so the old 503 ("minting not configured")/502
("Keycloak rejected the exchange") failure modes are gone entirely -- mint
either succeeds for any authenticated principal or fails on something this
endpoint itself controls (rate limit, duplicate name, validation).

**This endpoint's own authentication is UNCHANGED.** It still requires a
Keycloak JWT via ``keycloak_dependency`` -- only what it *returns* changed.
This is deliberate and security-load-bearing, not an oversight: ``/v1`` stays
Keycloak-JWT-only precisely so a PAT can never authenticate here. If a PAT
could mint further PATs, a single leaked credential would become
self-renewing, and revocation would degrade into whack-a-mole against
tokens the leaked one itself created (GitHub disallows this by default for
the same reason). A PAT is therefore always traceable back to an
interactive Keycloak login -- whether initiated from the portal (this
endpoint) or, in a future step of issue #144, an OAuth bootstrap flow that
also authenticates via Keycloak first. See ``pat_auth.py``'s module
docstring for where PATs *are* accepted (``/mcp``, via
``mcp/middleware/identity_mw.py``'s ``AsgiAuthMiddleware``).

Storage is the **PAT store** (``token_registry.py``, adapted from the
original manual-bearer registry): identity and metadata only -- no groups,
no capabilities, no authorization data (see that module's docstring). This
endpoint never resolves or stores the caller's groups; the resulting PAT's
authority is always re-resolved fresh at validation time from
``principal_cache.py``, keyed by ``principal_id`` (the caller's Keycloak
``sub``).

Design notes / known limitations (see the PR description for the full
writeup — these are real gaps, not oversights):

* Listing only covers tokens minted through this endpoint. A future OAuth
  bootstrap flow (issue #144, later step) would mint through the same PAT
  store, so this gap is expected to close rather than widen.
* ``name`` is a unique-per-principal identifier, not free text (issue #116,
  carried forward): minting a second token whose name matches an existing
  *live* one for the same principal (case-insensitive) is rejected with 409.
  "Live" excludes revoked and expired tokens -- a name freed up by
  revocation or natural expiry can be reused, since the dead token can no
  longer be mistaken for the new one. The uniqueness enforcement lives in
  ``token_registry.TokenRegistryBackend.add()`` (see that module's
  docstring), not here, so it stays correct under concurrent mints from
  multiple broker replicas.
* ``note`` is an optional, free-text, user-supplied field -- purely
  self-descriptive, never consumed by the broker, stored alongside the
  record and shown back on mint/list. Absent (``None``) unless supplied.
* Expiry default is 90 days (``Settings.pat_default_expiry_days``);
  never-expiring is an explicit opt-in (``MintTokenRequest.never_expires``),
  logged loudly when used, never the default.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Annotated

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field, model_validator

from af_mcp_broker.audit import AuditRecord, write_audit
from af_mcp_broker.config import Settings, get_settings
from af_mcp_broker.identity import Principal, keycloak_dependency
from af_mcp_broker.pat import mint_pat
from af_mcp_broker.token_registry import (
    DuplicateNameError,
    TokenRecord,
    TokenRegistryBackend,
    default_token_name,
)

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/tokens", tags=["tokens"])

_MAX_NAME_LENGTH = 200
_MAX_NOTE_LENGTH = 256
_MIN_EXPIRES_IN_DAYS = 1
_MAX_EXPIRES_IN_DAYS = 3650

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

    # Optional; a server-generated default (see default_token_name) is used
    # when absent so every record always has a displayable name. Unique per
    # principal among live (non-revoked, unexpired-or-never-expiring) tokens,
    # case-insensitively -- see this module's docstring and token_registry.py.
    name: str | None = Field(default=None, max_length=_MAX_NAME_LENGTH)
    # Optional free-text note (issue #116) -- purely self-descriptive, never
    # consumed by the broker. None (absent) by default.
    note: str | None = Field(default=None, max_length=_MAX_NOTE_LENGTH)
    # None (the default) means "use Settings.pat_default_expiry_days" --
    # resolved in mint_token, not here, so the default tracks the broker's
    # configured value rather than a value frozen into this model.
    expires_in_days: int | None = Field(
        default=None, ge=_MIN_EXPIRES_IN_DAYS, le=_MAX_EXPIRES_IN_DAYS
    )
    # Explicit opt-in for a PAT that never expires (issue #144's design
    # notes) -- never the default. Mutually exclusive with expires_in_days;
    # see _validate_expiry below.
    never_expires: bool = False

    @model_validator(mode="after")
    def _validate_expiry(self) -> MintTokenRequest:
        if self.never_expires and self.expires_in_days is not None:
            raise ValueError("Set either never_expires or expires_in_days, not both.")
        return self


class MintTokenResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    # Present ONLY in this response — never returned again by GET /v1/tokens.
    token: str
    lookup_id: str
    created_at: str
    # None means the PAT never expires.
    expires_at: str | None
    name: str
    note: str | None


class TokenSummary(BaseModel):
    model_config = ConfigDict(frozen=True)

    lookup_id: str
    name: str
    note: str | None
    created_at: str
    expires_at: str | None
    # None until revoked; once set, the portal shows a "revoked" status
    # instead of removing the row (see docs/auth.md and issue #115 -- PR #28
    # used to drop the row entirely on revoke, which no longer happens).
    revoked_at: str | None
    last_used_at: str | None


class RevokeTokenResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    lookup_id: str
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
            lookup_id=record.lookup_id,
            principal_id=record.principal_id,
            expires_at=record.expires_at,
        )

    async def list_for_principal(self, principal_id: str) -> list[TokenRecord]:
        return await self._backend.list_for_principal(principal_id)

    async def owner_principal_id(self, lookup_id: str) -> str | None:
        return await self._backend.owner_principal_id(lookup_id)

    async def revoke(self, principal_id: str, lookup_id: str) -> TokenRecord | None:
        record = await self._backend.revoke(
            principal_id, lookup_id, revoked_at=time.time()
        )
        if record is not None:
            self._log.info(
                "token_registry.revoked", lookup_id=lookup_id, principal_id=principal_id
            )
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


# ---------------------------------------------------------------------------
# Audit helper
# ---------------------------------------------------------------------------


async def _audit(
    principal: Principal, action: str, lookup_id: str, args_summary: str
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
            request_id=lookup_id,
            audit_id=lookup_id,
        )
    )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.post(
    "",
    response_model=MintTokenResponse,
    summary="Mint a new identity PAT for programmatic-client bootstrap",
)
async def mint_token(
    body: MintTokenRequest,
    request: Request,
    principal: Annotated[Principal, Depends(keycloak_dependency)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> MintTokenResponse:
    """Mint a broker-issued PAT for the calling (Keycloak-JWT-authenticated) principal.

    Authentication for THIS route is unchanged (``keycloak_dependency`` --
    the same JWT dependency every other ``/v1`` route uses). Only the
    returned credential type changed, from an RFC 8693 token-exchange JWT to
    a PAT -- see this module's docstring for why a PAT must never be able to
    authenticate here.
    """
    registry = _registry(request)
    try:
        registry.check_mint_rate_limit(principal.uid)
    except RateLimitError as exc:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=str(exc)
        ) from exc

    plaintext, lookup_id, secret_hash = mint_pat()
    now = time.time()

    if body.never_expires:
        expires_at: float | None = None
        logger.warning(
            "pat_minted_without_expiry",
            principal_id=principal.subject,
            lookup_id=lookup_id,
        )
    else:
        days = (
            body.expires_in_days
            if body.expires_in_days is not None
            else settings.pat_default_expiry_days
        )
        expires_at = now + days * 86400

    name = (body.name or "").strip() or default_token_name(lookup_id, now)
    note = (body.note or "").strip() or None

    try:
        await registry.put(
            TokenRecord(
                lookup_id=lookup_id,
                principal_id=principal.subject,
                secret_hash=secret_hash,
                name=name,
                created_at=now,
                expires_at=expires_at,
                revoked_at=None,
                last_used_at=None,
                note=note,
            )
        )
    except DuplicateNameError as exc:
        logger.warning(
            "token_mint_duplicate_name", principal_id=principal.subject, name=name
        )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail=str(exc)
        ) from exc
    registry.record_mint(principal.uid)

    # Log lookup_id-only — never the token itself.
    await _audit(
        principal,
        "token.minted",
        lookup_id,
        args_summary=f"lookup_id={lookup_id} name={name!r} never_expires={expires_at is None}",
    )

    return MintTokenResponse(
        token=plaintext,
        lookup_id=lookup_id,
        created_at=_iso(now),
        expires_at=_iso(expires_at) if expires_at is not None else None,
        name=name,
        note=note,
    )


@router.get(
    "",
    response_model=list[TokenSummary],
    summary="List PATs issued to the caller",
)
async def list_tokens(
    request: Request,
    principal: Annotated[Principal, Depends(keycloak_dependency)],
) -> list[TokenSummary]:
    """List PATs the caller owns.

    Only covers PATs minted via POST /v1/tokens -- see this module's
    docstring. Revoked rows stay listed (``revoked_at`` set) rather than
    disappearing, so the portal can show a revoked/active/expired status.
    """
    registry = _registry(request)
    rows = await registry.list_for_principal(principal.subject)
    return [
        TokenSummary(
            lookup_id=r.lookup_id,
            name=r.name,
            note=r.note,
            created_at=_iso(r.created_at),
            expires_at=_iso(r.expires_at) if r.expires_at is not None else None,
            revoked_at=_iso(r.revoked_at) if r.revoked_at is not None else None,
            last_used_at=_iso(r.last_used_at) if r.last_used_at is not None else None,
        )
        for r in rows
    ]


@router.delete(
    "/{lookup_id}",
    response_model=RevokeTokenResponse,
    summary="Revoke a PAT before its natural expiry",
)
async def revoke_token(
    lookup_id: str,
    request: Request,
    principal: Annotated[Principal, Depends(keycloak_dependency)],
) -> RevokeTokenResponse:
    registry = _registry(request)

    # owner_principal_id() distinguishes "unknown token" (404) from "exists
    # but belongs to someone else" (403) without a principal-scoped lookup
    # first -- see token_registry.TokenRegistryBackend.owner_principal_id.
    owner_principal_id = await registry.owner_principal_id(lookup_id)
    if owner_principal_id is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Unknown token"
        )
    if owner_principal_id != principal.subject:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Not your token"
        )

    record = await registry.revoke(principal.subject, lookup_id)
    if record is None:  # pragma: no cover - guarded by the ownership check above
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Unknown token"
        )

    await _audit(
        principal, "token.revoked", lookup_id, args_summary=f"lookup_id={lookup_id}"
    )

    return RevokeTokenResponse(lookup_id=lookup_id, revoked=True)
