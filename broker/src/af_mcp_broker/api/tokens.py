"""Broker-issued identity PAT bootstrap — POST/GET/DELETE /v1/tokens (issue #144 step 2a).

Not an RFC 8693 token exchange (the design of issues #24/#115/#116 and
PR #28): instead of exchanging the caller's Keycloak JWT for another JWT via
Standard Token Exchange, ``POST /v1/tokens`` mints a broker-issued PAT
directly (``pat.mint_pat`` -- 256-bit random secret, SHA-256 hashed for
storage, plaintext returned exactly once). No Keycloak round trip is needed
to mint one, so there is no "minting not configured" (503) or "Keycloak
rejected the exchange" (502) failure mode -- mint either succeeds for any authenticated principal or fails on something this
endpoint itself controls (rate limit, duplicate name, validation).

**This endpoint's own authentication is a Keycloak JWT** via
``keycloak_dependency``; only what it *returns* is a PAT.
This is deliberate and security-load-bearing, not an oversight: ``/v1`` stays
Keycloak-JWT-only precisely so a PAT can never authenticate here. If a PAT
could mint further PATs, a single leaked credential would become
self-renewing, and revocation would degrade into whack-a-mole against
tokens the leaked one itself created (GitHub disallows this by default for
the same reason). A PAT is therefore always traceable back to an
interactive Keycloak login -- whether initiated from the portal (this
endpoint) or the OAuth discovery bootstrap flow (``api/mcp_oauth.py``,
issue #140), which also authenticates via Keycloak first. See
``pat_auth.py``'s module
docstring for where PATs *are* accepted (``/mcp``, via
``mcp/middleware/identity_mw.py``'s ``AsgiAuthMiddleware``).

Storage is the **PAT store** (``token_registry.py``, adapted from the
original manual-bearer registry): identity and metadata only -- no groups,
no permissions, no authorization data (see that module's docstring). This
endpoint never resolves or stores the caller's groups; the resulting PAT's
authority is always re-resolved fresh at validation time from
``principal_cache.py``, keyed by ``principal_id`` (the caller's Keycloak
``sub``).

Design notes / known limitations (see the PR description for the full
writeup — these are real gaps, not oversights):

* Listing covers every PAT minted for the principal regardless of mint
  path -- both this endpoint and the OAuth discovery bootstrap flow
  (``api/mcp_oauth.py``'s ``_mint_bootstrap_pat``) mint through the same
  ``TokenRegistry.put()`` primitives, keyed by the same ``principal_id``,
  and ``TokenRegistryBackend.list_for_principal()`` has no mint-source
  filter.
* ``name`` is a unique-per-principal identifier, not free text (issue #116,
  carried forward): minting a second token whose name matches an existing
  *live* one for the same principal (case-insensitive) is rejected with 409.
  "Live" excludes revoked and expired tokens -- a name freed up by
  revocation or natural expiry can be reused, since the dead token cannot
  be mistaken for the new one. The uniqueness enforcement lives in
  ``token_registry.TokenRegistryBackend.add()`` (see that module's
  docstring), not here, so it stays correct under concurrent mints from
  multiple broker replicas.
* ``note`` is an optional, free-text, user-supplied field -- purely
  self-descriptive, never consumed by the broker, stored alongside the
  record and shown back on mint/list. Absent (``None``) unless supplied.
* Expiry default is 90 days (``Settings.pat_default_expiry_days``);
  never-expiring is an explicit opt-in (``MintTokenRequest.never_expires``),
  logged loudly when used, never the default.
* ``permissions`` (issue #144 step 4) mints a **permission PAT** -- see
  ``MintTokenRequest.permissions``'s docstring and docs/auth.md's
  "Permission PATs" section for the mint-time-validation-vs-enforcement
  split. Absent (``None``, the default) mints an ordinary identity PAT,
  unchanged from every PAT minted before this field existed.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime
from typing import Annotated

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, ConfigDict, Field, model_validator

from af_mcp_broker.api.auth import keycloak_dependency
from af_mcp_broker.api.errors import RateLimitedHTTPException
from af_mcp_broker.audit import AuditRecord, write_audit
from af_mcp_broker.authorization import get_principal_permissions
from af_mcp_broker.broker_state import get_broker_state, get_state_settings
from af_mcp_broker.config import (
    Settings,  # noqa: TC001 -- FastAPI resolves the dependency annotations at runtime
)
from af_mcp_broker.logging import current_request_id
from af_mcp_broker.pat import mint_pat
from af_mcp_broker.principal import Principal
from af_mcp_broker.retry_after import RateLimiter
from af_mcp_broker.token_registry import (
    DuplicateNameError,
    PatMintRateLimitError,
    TokenRecord,
    TokenRegistry,
    default_token_name,
)

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/tokens", tags=["tokens"])

_MAX_NAME_LENGTH = 200
_MAX_NOTE_LENGTH = 256
_MIN_EXPIRES_IN_DAYS = 1
_MAX_EXPIRES_IN_DAYS = 3650

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
    # Optional explicit permission grant (issue #144 step 4). None (the
    # default) mints an ordinary identity PAT: its authority is always the
    # caller's CURRENT permissions, re-derived fresh on every request, same
    # as before this field existed. A non-None value mints a **permission
    # PAT** instead: mint_token below validates it's a subset of the
    # caller's permissions at mint time, purely for a clear error message
    # naming any offending permission -- that check is advisory only, never
    # the thing standing between a caller and extra access. Enforcement is
    # the intersection ``authorization.get_principal_permissions`` performs
    # against the caller's current permissions on every request, and does
    # not depend on this validation having run; see docs/auth.md's
    # "Permission PATs" section.
    permissions: list[str] | None = None

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
    # None means an identity PAT (this token's authority is always the
    # caller's current permissions); a sorted list of permission names means
    # a permission PAT scoped to at most those (issue #144 step 4) -- see
    # MintTokenRequest.permissions and docs/auth.md's "Permission PATs".
    permission_grant: list[str] | None


class TokenSummary(BaseModel):
    model_config = ConfigDict(frozen=True)

    lookup_id: str
    name: str
    note: str | None
    created_at: str
    expires_at: str | None
    # None until revoked; once set, the portal shows a "revoked" status
    # instead of removing the row (see docs/auth.md and issue #115): the row
    # stays until the token sweep deletes it.
    revoked_at: str | None
    last_used_at: str | None
    # See MintTokenResponse.permission_grant -- same meaning, read back from
    # the stored record rather than the mint request.
    permission_grant: list[str] | None


class RevokeTokenResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    lookup_id: str
    revoked: bool


class DeleteTokenResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    lookup_id: str
    deleted: bool


class ClearTokensResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    # How many revoked or expired rows were deleted.
    deleted: int


def get_token_registry(request: Request) -> TokenRegistry:
    return get_broker_state(request).token_registry


def _iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=UTC).isoformat()


def to_summary(record: TokenRecord) -> TokenSummary:
    return TokenSummary(
        lookup_id=record.lookup_id,
        name=record.name,
        note=record.note,
        created_at=_iso(record.created_at),
        expires_at=_iso(record.expires_at) if record.expires_at is not None else None,
        revoked_at=_iso(record.revoked_at) if record.revoked_at is not None else None,
        last_used_at=(
            _iso(record.last_used_at) if record.last_used_at is not None else None
        ),
        permission_grant=sorted(record.permission_grant)
        if record.permission_grant is not None
        else None,
    )


# ---------------------------------------------------------------------------
# Audit helper
# ---------------------------------------------------------------------------


async def audit_token_action(
    principal: Principal, action: str, lookup_id: str, args_summary: str
) -> None:
    await write_audit(
        AuditRecord(
            subject=principal.subject,
            principal_uid=principal.uid,
            permission="tokens",
            target="mcp-gateway",
            action=action,
            action_type="state_change",
            args_summary=args_summary,
            timestamp=time.time(),
            request_id=current_request_id(),
            token_id=lookup_id,
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
    settings: Annotated[Settings, Depends(get_state_settings)],
) -> MintTokenResponse:
    """Mint a broker-issued PAT for the calling (Keycloak-JWT-authenticated) principal.

    Authentication for THIS route is unchanged (``keycloak_dependency`` --
    the same JWT dependency every other ``/v1`` route uses). Only the
    returned credential type changed, from an RFC 8693 token-exchange JWT to
    a PAT -- see this module's docstring for why a PAT must never be able to
    authenticate here.
    """
    registry = get_token_registry(request)
    try:
        await registry.check_mint_rate_limit(principal.subject)
    except PatMintRateLimitError as exc:
        raise RateLimitedHTTPException(
            str(exc),
            limiter=RateLimiter.PAT_MINT,
            retry_after_seconds=exc.retry_after_seconds,
        ) from exc

    # Permission PAT grant (issue #144 step 4) -- see MintTokenRequest
    # .permissions's docstring for why this check is advisory-only: it
    # exists purely to name the offending permissions in a clear error
    # right now, never as the sole thing preventing escalation. Enforcement
    # is the intersection get_principal_permissions performs against the
    # caller's CURRENT permissions on every request, which does not
    # consult this check at all.
    permission_grant: frozenset[str] | None = None
    if body.permissions is not None:
        requested = frozenset(body.permissions)
        current_caps = get_principal_permissions(
            principal, get_broker_state(request).entitlement_policy
        )
        missing = sorted(requested - current_caps)
        if missing:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    "Cannot grant permissions you don't currently hold: "
                    + ", ".join(missing)
                ),
            )
        permission_grant = requested

    plaintext, lookup_id, secret_hash = mint_pat()
    now = time.time()

    if body.never_expires:
        expires_at: float | None = None
        logger.warning(
            "tokens.pat_minted_without_expiry",
            subject=principal.subject,
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
                permission_grant=permission_grant,
            )
        )
    except DuplicateNameError as exc:
        logger.warning(
            "tokens.mint_duplicate_name", subject=principal.subject, name=name
        )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail=str(exc)
        ) from exc
    await registry.record_mint(principal.subject)

    # Log lookup_id-only — never the token itself.
    await audit_token_action(
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
        permission_grant=sorted(permission_grant)
        if permission_grant is not None
        else None,
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

    Covers every PAT minted for the caller regardless of mint path --
    both ``POST /v1/tokens`` and the OAuth discovery bootstrap flow mint
    through the same ``TokenRegistry``, keyed by the same principal id (see
    this module's docstring). Revoked rows stay listed (``revoked_at`` set)
    rather than disappearing, so the portal can show a revoked/active/expired
    status.
    """
    registry = get_token_registry(request)
    rows = await registry.list_for_principal(principal.subject)
    return [to_summary(r) for r in rows]


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
    registry = get_token_registry(request)

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

    await audit_token_action(
        principal, "token.revoked", lookup_id, args_summary=f"lookup_id={lookup_id}"
    )

    return RevokeTokenResponse(lookup_id=lookup_id, revoked=True)


@router.delete(
    "/{lookup_id}/record",
    response_model=DeleteTokenResponse,
    summary="Delete the row of a revoked or expired PAT",
)
async def delete_token_record(
    lookup_id: str,
    request: Request,
    principal: Annotated[Principal, Depends(keycloak_dependency)],
) -> DeleteTokenResponse:
    """Hard-delete the caller's own token row, so revoked and expired rows do not pile up on the Tokens page.

    Distinct from ``DELETE /v1/tokens/{lookup_id}``, which revokes and keeps
    the row as a tombstone. An active token is refused with 409: revoke it
    first, so a single mis-click can never both disable and erase a
    credential.
    """
    registry = get_token_registry(request)

    owner_principal_id = await registry.owner_principal_id(lookup_id)
    if owner_principal_id is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Unknown token"
        )
    if owner_principal_id != principal.subject:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Not your token"
        )

    # A record only ever moves from active to inactive, so an inactive record
    # read here is still inactive when delete_inactive() runs.
    record = await registry.get(principal.subject, lookup_id)
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Unknown token"
        )
    if record.is_active(time.time()):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Token is still active; revoke it before deleting it",
        )

    deleted = await registry.delete_inactive(principal.subject, frozenset({lookup_id}))
    if deleted:
        await audit_token_action(
            principal,
            "token.deleted",
            lookup_id,
            args_summary=f"lookup_id={lookup_id}",
        )
    return DeleteTokenResponse(lookup_id=lookup_id, deleted=True)


@router.delete(
    "",
    response_model=ClearTokensResponse,
    summary="Delete every revoked or expired PAT row the caller owns",
)
async def clear_inactive_tokens(
    request: Request,
    principal: Annotated[Principal, Depends(keycloak_dependency)],
    inactive: Annotated[bool, Query()],
) -> ClearTokensResponse:
    """Delete the caller's revoked and expired token rows; active tokens are never touched.

    ``inactive=true`` is required: a bare ``DELETE /v1/tokens`` (or
    ``inactive=false``) is rejected with 422 rather than doing anything.
    """
    if not inactive:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="inactive=true is required",
        )
    registry = get_token_registry(request)

    deleted = await registry.delete_inactive(principal.subject)
    for lookup_id in deleted:
        await audit_token_action(
            principal,
            "token.deleted",
            lookup_id,
            args_summary=f"lookup_id={lookup_id}",
        )
    return ClearTokensResponse(deleted=len(deleted))
