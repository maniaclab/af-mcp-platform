"""GET/DELETE /v1/admin/tokens -- admin listing and revocation of another principal's PATs (issue #336).

Gated by ``require_admin``. Without these, cutting off one user during an
incident meant hand-editing Vault; here an admin lists a principal's PATs,
revokes one, or revokes all of a principal's active PATs in one CAS write.

Revocation is the same ``TokenRegistry.revoke``/``revoke_all`` an owner's own
``DELETE /v1/tokens/{lookup_id}`` uses: it sets ``revoked_at`` on the record,
which PAT validation checks on every request, so it takes effect on the
owner's next request. Each revoked token emits a ``token.revoked`` audit
event with the admin as ``principal_sub`` (the actor) and the owner in
``args_summary`` as ``subject=`` -- the same event name the owner-initiated
route emits, so one query finds every revocation.

Deliberately no admin delete-of-row: clearing revoked rows is the owner's
housekeeping (``DELETE /v1/tokens/{lookup_id}/record``); an admin has no need
to erase the tombstone of a token they revoked.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, ConfigDict

from af_mcp_broker.api.tokens import (
    RevokeTokenResponse,
    TokenSummary,
    _audit,
    _registry,
    _to_summary,
)
from af_mcp_broker.identity import Principal, require_admin

router = APIRouter(prefix="/admin/tokens", tags=["admin"])


class RevokeAllTokensResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    subject: str
    # lookup_ids this call revoked; tokens that were already revoked or
    # expired are not included.
    revoked: list[str]


async def _audit_revocation(
    admin: Principal, lookup_id: str, owner_subject: str
) -> None:
    await _audit(
        admin,
        "token.revoked",
        lookup_id,
        args_summary=f"lookup_id={lookup_id} subject={owner_subject} by_admin=true",
    )


@router.get(
    "",
    response_model=list[TokenSummary],
    summary="List another principal's PATs (admin)",
)
async def list_principal_tokens(
    request: Request,
    _admin: Annotated[Principal, Depends(require_admin)],
    subject: Annotated[str, Query(min_length=1)],
) -> list[TokenSummary]:
    registry = _registry(request)
    rows = await registry.list_for_principal(subject)
    return [_to_summary(r) for r in rows]


@router.delete(
    "/{lookup_id}",
    response_model=RevokeTokenResponse,
    summary="Revoke one PAT of any principal (admin)",
)
async def revoke_principal_token(
    lookup_id: str,
    request: Request,
    admin: Annotated[Principal, Depends(require_admin)],
) -> RevokeTokenResponse:
    registry = _registry(request)

    # The owner is resolved from the lookup index rather than taken from the
    # caller, which is what lets an admin revoke a token they do not own.
    owner_principal_id = await registry.owner_principal_id(lookup_id)
    if owner_principal_id is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Unknown token"
        )

    record = await registry.revoke(owner_principal_id, lookup_id)
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Unknown token"
        )

    await _audit_revocation(admin, lookup_id, owner_principal_id)
    return RevokeTokenResponse(lookup_id=lookup_id, revoked=True)


@router.delete(
    "",
    response_model=RevokeAllTokensResponse,
    summary="Revoke every active PAT of a principal (admin)",
)
async def revoke_all_principal_tokens(
    request: Request,
    admin: Annotated[Principal, Depends(require_admin)],
    subject: Annotated[str, Query(min_length=1)],
) -> RevokeAllTokensResponse:
    registry = _registry(request)

    records = await registry.revoke_all(subject)
    for record in records:
        await _audit_revocation(admin, record.lookup_id, subject)
    return RevokeAllTokensResponse(
        subject=subject, revoked=[r.lookup_id for r in records]
    )
