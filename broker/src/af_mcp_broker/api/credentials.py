from __future__ import annotations

import time
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Any

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, SecretBytes, SecretStr

from af_mcp_broker.audit.logger import AuditRecord, write_audit
from af_mcp_broker.credentials import (
    CredentialCache,
    CredentialKind,
    CredentialRegistry,
    Krb5TokenAccountError,
    Krb5TokenBadCredentialError,
    Krb5TokenInvalidRequestError,
    Krb5TokenMintError,
    Krb5TokenRateLimitedError,
    KrbTokenProvider,
    NeedsUnlock,
    PosixIdentityRequiredError,
    VomsServiceBadPassphraseError,
    VomsServiceMintError,
    VomsServicePreflightError,
    X509Provider,
)
from af_mcp_broker.identity import Principal, keycloak_dependency

if TYPE_CHECKING:
    from af_mcp_broker.credentials.base import IssuedCredential as _IssuedCredential

log = structlog.get_logger(__name__)

router = APIRouter(tags=["credentials"])

# Separate from `router`: holds only routes authenticated by an AF Broker
# Identity Token (redeem_x509_proxy below), never a Keycloak token. Mounted
# in api/router.py WITHOUT the maintenance-mode dependency -- that
# dependency resolves its caller via keycloak_dependency to check for
# admin-bypass, and an AF Broker Identity Token can never satisfy that (it
# isn't a Keycloak token and carries no groups), so every backend redeem
# call 401'd as "Invalid or expired token" regardless of maintenance state
# when this router was still folded into the gated one.
backend_router = APIRouter(tags=["credentials"])

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class CredentialRequest(BaseModel):
    model_config = ConfigDict(frozen=True)

    target: str
    # Minimum seconds remaining before the caller considers the credential stale.
    min_remaining_seconds: int = 300


class IssuedCredential(BaseModel):
    model_config = ConfigDict(frozen=True)

    target: str
    kind: str  # "bearer" | "x509_proxy_ref" | "none"
    credential_type: str  # provider cred_class
    expires_at: str  # ISO-8601
    remaining_seconds: int
    # bearer credentials carry a token the aggregator injects server-side.
    # x509 credentials return only handle/path metadata — never the PEM.
    token: str | None = None
    proxy_handle: str | None = None
    proxy_path: str | None = None


class ProxyRequest(BaseModel):
    model_config = ConfigDict(frozen=True)

    # SecretStr prevents the passphrase from appearing in repr/logs.
    passphrase: SecretStr
    valid: str = "12:00"
    voms: str = "atlas"
    # Which x509 target to mint for; defaults to the first configured x509 target.
    target: str | None = None
    # Custody consent (service mode): True — store the passphrase in Vault
    # for hands-free renewal (the pre-toggle behavior, and the default so
    # existing callers are unchanged); False — mint and store the proxy but
    # never persist the passphrase, so the link lasts exactly the proxy's
    # validity window. Legacy mode never persists a passphrase either way.
    remember: bool = True


class ProxyMetadata(BaseModel):
    model_config = ConfigDict(frozen=True)

    target: str
    dn: str
    voms_attributes: list[str]
    expires_at: str  # ISO-8601
    remaining_seconds: int
    # PEM is intentionally absent — the proxy is stored server-side.


class KrbTicketRequest(BaseModel):
    model_config = ConfigDict(frozen=True)

    username: str
    # SecretStr prevents the CERN password from appearing in repr/logs.
    password: SecretStr
    # Which krb5-token target to mint for; defaults to the first configured
    # krb5-token target.
    target: str | None = None
    lifetime: str | None = None
    renewable_lifetime: str | None = None
    # Custody consent: True — additionally bootstrap and store a keytab from
    # this same password so future tickets can be renewed/reminted hands-free
    # (tier 4) without the user re-entering their password; False (the
    # default) mints a ticket without persisting anything password-derived.
    remember: bool = False


class KrbTicketMetadata(BaseModel):
    model_config = ConfigDict(frozen=True)

    target: str
    principal: str
    realm: str
    expires_at: str  # ISO-8601
    remaining_seconds: int
    renew_until: str | None = None  # ISO-8601, null if not renewable
    # ccache_b64 is intentionally absent -- the ticket is cached server-side
    # (same "credentials never transit to the client" rule as x509's PEM).


class KrbTicketRedeemResponse(BaseModel):
    """The one response that carries ccache material out of the broker.

    Served only by ``POST /credentials/krb5/redeem`` to callers presenting a
    valid AF Broker Identity Token whose ``aud`` is a configured krb5
    target -- the krb5 analogue of ``ProxyRedeemResponse`` (issue #112's
    "backend calls back" wire format, mirrored here for
    ``af_credentials.krb5``). Read-only: this is whatever
    ``KrbTokenProvider.peek_ticket`` finds already cached or Vault-stored --
    the route never mints or renews.
    """

    model_config = ConfigDict(frozen=True)

    ccache_b64: str
    principal: str
    realm: str
    expires_at: str  # ISO-8601
    remaining_seconds: int
    renew_until: str | None = None  # ISO-8601, null if not renewable


class ProxyCacheStatus(BaseModel):
    model_config = ConfigDict(frozen=True)

    cached: bool
    dn: str | None = None
    voms_attributes: list[str] = []
    expires_at: str | None = None
    remaining_seconds: int | None = None
    # VOMS nickname attribute (issue #191) — same field/gap as
    # ProxyRedeemResponse.nickname: populated in voms-token-service
    # (Vault-backed) mode, None on the legacy cache path (ProxyMeta has no
    # such field). Lets the portal show the resolved CERN/Rucio account for
    # the user to visually confirm.
    nickname: str | None = None


class ProxyRedeemResponse(BaseModel):
    """The one response that carries proxy PEM material out of the broker.

    Served only by ``POST /credentials/x509/redeem`` to callers presenting a
    valid AF Broker Identity Token whose ``aud`` is a configured x509 target
    — the deliberate, audited exception to the portal-facing rule that the
    PEM never leaves the broker (issue #112's "backend calls back" wire
    format; consumed by ``af_credentials.proxy.ProxyClient``).
    """

    model_config = ConfigDict(frozen=True)

    pem: str
    dn: str
    voms_attributes: list[str]
    expires_at: str  # ISO-8601
    remaining_seconds: int
    # VOMS nickname attribute (issue #191) — the subject's CERN/Rucio
    # account, which AF unixnames do not match; consumed by
    # af_credentials.proxy.ProxyClient so backends (e.g. rucio-mcp) have a
    # source of truth other than account=None. None on the legacy
    # (non-Vault) redeem path, which has no such field to plumb it through.
    nickname: str | None = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=UTC).isoformat()


def _registry(request: Request) -> CredentialRegistry:
    registry = getattr(request.app.state, "credential_registry", None)
    if registry is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Credential subsystem is not configured",
        )
    return registry


def _cache(request: Request) -> CredentialCache:
    cache = getattr(request.app.state, "credential_cache", None)
    if cache is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Credential cache is not configured",
        )
    return cache


async def _x509_provider(request: Request, target: str) -> X509Provider:
    """Resolve the ``X509Provider`` registered for *target*.

    Per-target resolution (not a single app-wide default) because each
    x509 ``identity_providers`` entry constructs its own provider — with
    its own voms-token-service URL/VO in service mode — and the /v1 x509
    surfaces must mint/serve via the entry that actually services the
    requested target.
    """
    registry = _registry(request)
    try:
        provider = await registry.resolve(target)
    except KeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No x509 credential provider is configured for '{target}'",
        ) from exc
    if not isinstance(provider, X509Provider):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Target '{target}' is not an x509 target",
        )
    return provider


def _resolve_x509_target(request: Request, target: str | None) -> str:
    if target is not None:
        return target
    targets: list[str] = getattr(request.app.state, "x509_targets", [])
    if not targets:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No x509 target is configured",
        )
    return targets[0]


async def _krb5_provider(request: Request, target: str) -> KrbTokenProvider:
    """Resolve the ``KrbTokenProvider`` registered for *target*.

    Mirrors ``_x509_provider``: each krb5-token ``identity_providers`` entry
    constructs its own provider with its own krb5-token-service client, so
    the /v1/krb5 surfaces must mint via the entry that actually services the
    requested target.
    """
    registry = _registry(request)
    try:
        provider = await registry.resolve(target)
    except KeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No krb5-token credential provider is configured for '{target}'",
        ) from exc
    if not isinstance(provider, KrbTokenProvider):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Target '{target}' is not a krb5-token target",
        )
    return provider


def _resolve_krb5_target(request: Request, target: str | None) -> str:
    if target is not None:
        return target
    targets: list[str] = getattr(request.app.state, "krb5_targets", [])
    if not targets:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No krb5-token target is configured",
        )
    return targets[0]


def _to_response(cred: _IssuedCredential) -> IssuedCredential:
    remaining = max(0, int(cred.expires_at - time.time()))
    common: dict[str, Any] = {
        "target": cred.target,
        "kind": cred.kind.value,
        "credential_type": cred.cred_class,
        "expires_at": _iso(cred.expires_at),
        "remaining_seconds": remaining,
    }
    if cred.kind == CredentialKind.BEARER:
        return IssuedCredential(token=cred.payload.get("access_token"), **common)
    if cred.kind in (CredentialKind.X509_PROXY_REF, CredentialKind.X509_PROXY_REDEEM):
        # proxy_path is absent for the redeem kind — the PEM lives in Vault
        # and backends fetch it via POST /v1/credentials/x509/redeem.
        return IssuedCredential(
            proxy_handle=cred.payload.get("proxy_handle"),
            proxy_path=cred.payload.get("proxy_path"),
            **common,
        )
    return IssuedCredential(**common)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.post(
    "/credential",
    response_model=IssuedCredential,
    summary="Issue or retrieve a cached credential",
)
async def issue_credential(
    body: CredentialRequest,
    request: Request,
    principal: Annotated[Principal, Depends(keycloak_dependency)],
) -> IssuedCredential:
    registry = _registry(request)
    try:
        provider = await registry.resolve(body.target)
    except KeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No credential provider registered for target '{body.target}'",
        ) from exc

    # X509Provider.is_linked() returns a plain False for a principal with no
    # POSIX identity (safe for best-effort status probing elsewhere -- see
    # its docstring), which would otherwise fall through to the generic
    # "not linked" 404 below and lose the more actionable, backend-naming
    # message issue() itself would raise. Surface that message here too,
    # before the generic gate, rather than only reaching it via the
    # POST /v1/x509/proxy route below.
    if isinstance(provider, X509Provider) and (
        principal.uid is None or principal.gid is None or principal.unixname is None
    ):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(
                PosixIdentityRequiredError(body.target, settings=provider.settings)
            ),
        )

    # Gate on linkage BEFORE issue() so an unlinked user gets a clean 404
    # instead of an opaque failure surfacing from inside the provider. Every
    # provider benefits uniformly from this one check rather than each
    # duplicating its own pre-check.
    if not await provider.is_linked(principal):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                f"{type(provider).__name__} not linked. "
                "Visit the portal Identities page to connect it."
            ),
        )

    try:
        cred = await provider.issue(
            principal,
            body.target,
            min_remaining_seconds=body.min_remaining_seconds,
        )
    except NeedsUnlock as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "error": "proxy_unlock_required",
                "unlock_endpoint": exc.unlock_endpoint,
            },
        ) from exc
    except PosixIdentityRequiredError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc
    return _to_response(cred)


@router.delete(
    "/credential",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Burn cached credentials",
)
async def delete_credential(
    request: Request,
    principal: Annotated[Principal, Depends(keycloak_dependency)],
) -> None:
    await _cache(request).revoke_all(principal.subject)


@router.post(
    "/x509/proxy",
    response_model=ProxyMetadata,
    status_code=status.HTTP_201_CREATED,
    summary="Generate and cache a VOMS proxy",
)
async def create_proxy(
    body: ProxyRequest,
    request: Request,
    principal: Annotated[Principal, Depends(keycloak_dependency)],
) -> ProxyMetadata:
    target = _resolve_x509_target(request, body.target)
    provider = await _x509_provider(request, target)
    passphrase = SecretBytes(body.passphrase.get_secret_value().encode())
    try:
        await provider.issue(
            principal, target, passphrase=passphrase, remember=body.remember
        )
    except PermissionError as exc:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=str(exc),
        ) from exc
    except PosixIdentityRequiredError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc
    # voms-token-service mode only (the legacy path raises plain ValueError,
    # deliberately left to the generic handler so its behavior is unchanged):
    # a bad passphrase is the caller's 400 to fix; a service infra failure is
    # a 502 that must not read as "wrong passphrase".
    except VomsServiceBadPassphraseError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc
    except VomsServiceMintError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Proxy minting is temporarily unavailable — retry later.",
        ) from exc

    meta = _cache(request).get_proxy_meta(principal.subject, target)
    if meta is None:  # pragma: no cover - mint succeeded but nothing cached
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Proxy minted but no metadata was cached",
        )
    return ProxyMetadata(
        target=target,
        dn=meta.dn,
        voms_attributes=meta.voms_attributes,
        expires_at=_iso(meta.not_after),
        remaining_seconds=max(0, int(meta.not_after - time.time())),
    )


@router.post(
    "/krb5/ticket",
    response_model=KrbTicketMetadata,
    status_code=status.HTTP_201_CREATED,
    summary="Mint and cache a Kerberos ticket",
)
async def create_krb5_ticket(
    body: KrbTicketRequest,
    request: Request,
    principal: Annotated[Principal, Depends(keycloak_dependency)],
) -> KrbTicketMetadata:
    target = _resolve_krb5_target(request, body.target)
    provider = await _krb5_provider(request, target)
    passphrase = SecretBytes(body.password.get_secret_value().encode())
    try:
        cred = await provider.issue(
            principal,
            target,
            passphrase=passphrase,
            username=body.username,
            lifetime=body.lifetime,
            renewable_lifetime=body.renewable_lifetime,
            remember=body.remember,
        )
    except Krb5TokenBadCredentialError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc
    except Krb5TokenAccountError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)
        ) from exc
    except Krb5TokenInvalidRequestError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)
        ) from exc
    except Krb5TokenRateLimitedError as exc:
        headers = {"Retry-After": exc.retry_after} if exc.retry_after else None
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=str(exc),
            headers=headers,
        ) from exc
    except Krb5TokenMintError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Kerberos ticket issuance is temporarily unavailable — retry later.",
        ) from exc

    payload = cred.payload
    renew_until = payload.get("renew_until")
    return KrbTicketMetadata(
        target=target,
        principal=payload["principal"],
        realm=payload["realm"],
        expires_at=_iso(cred.expires_at),
        remaining_seconds=max(0, int(cred.expires_at - time.time())),
        renew_until=_iso(renew_until) if renew_until is not None else None,
    )


@router.get(
    "/x509/preflight",
    summary="Grid-certificate readiness checklist",
)
async def x509_preflight(
    request: Request,
    principal: Annotated[Principal, Depends(keycloak_dependency)],
    target: str | None = None,
) -> dict[str, Any]:
    """Proxy voms-token-service's ``GET /v1/preflight/{unixname}`` for the caller.

    Answers "is this user's Globus credential in a state where minting could
    possibly work?" without performing a mint — the portal's x509 card
    renders the per-check table (exists/mode/readable + actionable detail)
    straight from the body, which is passed through verbatim: the checklist
    shape is voms-token-service's contract, not the broker's.

    Resolved per target like every other /v1/x509 route, since each x509
    ``identity_providers`` entry may point at its own service. A legacy
    entry (no ``service_url``) has no service to ask — 501; an unreachable
    or erroring service is a 502.
    """
    resolved = _resolve_x509_target(request, target)
    provider = await _x509_provider(request, resolved)
    if principal.unixname is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(
                PosixIdentityRequiredError(resolved, settings=provider.settings)
            ),
        )
    voms_client = provider.voms_client
    if voms_client is None:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail=(
                f"The x509 entry servicing {resolved!r} mints via the legacy "
                "in-cluster Job path (no service_url configured), so there "
                "is no voms-token-service to ask for a credential-readiness "
                "checklist."
            ),
        )
    try:
        return await voms_client.preflight(
            subject=principal.subject, unixname=principal.unixname
        )
    except VomsServicePreflightError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=(
                "The grid-certificate checklist is temporarily unavailable "
                "— retry later."
            ),
        ) from exc


@router.get(
    "/x509/proxy/status",
    response_model=ProxyCacheStatus,
    summary="Check proxy cache status",
)
async def proxy_status(
    request: Request,
    principal: Annotated[Principal, Depends(keycloak_dependency)],
    target: str | None = None,
) -> ProxyCacheStatus:
    """Report whether the caller holds a live VOMS proxy for *target*.

    In voms-token-service mode Vault is authoritative — the same rule the
    redeem path and ``/v1/identities``' ``proxy_expires_at`` already follow:
    the in-memory ProxyMeta only exists on the replica that minted, so
    answering from it made this endpoint's answer vary per replica behind
    round-robin (the portal's active/no-proxy ping-pong). An expired Vault
    proxy reads as absent (``get_proxy`` is expiry-aware). Legacy mode keeps
    the in-memory answer — the tmpfs proxy file is per-replica by design
    there.
    """
    resolved = _resolve_x509_target(request, target)
    provider = await _x509_provider(request, resolved)
    if provider.uses_voms_service:
        store = provider.vault_store
        assert store is not None  # uses_voms_service checked
        record = await store.get_proxy(principal.subject)
        if record is None:
            return ProxyCacheStatus(cached=False)
        # get_proxy only returns records with a proxy; narrow for mypy.
        assert record.not_after is not None
        return ProxyCacheStatus(
            cached=True,
            dn=record.dn,
            voms_attributes=list(record.voms_attributes),
            expires_at=_iso(record.not_after),
            remaining_seconds=max(0, int(record.not_after - time.time())),
            nickname=record.nickname,
        )
    meta = _cache(request).get_proxy_meta(principal.subject, resolved)
    if meta is None:
        return ProxyCacheStatus(cached=False)
    return ProxyCacheStatus(
        cached=True,
        dn=meta.dn,
        voms_attributes=meta.voms_attributes,
        expires_at=_iso(meta.not_after),
        remaining_seconds=max(0, int(meta.not_after - time.time())),
    )


@router.delete(
    "/x509/proxy",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Revoke cached proxy",
)
async def delete_proxy(
    request: Request,
    principal: Annotated[Principal, Depends(keycloak_dependency)],
    target: str | None = None,
) -> None:
    targets: list[str]
    if target is not None:
        targets = [target]
    else:
        targets = getattr(request.app.state, "x509_targets", [])
    for tgt in targets:
        provider = await _x509_provider(request, tgt)
        await provider.revoke(principal, tgt)


_REDEEM_MINT_HINT = (
    "No valid x509/VOMS proxy is cached for this account — "
    "mint one at the AF portal and retry."
)

_REDEEM_RELINK_HINT = (
    "The stored Globus passphrase was rejected (changed password?) — the "
    "x509 identity has been unlinked. Re-link it at the AF portal and retry."
)

_KRB5_REDEEM_MINT_HINT = (
    "No Kerberos ticket is cached for this account — "
    "mint one via POST /v1/krb5/ticket and retry."
)


def _release_audit(
    *,
    subject: str,
    uid: Any,
    audience: str,
    request_id: str,
    outcome: str,
    args_summary: str,
    error: str | None = None,
    nickname: str | None = None,
) -> AuditRecord:
    """One ``x509_proxy_release`` audit record — shared by the legacy and Vault redeem paths so every release (and every failed renewal) is shaped identically.

    ``nickname`` is the resolved VOMS nickname of the released proxy (issue
    #199) — supplied only on the Vault success path, where the store record
    carries it; the legacy path (ProxyMeta has no nickname) and every failure
    path (no proxy resolved) leave it null.
    """
    return AuditRecord(
        principal_sub=subject,
        principal_uid=uid,
        permission=None,
        target=audience,
        action="x509_proxy_release",
        action_type="read",
        args_summary=args_summary,
        timestamp=time.time(),
        request_id=request_id,
        outcome=outcome,
        error=error,
        nickname=nickname,
    )


async def _redeem_from_vault(
    provider: X509Provider,
    *,
    subject: str,
    audience: str,
    uid: Any,
    request_id: str,
) -> ProxyRedeemResponse:
    """Serve the Vault-stored proxy, renewing hands-free when it has expired.

    The voms-token-service-mode half of ``redeem_x509_proxy``: Vault is
    authoritative (a leftover tmpfs-cached proxy from before the feature
    flip is never consulted). An expired proxy with a stored passphrase is
    re-minted via ``X509Provider.renew_from_stored_link``; a bad-passphrase
    failure there has already UNLINKED the identity, so the 404 tells the
    user to re-link rather than merely re-mint. Failed renewals write
    ``outcome="error"`` audit records; infra failures keep the link and
    surface as 502.
    """
    store = provider.vault_store
    assert store is not None  # uses_voms_service checked by the caller
    record = await store.get_proxy(subject)
    renewed = False
    if record is None:
        try:
            record = await provider.renew_from_stored_link(subject, audience)
        except NeedsUnlock as exc:
            if exc.reason == "not_linked":
                # Same actionable 404 as "nothing cached" on the legacy path.
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND, detail=_REDEEM_MINT_HINT
                ) from exc
            await write_audit(
                _release_audit(
                    subject=subject,
                    uid=uid,
                    audience=audience,
                    request_id=request_id,
                    outcome="error",
                    args_summary="hands-free renewal failed: stored passphrase rejected; identity unlinked",
                    error="stored Globus passphrase rejected by voms-token-service",
                )
            )
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail=_REDEEM_RELINK_HINT
            ) from exc
        except VomsServiceMintError as exc:
            await write_audit(
                _release_audit(
                    subject=subject,
                    uid=uid,
                    audience=audience,
                    request_id=request_id,
                    outcome="error",
                    args_summary="hands-free renewal failed: voms-token-service unavailable",
                    error=str(exc),
                )
            )
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="Proxy renewal is temporarily unavailable — retry later.",
            ) from exc
        renewed = True

    # renew_from_stored_link/get_proxy only return records with a proxy.
    assert record.proxy_pem is not None
    assert record.not_after is not None

    await write_audit(
        _release_audit(
            subject=subject,
            uid=uid,
            audience=audience,
            request_id=request_id,
            outcome="success",
            args_summary=(
                f"proxy renewed hands-free and released to backend {audience!r}"
                if renewed
                else f"proxy released to backend {audience!r}"
            ),
            nickname=record.nickname,
        )
    )
    now = time.time()
    return ProxyRedeemResponse(
        pem=record.proxy_pem.get_secret_value(),
        dn=record.dn or "",
        voms_attributes=list(record.voms_attributes),
        expires_at=_iso(record.not_after),
        remaining_seconds=max(0, int(record.not_after - now)),
        nickname=record.nickname,
    )


@backend_router.post(
    "/credentials/x509/redeem",
    response_model=ProxyRedeemResponse,
    summary="Redeem the caller's cached x509 proxy (backend-facing)",
)
async def redeem_x509_proxy(request: Request) -> ProxyRedeemResponse:
    """Release the caller's cached VOMS proxy PEM to an x509 backend.

    Authenticated by an AF Broker Identity Token (NOT a Keycloak token): the
    broker verifies its own RS256 signature and requires ``aud`` to be a
    configured x509 target. The path is deliberately under ``/credentials/``
    rather than ``/x509/`` to match the wire contract af-credentials codes
    against (``POST /v1/credentials/x509/redeem``).

    This is the one deliberate exception to "the PEM never leaves the
    broker": scoped to authenticated backend targets, released once per
    request over in-cluster TLS, and audited as a distinct credential-release
    event. Backends must never persist the PEM (see docs/auth.md).
    """
    issuer = getattr(request.app.state, "broker_token_issuer", None)
    if issuer is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Broker identity tokens are not configured",
        )

    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Bearer token in Authorization header",
        )
    claims = issuer.verify(auth[7:].strip())
    if claims is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired broker identity token",
        )

    subject: str = claims["sub"]
    token_aud: str = claims["aud"]
    request_id = claims.get("jti", "")

    # The token's aud is the service's effective_audience (what the broker
    # mints, issue #257), which can differ from the x509 *target* name the
    # proxy/provider are keyed under. Map it back rather than assuming
    # aud == target name -- that assumption 403'd every renamed x509 backend
    # on 2026-08-27. An aud that maps to no x509 target is genuinely not ours.
    x509_audiences: dict[str, str] = getattr(request.app.state, "x509_audiences", {})
    audience = x509_audiences.get(token_aud)
    if audience is None:
        await write_audit(
            AuditRecord(
                principal_sub=subject,
                principal_uid=claims.get("uid"),
                permission=None,
                target=token_aud,
                action="x509_proxy_release",
                action_type="read",
                args_summary="redeem denied: audience is not an x509 target",
                timestamp=time.time(),
                request_id=request_id,
                outcome="denied",
                error=f"audience {token_aud!r} is not a configured x509 target",
            )
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Audience {token_aud!r} is not a configured x509 target",
        )

    # voms-token-service mode: Vault is authoritative — serve the stored
    # proxy, renewing hands-free with the stored passphrase when it has
    # expired (issue #112's Vault-backed linking). Resolved per audience:
    # each x509 identity_providers entry has its own provider (and possibly
    # its own voms-token-service), so the redeeming backend's target picks
    # the mode and the mint path.
    provider = await _x509_provider(request, audience)
    if provider.uses_voms_service:
        return await _redeem_from_vault(
            provider,
            subject=subject,
            audience=audience,
            uid=claims.get("uid"),
            request_id=request_id,
        )

    cache: CredentialCache = _cache(request)
    meta = cache.get_proxy_meta(subject, audience)
    now = time.time()
    # proxy_path is None for Vault-persisted proxies (voms-token-service
    # mode), which have no local file to read — treat as absent here.
    if meta is None or meta.not_after <= now or meta.proxy_path is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=_REDEEM_MINT_HINT
        )

    try:
        pem = Path(meta.proxy_path).read_text()
    except OSError:
        # Cached metadata without its file is an inconsistency (e.g. tmpfs
        # cleared); from the caller's perspective the proxy is simply gone.
        log.warning(
            "x509_redeem.proxy_file_missing",
            subject=subject,
            target=audience,
            proxy_path=meta.proxy_path,
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=_REDEEM_MINT_HINT
        ) from None

    await write_audit(
        _release_audit(
            subject=subject,
            uid=claims.get("uid"),
            audience=audience,
            request_id=request_id,
            outcome="success",
            args_summary=f"proxy released to backend {audience!r}",
        )
    )

    return ProxyRedeemResponse(
        pem=pem,
        dn=meta.dn,
        voms_attributes=list(meta.voms_attributes),
        expires_at=_iso(meta.not_after),
        remaining_seconds=max(0, int(meta.not_after - now)),
    )


@backend_router.post(
    "/credentials/krb5/redeem",
    response_model=KrbTicketRedeemResponse,
    summary="Redeem the caller's cached Kerberos ticket (backend-facing)",
)
async def redeem_krb5_ticket(request: Request) -> KrbTicketRedeemResponse:
    """Release the caller's cached Kerberos ccache to a krb5 backend.

    Authenticated by an AF Broker Identity Token (NOT a Keycloak token),
    exactly like ``redeem_x509_proxy`` above: the broker verifies its own
    RS256 signature and requires ``aud`` to be a configured krb5 target. The
    path is deliberately under ``/credentials/`` for the same reason x509's
    is -- to match the wire contract af-credentials codes against
    (``POST /v1/credentials/krb5/redeem``).

    Unlike the x509 route, this NEVER mints or renews a ticket: it only
    serves whatever ``KrbTokenProvider.peek_ticket`` finds already cached or
    Vault-stored, 404ing otherwise -- a synchronous backend-to-backend call
    has no way to prompt a user for a CERN password.
    """
    issuer = getattr(request.app.state, "broker_token_issuer", None)
    if issuer is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Broker identity tokens are not configured",
        )

    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Bearer token in Authorization header",
        )
    claims = issuer.verify(auth[7:].strip())
    if claims is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired broker identity token",
        )

    subject: str = claims["sub"]
    token_aud: str = claims["aud"]
    request_id = claims.get("jti", "")

    # Same effective_audience -> target reverse map as x509_audiences above
    # (issue #257) -- the aud a krb5 backend presents may differ from the
    # krb5 target name the ticket/provider are keyed under.
    krb5_audiences: dict[str, str] = getattr(request.app.state, "krb5_audiences", {})
    target = krb5_audiences.get(token_aud)
    if target is None:
        # Mirrors redeem_x509_proxy's audience-not-mapped audit exactly
        # (same inline AuditRecord shape, action renamed for krb5) -- this is
        # security-relevant on its own: krb5_audiences is empty until a real
        # services.yaml consumer is configured, so this 403 is the ONLY
        # outcome this route reaches in any real deployment today.
        await write_audit(
            AuditRecord(
                principal_sub=subject,
                principal_uid=claims.get("uid"),
                permission=None,
                target=token_aud,
                action="krb5_ticket_release",
                action_type="read",
                args_summary="redeem denied: audience is not a krb5 target",
                timestamp=time.time(),
                request_id=request_id,
                outcome="denied",
                error=f"audience {token_aud!r} is not a configured krb5 target",
            )
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Audience {token_aud!r} is not a configured krb5 target",
        )

    provider = await _krb5_provider(request, target)
    cred = await provider.peek_ticket(subject, target)
    if cred is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=_KRB5_REDEEM_MINT_HINT
        )

    payload = cred.payload
    renew_until = payload.get("renew_until")
    now = time.time()

    # Mirrors redeem_x509_proxy's success-path audit (_release_audit's
    # outcome="success" record) -- subject/target/outcome plus resolved
    # principal metadata only, never the ccache material itself.
    await write_audit(
        AuditRecord(
            principal_sub=subject,
            principal_uid=claims.get("uid"),
            permission=None,
            target=target,
            action="krb5_ticket_release",
            action_type="read",
            args_summary=f"ticket for {payload['principal']!r} released to backend {target!r}",
            timestamp=time.time(),
            request_id=request_id,
            outcome="success",
        )
    )

    return KrbTicketRedeemResponse(
        ccache_b64=payload["ccache_b64"],
        principal=payload["principal"],
        realm=payload["realm"],
        expires_at=_iso(cred.expires_at),
        remaining_seconds=max(0, int(cred.expires_at - now)),
        renew_until=_iso(renew_until) if renew_until is not None else None,
    )
