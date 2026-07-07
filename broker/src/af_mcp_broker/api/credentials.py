from __future__ import annotations

import time
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, SecretBytes, SecretStr

from af_mcp_broker.credentials import (
    CredentialCache,
    CredentialKind,
    CredentialRegistry,
    NeedsUnlock,
    X509Provider,
)
from af_mcp_broker.credentials.base import IssuedCredential as _IssuedCredential
from af_mcp_broker.identity import Principal, keycloak_dependency

router = APIRouter(tags=["credentials"])

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


class ProxyMetadata(BaseModel):
    model_config = ConfigDict(frozen=True)

    target: str
    dn: str
    voms_attributes: list[str]
    expires_at: str  # ISO-8601
    remaining_seconds: int
    # PEM is intentionally absent — the proxy is stored server-side.


class ProxyCacheStatus(BaseModel):
    model_config = ConfigDict(frozen=True)

    cached: bool
    dn: str | None = None
    voms_attributes: list[str] = []
    expires_at: str | None = None
    remaining_seconds: int | None = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()


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


def _x509_provider(request: Request) -> X509Provider:
    provider = getattr(request.app.state, "x509_provider", None)
    if provider is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No x509 credential provider is configured",
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


def _to_response(cred: _IssuedCredential) -> IssuedCredential:
    remaining = max(0, int(cred.expires_at - time.time()))
    common = {
        "target": cred.target,
        "kind": cred.kind.value,
        "credential_type": cred.cred_class,
        "expires_at": _iso(cred.expires_at),
        "remaining_seconds": remaining,
    }
    if cred.kind == CredentialKind.BEARER:
        return IssuedCredential(token=cred.payload.get("access_token"), **common)
    if cred.kind == CredentialKind.X509_PROXY_REF:
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
    principal: Principal = Depends(keycloak_dependency),
) -> IssuedCredential:
    registry = _registry(request)
    try:
        cred = await registry.issue(
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
    except KeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No credential provider registered for target '{body.target}'",
        ) from exc
    return _to_response(cred)


@router.delete(
    "/credential",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Burn cached credentials",
)
async def delete_credential(
    request: Request,
    principal: Principal = Depends(keycloak_dependency),
) -> None:
    await _cache(request).revoke_all(principal.uid)


@router.post(
    "/x509/proxy",
    response_model=ProxyMetadata,
    status_code=status.HTTP_201_CREATED,
    summary="Generate and cache a VOMS proxy",
)
async def create_proxy(
    body: ProxyRequest,
    request: Request,
    principal: Principal = Depends(keycloak_dependency),
) -> ProxyMetadata:
    provider = _x509_provider(request)
    target = _resolve_x509_target(request, body.target)
    passphrase = SecretBytes(body.passphrase.get_secret_value().encode())
    try:
        await provider.issue(principal, target, passphrase=passphrase)
    except PermissionError as exc:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=str(exc),
        ) from exc

    meta = _cache(request).get_proxy_meta(principal.uid, target)
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


@router.get(
    "/x509/proxy/status",
    response_model=ProxyCacheStatus,
    summary="Check proxy cache status",
)
async def proxy_status(
    request: Request,
    target: str | None = None,
    principal: Principal = Depends(keycloak_dependency),
) -> ProxyCacheStatus:
    resolved = _resolve_x509_target(request, target)
    meta = _cache(request).get_proxy_meta(principal.uid, resolved)
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
    target: str | None = None,
    principal: Principal = Depends(keycloak_dependency),
) -> None:
    provider = _x509_provider(request)
    targets: list[str]
    if target is not None:
        targets = [target]
    else:
        targets = getattr(request.app.state, "x509_targets", [])
    for tgt in targets:
        await provider.revoke(principal, tgt)
