from __future__ import annotations

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, SecretStr

from af_mcp_broker.identity import Principal, keycloak_dependency

logger = structlog.get_logger(__name__)

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
    credential_type: str
    expires_at: str  # ISO-8601
    remaining_seconds: int
    # bearer_token / scitokens are returned here; PEM is never returned.
    token: str | None = None


class ProxyRequest(BaseModel):
    model_config = ConfigDict(frozen=True)

    # SecretStr prevents the passphrase from appearing in repr/logs.
    passphrase: SecretStr
    valid: str = "12:00"
    voms: str = "atlas"


class ProxyMetadata(BaseModel):
    model_config = ConfigDict(frozen=True)

    dn: str
    voms_attributes: list[str]
    expires_at: str  # ISO-8601
    remaining_seconds: int
    # PEM is intentionally absent from this model — the proxy is stored
    # server-side and never returned to callers.


class ProxyCacheStatus(BaseModel):
    model_config = ConfigDict(frozen=True)

    cached: bool
    dn: str | None = None
    voms_attributes: list[str] = []
    expires_at: str | None = None
    remaining_seconds: int | None = None


# ---------------------------------------------------------------------------
# Credential subsystem stubs — replaced by real implementations when the
# backing stores (Vault, SciTokens issuer, proxy cache) are wired up.
# ---------------------------------------------------------------------------


async def _issue_credential(
    principal: Principal,
    target: str,
    min_remaining_seconds: int,
    app_state: object,
) -> IssuedCredential:
    """Look up a cached credential or issue a new one for the target.

    Raises HTTPException(409) when the target requires a proxy but the proxy
    cache is empty — the client must call POST /v1/x509/proxy first.
    """
    proxy_status: ProxyCacheStatus = _get_proxy_cache_status(principal, app_state)

    if target.startswith("rucio") or target.startswith("grid"):
        if not proxy_status.cached:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "error": "proxy_unlock_required",
                    "unlock_endpoint": "/v1/x509/proxy",
                },
            )

    # Stub: return placeholder until real token issuance is implemented.
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail=f"Credential issuance for target '{target}' is not yet implemented",
    )


def _get_proxy_cache_status(
    principal: Principal, app_state: object
) -> ProxyCacheStatus:
    """Read the proxy cache for the caller's unixname.

    The real implementation reads from a Redis store keyed by uid. This stub
    always returns uncached so that downstream logic behaves correctly before
    the cache is wired up.
    """
    return ProxyCacheStatus(cached=False)


async def _burn_credentials(principal: Principal, app_state: object) -> None:
    """Invalidate all cached credentials for the caller.

    No-op until the credential store is wired up.
    """
    logger.info("credential_burn_requested", subject=principal.subject)


async def _issue_proxy(
    principal: Principal,
    passphrase: SecretStr,
    valid: str,
    voms: str,
    app_state: object,
) -> ProxyMetadata:
    """Run voms-proxy-init against the user's certificate, store the proxy.

    The passphrase is consumed here and must never be logged or forwarded
    further. PassphraseRedactProcessor in the logging pipeline ensures that
    any accidental structlog calls with a 'passphrase' key are sanitised.

    Raises HTTPException(424) when the ATLAS IAM identity is not linked — the
    proxy workflow requires a delegated certificate from ATLAS IAM.
    """
    if principal.iam_sub is None:
        raise HTTPException(
            status_code=status.HTTP_424_FAILED_DEPENDENCY,
            detail={
                "error": "atlas_iam_not_linked",
                "message": (
                    "An ATLAS IAM identity must be linked before a VOMS proxy "
                    "can be generated. Link at POST /v1/identities/link."
                ),
            },
        )

    logger.info(
        "proxy_issuance_requested",
        subject=principal.subject,
        unixname=principal.unixname,
        voms=voms,
        valid=valid,
        # passphrase is intentionally absent — PassphraseRedactProcessor is a
        # belt-and-suspenders guard; never pass it here at all.
    )

    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail="VOMS proxy issuance is not yet implemented",
    )


async def _burn_proxy(principal: Principal, app_state: object) -> None:
    """Revoke and delete the cached proxy for the caller."""
    logger.info("proxy_burn_requested", subject=principal.subject)


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
    return await _issue_credential(
        principal, body.target, body.min_remaining_seconds, request.app.state
    )


@router.delete(
    "/credential",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Burn cached credentials",
)
async def delete_credential(
    request: Request,
    principal: Principal = Depends(keycloak_dependency),
) -> None:
    await _burn_credentials(principal, request.app.state)


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
    # PassphraseRedactProcessor handles any accidental passphrase leakage in
    # structlog calls within _issue_proxy. We do not log the body here.
    return await _issue_proxy(
        principal,
        body.passphrase,
        body.valid,
        body.voms,
        request.app.state,
    )


@router.get(
    "/x509/proxy/status",
    response_model=ProxyCacheStatus,
    summary="Check proxy cache status",
)
async def proxy_status(
    request: Request,
    principal: Principal = Depends(keycloak_dependency),
) -> ProxyCacheStatus:
    return _get_proxy_cache_status(principal, request.app.state)


@router.delete(
    "/x509/proxy",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Revoke cached proxy",
)
async def delete_proxy(
    request: Request,
    principal: Principal = Depends(keycloak_dependency),
) -> None:
    await _burn_proxy(principal, request.app.state)
