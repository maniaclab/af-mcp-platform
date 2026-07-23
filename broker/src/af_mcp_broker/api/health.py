from __future__ import annotations

from typing import cast

import structlog
from fastapi import APIRouter, Request, Response, status
from pydantic import BaseModel, ConfigDict

from af_mcp_broker.config import Settings
from af_mcp_broker.identity import get_jwks

logger = structlog.get_logger(__name__)

router = APIRouter(tags=["health"])


class HealthResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    status: str


class ReadinessResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    status: str
    jwks_reachable: bool
    backends_loaded: bool
    backends_count: int


@router.get(
    "/healthz",
    response_model=HealthResponse,
    summary="Liveness probe",
)
async def healthz() -> HealthResponse:
    """Always returns 200 OK as long as the process is alive."""
    return HealthResponse(status="ok")


@router.get(
    "/readyz",
    response_model=ReadinessResponse,
    summary="Readiness probe",
)
async def readyz(
    request: Request,
    response: Response,
) -> ReadinessResponse:
    """Returns 200 as long as JWKS is reachable.

    An empty backend list is a valid degraded state — /v1/identities,
    /v1/capabilities, and /v1/x509/proxy don't need any backend configured
    (issue #29) — so backends_loaded/backends_count are informational only
    and never gate the HTTP status.
    """
    settings: Settings = (
        cast("Settings", getattr(request.app.state, "settings", None)) or Settings()
    )

    jwks_ok = False
    try:
        keys = await get_jwks(settings)
        jwks_ok = len(keys) > 0
    except Exception:  # noqa: BLE001  # readiness probe: broad catch is intentional
        logger.warning("readyz_jwks_check_failed")

    # backends_loaded/backends are set on app.state during the lifespan
    # startup handler. backends_loaded reflects whether backends.yaml parsed
    # without error, not whether any backend is configured.
    backends_ok: bool = getattr(request.app.state, "backends_loaded", False)
    backends_count: int = len(getattr(request.app.state, "backends", []))

    if not jwks_ok:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    return ReadinessResponse(
        status="ready" if jwks_ok else "not_ready",
        jwks_reachable=jwks_ok,
        backends_loaded=backends_ok,
        backends_count=backends_count,
    )
