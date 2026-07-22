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
    """Returns 200 when both JWKS and backends config are available."""
    settings: Settings = (
        cast("Settings", getattr(request.app.state, "settings", None)) or Settings()
    )

    jwks_ok = False
    try:
        keys = await get_jwks(settings)
        jwks_ok = len(keys) > 0
    except Exception:  # noqa: BLE001  # readiness probe: broad catch is intentional
        logger.warning("readyz_jwks_check_failed")

    # backends_loaded is set on app.state during the lifespan startup handler.
    backends_ok: bool = getattr(request.app.state, "backends_loaded", False)

    all_ready = jwks_ok and backends_ok
    if not all_ready:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    return ReadinessResponse(
        status="ready" if all_ready else "not_ready",
        jwks_reachable=jwks_ok,
        backends_loaded=backends_ok,
    )
