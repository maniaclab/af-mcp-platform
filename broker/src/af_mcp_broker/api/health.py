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
    services_loaded: bool
    services_count: int


@router.get(
    "/healthz",
    response_model=HealthResponse,
    summary="Liveness probe",
)
async def healthz() -> HealthResponse:
    """Return 200 OK unconditionally, as long as the process is alive."""
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
    """Return 200 as long as JWKS is reachable.

    An empty service list is a valid degraded state — /v1/identities,
    /v1/permissions, and /v1/x509/proxy don't need any service configured
    (issue #29) — so services_loaded/services_count are informational only
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

    # services_loaded/services are set on app.state during the lifespan
    # startup handler. services_loaded reflects whether services.yaml parsed
    # without error, not whether any service is configured.
    services_ok: bool = getattr(request.app.state, "services_loaded", False)
    services_count: int = len(getattr(request.app.state, "services", []))

    if not jwks_ok:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    return ReadinessResponse(
        status="ready" if jwks_ok else "not_ready",
        jwks_reachable=jwks_ok,
        services_loaded=services_ok,
        services_count=services_count,
    )
