from __future__ import annotations

import structlog
from fastapi import APIRouter, Request, Response, status
from pydantic import BaseModel, ConfigDict

from af_mcp_broker.broker_state import get_broker_state
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

    A broker whose services file is missing or empty never boots, so
    services_count is informational only and never gates the HTTP status.
    """
    state = get_broker_state(request)
    settings = state.settings

    jwks_ok = False
    try:
        keys = await get_jwks(settings, state.http_client)
        jwks_ok = len(keys) > 0
    except Exception:  # noqa: BLE001  # readiness probe: broad catch is intentional
        logger.warning("readyz.jwks_check_failed")

    services_count = len(state.services)

    if not jwks_ok:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    return ReadinessResponse(
        status="ready" if jwks_ok else "not_ready",
        jwks_reachable=jwks_ok,
        services_count=services_count,
    )
