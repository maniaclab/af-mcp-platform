from __future__ import annotations

import os
from contextlib import asynccontextmanager
from typing import Any, AsyncGenerator

import structlog
import yaml  # type: ignore[import-untyped]
from fastapi import FastAPI, HTTPException, Request
from fastapi.exception_handlers import http_exception_handler
from fastapi.responses import JSONResponse, Response
from pydantic import ValidationError

from af_mcp_broker.api.router import router as v1_router
from af_mcp_broker.config import Settings
from af_mcp_broker.identity import get_jwks
from af_mcp_broker.logging import configure_logging
from af_mcp_broker.mcp.aggregator import aggregator_app

logger = structlog.get_logger(__name__)


def _load_yaml_file(path: str, label: str) -> dict[str, Any] | list[Any]:
    """Load a YAML file and return the parsed content.

    Returns an empty dict when the file does not exist, so the application
    degrades gracefully in development environments without full config.
    """
    if not os.path.exists(path):
        logger.warning(f"{label}_file_not_found", path=path)
        return {}
    with open(path) as fh:
        data = yaml.safe_load(fh)
    if data is None:
        return {}
    return data


@asynccontextmanager
async def lifespan(application: FastAPI) -> AsyncGenerator[None, None]:
    settings = Settings()
    configure_logging(settings.log_level)

    # Load policy and backends into app state so route handlers can access them
    # via request.app.state without passing Settings through every dependency.
    policy = _load_yaml_file(settings.policy_file, "policy")
    backends_raw = _load_yaml_file(settings.backends_file, "backends")

    application.state.policy = policy
    application.state.settings = settings

    # backends.yaml is expected to have a top-level "backends" list.
    if isinstance(backends_raw, dict):
        application.state.backends = backends_raw.get("backends", [])
    else:
        application.state.backends = backends_raw

    application.state.backends_loaded = bool(application.state.backends)

    # Prime the JWKS cache at startup so the first request does not pay the
    # latency cost of a remote fetch.
    try:
        keys = await get_jwks(settings)
        logger.info("jwks_cache_primed", key_count=len(keys))
    except Exception as exc:
        # Non-fatal at startup — the cache will be retried on the first request.
        logger.warning("jwks_cache_prime_failed", error=str(exc))

    logger.info(
        "af_mcp_broker_started",
        version="0.0.1",
        keycloak_issuer=settings.keycloak_issuer,
        policy_file=settings.policy_file,
        backends_file=settings.backends_file,
        backends_count=len(application.state.backends),
    )

    yield

    logger.info("af_mcp_broker_stopped")


# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------

app = FastAPI(
    title="AF MCP Broker",
    version="0.1.0",
    description=(
        "Credential-brokered MCP gateway for the UChicago ATLAS Analysis Facility. "
        "Provides Identity, Authorization, Credentialing, and Audit subsystems."
    ),
    lifespan=lifespan,
)

# Mount the MCP aggregator at /mcp. Requests to /mcp/** are handled entirely
# by the aggregator_app sub-application; they do not pass through the broker's
# FastAPI middleware chain after the mount point.
app.mount("/mcp", aggregator_app)

app.include_router(v1_router)


# ---------------------------------------------------------------------------
# Prometheus metrics
# ---------------------------------------------------------------------------

try:
    from prometheus_fastapi_instrumentator import Instrumentator  # type: ignore[import]

    Instrumentator().instrument(app).expose(app, endpoint="/metrics")
except ImportError:
    # prometheus-fastapi-instrumentator is an optional dependency. The broker
    # functions correctly without it; metrics simply won't be available.
    logger.debug("prometheus_instrumentator_not_installed")


# ---------------------------------------------------------------------------
# Global exception handlers
# ---------------------------------------------------------------------------


@app.exception_handler(HTTPException)
async def _http_exception_handler(request: Request, exc: HTTPException) -> Response:
    # Delegate to FastAPI's built-in handler so WWW-Authenticate headers etc.
    # are preserved, then let structlog capture the event.
    logger.info(
        "http_exception",
        status_code=exc.status_code,
        detail=exc.detail,
        path=request.url.path,
    )
    return await http_exception_handler(request, exc)


@app.exception_handler(ValidationError)
async def _validation_error_handler(
    request: Request, exc: ValidationError
) -> JSONResponse:
    logger.warning(
        "request_validation_error",
        path=request.url.path,
        errors=exc.errors(),
    )
    return JSONResponse(
        status_code=422,
        content={"detail": exc.errors()},
    )
