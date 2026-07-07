from __future__ import annotations

import sys
from contextlib import asynccontextmanager
from typing import AsyncGenerator, TextIO

import structlog
from fastapi import FastAPI, HTTPException, Request
from fastapi.exception_handlers import http_exception_handler
from fastapi.responses import JSONResponse, Response
from pydantic import ValidationError

from af_mcp_broker._version import version as __version__
from af_mcp_broker.api.router import router as v1_router
from af_mcp_broker.audit.logger import init_audit_logger
from af_mcp_broker.authorization import EntitlementPolicy, load_policy
from af_mcp_broker.config import Settings
from af_mcp_broker.credentials import (
    CredentialCache,
    CredentialRegistry,
    OIDCProvider,
    X509Provider,
)
from af_mcp_broker.identity import get_jwks
from af_mcp_broker.logging import configure_logging
from af_mcp_broker.mcp.aggregator import aggregator_app
from af_mcp_broker.mcp.registry import BackendRegistry

logger = structlog.get_logger(__name__)


def _open_audit_output(dest: str) -> TextIO:
    """Resolve the AUDIT_LOG_FILE setting to a writable stream.

    "-" means stdout; any other value is opened for appending.
    """
    if dest == "-":
        return sys.stdout
    return open(dest, "a")  # noqa: SIM115 - closed on lifespan shutdown


@asynccontextmanager
async def lifespan(application: FastAPI) -> AsyncGenerator[None, None]:
    settings = Settings()
    configure_logging(settings.log_level)

    # --- Authorization: the authorization/ engine matches the shipped policy.yaml.
    try:
        entitlement_policy = load_policy(settings.policy_file)
    except FileNotFoundError:
        logger.warning("policy_file_not_found", path=settings.policy_file)
        entitlement_policy = EntitlementPolicy()

    # --- Backend registry (config-only; adding a backend needs no code change).
    backend_registry = BackendRegistry()
    try:
        backend_registry.load(settings.backends_file)
    except FileNotFoundError:
        logger.warning("backends_file_not_found", path=settings.backends_file)
    backends = backend_registry.all_backends()

    # --- Credential subsystem: cache + janitor + provider registry.
    credential_cache = CredentialCache()
    credential_cache.start_janitor()

    oidc_provider = OIDCProvider(settings, credential_cache)
    x509_provider = X509Provider(settings, credential_cache)
    credential_registry = CredentialRegistry([oidc_provider, x509_provider])

    # Map each backend target to a provider by its declared auth_type.
    #   bearer -> OIDCProvider (stored brokered IAM token)
    #   x509   -> X509Provider (voms-proxy minted from the user's ~/.globus cert)
    #   none   -> no user credential required, so no provider is registered.
    x509_targets: list[str] = []
    for spec in backends:
        if spec.auth_type == "bearer":
            credential_registry.register(spec.name, oidc_provider)
        elif spec.auth_type == "x509":
            credential_registry.register(spec.name, x509_provider)
            x509_targets.append(spec.name)

    # --- Audit: without init the module drops every record. Honor AUDIT_LOG_FILE.
    audit_output = _open_audit_output(settings.audit_log_file)
    init_audit_logger(audit_output)

    application.state.settings = settings
    application.state.entitlement_policy = entitlement_policy
    application.state.backend_registry = backend_registry
    application.state.backends = backends
    application.state.backends_loaded = bool(backends)
    application.state.credential_cache = credential_cache
    application.state.credential_registry = credential_registry
    application.state.x509_provider = x509_provider
    application.state.x509_targets = x509_targets

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
        version=__version__,
        keycloak_issuer=settings.keycloak_issuer,
        policy_file=settings.policy_file,
        backends_file=settings.backends_file,
        backends_count=len(backends),
        x509_targets=x509_targets,
    )

    yield

    await credential_cache.stop_janitor()
    if audit_output is not sys.stdout:
        audit_output.close()
    logger.info("af_mcp_broker_stopped")


# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------

app = FastAPI(
    title="AF MCP Broker",
    version=__version__,
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
