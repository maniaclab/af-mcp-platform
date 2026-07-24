from __future__ import annotations

import sys
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, TextIO

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator

import structlog
from fastapi import FastAPI, HTTPException, Request
from fastapi.exception_handlers import http_exception_handler
from fastapi.responses import JSONResponse, Response
from pydantic import ValidationError
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

from af_mcp_broker._version import version as __version__
from af_mcp_broker.api.router import router as v1_router
from af_mcp_broker.api.wellknown import router as wellknown_router
from af_mcp_broker.audit.logger import init_audit_logger
from af_mcp_broker.authorization import EntitlementPolicy, load_policy
from af_mcp_broker.config import Settings
from af_mcp_broker.credentials import (
    CredentialCache,
    CredentialRegistry,
    OIDCProvider,
    X509Provider,
)
from af_mcp_broker.credentials.cache import RateLimitError
from af_mcp_broker.http import aclose_http_client
from af_mcp_broker.identity import build_dev_principal, get_jwks, issuer_is_local
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
    return Path(dest).open("a")


@asynccontextmanager
async def lifespan(application: FastAPI) -> AsyncGenerator[None, None]:
    settings = Settings()
    configure_logging(settings.log_level)

    # --- Local-development auth bypass. When BROKER_DEV_INSECURE_PRINCIPAL is
    # set we parse it into a Principal at startup and refuse to boot unless
    # the configured issuer clearly points at a local host — this is the
    # only line of defence against the bypass being enabled in production
    # by mistake, so it must be loud and fail-closed.
    application.state.dev_bypass_active = False
    application.state.dev_bypass_principal = None
    if settings.dev_insecure_principal is not None:
        if not issuer_is_local(settings.oidc_issuer):
            msg = (
                "BROKER_DEV_INSECURE_PRINCIPAL is set but OIDC_ISSUER "
                f"({settings.oidc_issuer!r}) does not look like a local "
                "development host. Refusing to start. Local hosts are "
                "'localhost', '127.0.0.1', '::1', or a hostname ending in "
                "'.localhost' / '.local' / '.test'."
            )
            raise RuntimeError(msg)
        # build_dev_principal raises RuntimeError with a clear message on
        # bad JSON or missing required keys — propagate as-is.
        dev_principal = build_dev_principal(settings.dev_insecure_principal)
        application.state.dev_bypass_active = True
        application.state.dev_bypass_principal = dev_principal
        logger.warning(
            "dev_auth_bypass_active",
            message="AUTH BYPASSED — DO NOT USE IN PRODUCTION",
            oidc_issuer=settings.oidc_issuer,
            unixname=dev_principal.unixname,
            uid=dev_principal.uid,
        )

    # --- Authorization: the authorization/ engine matches the shipped policy.yaml.
    try:
        entitlement_policy = load_policy(settings.policy_file)
    except FileNotFoundError:
        logger.warning("policy_file_not_found", path=settings.policy_file)
        entitlement_policy = EntitlementPolicy()

    # --- Backend registry (config-only; adding a backend needs no code change).
    # backends_loaded means "backends.yaml parsed without error" — an empty
    # `backends: []` is a valid, successfully-parsed degraded state (issue #29);
    # it is only False when the file is missing or fails to parse.
    backend_registry = BackendRegistry()
    try:
        backend_registry.load(settings.backends_file)
        backends_loaded = True
    except FileNotFoundError:
        logger.warning("backends_file_not_found", path=settings.backends_file)
        backends_loaded = False
    backends = backend_registry.all_backends()
    if not backends:
        logger.warning("no_backends_configured")

    # --- Credential subsystem: cache + janitor + provider registry.
    credential_cache = CredentialCache(
        max_failed_unlocks=settings.credential_unlock_max_failures,
        unlock_window_seconds=settings.credential_unlock_window_seconds,
    )
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

    # --- Metrics: /metrics lives on its own port (chart NetworkPolicy allows
    # Prometheus only there), served by prometheus_client's thread so the
    # single uvicorn worker owns the process-wide registry.
    metrics_server = None
    application.state.metrics_port = None
    if settings.metrics_port >= 0:
        try:
            from prometheus_client import start_http_server

            metrics_server, _ = start_http_server(settings.metrics_port)
            application.state.metrics_port = metrics_server.server_port
            logger.info("metrics_server_started", port=metrics_server.server_port)
        except ImportError:
            logger.debug("prometheus_client_not_installed")

    application.state.settings = settings
    application.state.entitlement_policy = entitlement_policy
    application.state.backend_registry = backend_registry
    application.state.backends = backends
    application.state.backends_loaded = backends_loaded
    application.state.credential_cache = credential_cache
    application.state.credential_registry = credential_registry
    application.state.oidc_provider = oidc_provider
    application.state.x509_provider = x509_provider
    application.state.x509_targets = x509_targets

    # Prime the JWKS cache at startup so the first request does not pay the
    # latency cost of a remote fetch.
    try:
        keys = await get_jwks(settings)
        logger.info("jwks_cache_primed", key_count=len(keys))
    except Exception as exc:  # noqa: BLE001  # non-fatal prime; broad catch intentional
        # Non-fatal at startup — the cache will be retried on the first request.
        logger.warning("jwks_cache_prime_failed", error=str(exc))

    logger.info(
        "af_mcp_broker_started",
        version=__version__,
        oidc_issuer=settings.oidc_issuer,
        policy_file=settings.policy_file,
        backends_file=settings.backends_file,
        backends_count=len(backends),
        x509_targets=x509_targets,
    )

    yield

    await credential_cache.stop_janitor()
    await aclose_http_client()
    if metrics_server is not None:
        metrics_server.shutdown()
        metrics_server.server_close()
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

# Trust X-Forwarded-{Proto,For,Host} from the fronting proxy so ``request.url``
# reports the client-visible scheme (https) instead of the container-local one
# (http). Load-bearing for /.well-known/cimd, whose self-referential
# ``client_id`` must equal the URL the fetcher used. ``trusted_hosts="*"`` is
# acceptable because the broker pod's HTTP port is only reachable inside the
# cluster via its Service — reaching it already implies cluster-network access.
app.add_middleware(ProxyHeadersMiddleware, trusted_hosts="*")

# Mount the MCP aggregator at /mcp. Requests to /mcp/** are handled entirely
# by the aggregator_app sub-application; they do not pass through the broker's
# FastAPI middleware chain after the mount point.
app.mount("/mcp", aggregator_app)

app.include_router(v1_router)
app.include_router(wellknown_router)


@app.middleware("http")
async def _dev_bypass_header(request: Request, call_next):  # type: ignore[no-untyped-def]
    """Annotate every response with ``X-Dev-Bypass: true`` when the local-dev
    auth bypass is active.

    Making bypassed responses visibly different from real ones is the
    client-side half of the defence-in-depth: any curl/browser interaction
    against a "prod" URL that unexpectedly answers with this header is a
    signal the deployment is misconfigured.
    """
    response = await call_next(request)
    if getattr(request.app.state, "dev_bypass_active", False):
        response.headers["X-Dev-Bypass"] = "true"
    return response


# ---------------------------------------------------------------------------
# Prometheus metrics
# ---------------------------------------------------------------------------

try:
    from prometheus_fastapi_instrumentator import Instrumentator  # type: ignore[import]

    # instrument() records request metrics into the default prometheus
    # registry; the lifespan serves that registry on METRICS_PORT (9090).
    # No expose() here — the API port must not serve /metrics (issue #11).
    Instrumentator().instrument(app)
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
    # A bare pydantic ValidationError reaching here is an internal bug
    # (e.g. building a response model): report a 500, not a client 422.
    # Bad request bodies raise RequestValidationError, which FastAPI's
    # default handler already turns into a 422.
    logger.error(
        "internal_validation_error",
        path=request.url.path,
        errors=exc.errors(),
    )
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"},
    )


@app.exception_handler(RateLimitError)
async def _rate_limit_error_handler(
    request: Request, exc: RateLimitError
) -> JSONResponse:
    # RateLimitError is raised by CredentialCache.get()/check_unlock_rate_limit()
    # from both the OIDC and x509 credential-issuance paths (unlimited
    # passphrase/lookup guessing against a colocated user's stored
    # credentials). Map it to 429 with Retry-After so well-behaved clients —
    # and the portal — back off instead of hammering the endpoint.
    retry_after = exc.retry_after_seconds
    retry_at = datetime.now(UTC).replace(microsecond=0) + timedelta(seconds=retry_after)
    logger.info(
        "rate_limit_exceeded",
        path=request.url.path,
        retry_after_seconds=retry_after,
    )
    return JSONResponse(
        status_code=429,
        content={
            "detail": (
                f"Too many failed unlock attempts. Try again in {retry_after} seconds."
            ),
            "retry_after_seconds": retry_after,
            "retry_at": retry_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        },
        headers={"Retry-After": str(retry_after)},
    )
