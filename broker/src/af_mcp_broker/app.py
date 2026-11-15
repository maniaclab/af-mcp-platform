from __future__ import annotations

from contextlib import AsyncExitStack, asynccontextmanager
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator

    from starlette.types import Receive, Scope, Send

import structlog
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.exception_handlers import http_exception_handler
from fastapi.responses import JSONResponse, Response
from pydantic import ValidationError
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

from af_mcp_broker._version import version as __version__
from af_mcp_broker.api.errors import CorrelatedHTTPException
from af_mcp_broker.api.router import router as v1_router
from af_mcp_broker.api.wellknown import router as wellknown_router
from af_mcp_broker.broker_state import broker_state_of
from af_mcp_broker.config import Settings, get_settings
from af_mcp_broker.credentials.errors import (
    CredentialError,
    CredentialForbiddenError,
    CredentialNotFoundError,
    CredentialRateLimitedError,
    CredentialReauthRequiredError,
    CredentialServiceError,
    UnlockRateLimitError,
)
from af_mcp_broker.credentials.stores import VaultLinkStores, build_vault_link_stores
from af_mcp_broker.identity import (
    AdminRequiredError,
    IdentityError,
    InvalidTokenError,
    JwksUnavailableError,
    NotAuthenticatedError,
    PrincipalDirectoryUnavailableError,
    TokenAudienceError,
    TokenExpiredError,
)
from af_mcp_broker.lint_observations import LintObservationStore
from af_mcp_broker.logging import (
    bind_new_correlation_id,
    close_audit_logging,
    configure_logging,
    log_request_finished,
    log_request_received,
)
from af_mcp_broker.maintenance import MaintenanceModeError
from af_mcp_broker.mcp.aggregator import BackendProviders
from af_mcp_broker.otel_metrics import init_otel_metrics, shutdown_otel_metrics
from af_mcp_broker.tracing import init_tracing, instrument_fastapi, shutdown_tracing
from af_mcp_broker.wiring.aggregator import (
    build_job_credential_guide,
    build_mcp_aggregator,
    build_mcp_app,
)
from af_mcp_broker.wiring.checks import validate_services_gated
from af_mcp_broker.wiring.credentials import (
    build_broker_token_issuer,
    build_credential_cache,
    build_credential_providers,
    build_list_cache_invalidator,
    build_oauth21_token_store,
    build_state_cipher,
    resolve_x509_provider,
)
from af_mcp_broker.wiring.http_client import build_http_client
from af_mcp_broker.wiring.identity import (
    build_dev_bypass_principal,
    build_mcp_auth_code_store,
    build_principal_cache,
    build_token_registry,
)
from af_mcp_broker.wiring.lifecycle import (
    open_shared_state,
    prime_jwks_cache,
    start_credmon_sync,
    start_maintenance_store,
    start_metering_pipeline,
    start_metrics_server,
    start_usage_store,
)
from af_mcp_broker.wiring.services import build_identity_targets, build_service_catalog
from af_mcp_broker.wiring.state import build_broker_state
from af_mcp_broker.wiring.vault import build_vault_kv

logger = structlog.get_logger(__name__)


def _warn_replica_hazards(settings: Settings) -> None:
    """Warn, never fail, about configurations that misbehave with more than one broker replica.

    ``mcp_replica_count`` is supplied by the chart; the broker cannot see
    whether the external mechanisms these warnings mention exist, so they can
    only warn.
    """
    multi_replica = (
        settings.mcp_replica_count is not None and settings.mcp_replica_count > 1
    )
    # --- /mcp transport mode (issue #128): a stateful aggregator (the
    # fastmcp/mcp SDK default, mcp_stateless_http=False) pins a streamable-
    # HTTP session to the pod that created it -- safe only with an external
    # session-affinity mechanism (e.g. an ingress hashing on client IP) in
    # front of more than one replica.
    if not settings.mcp_stateless_http and multi_replica:
        logger.warning(
            "mcp_stateful_multi_replica",
            message=(
                "mcp_stateless_http=False with more than one broker replica: "
                "streamable-HTTP sessions are in-process state, so a load "
                "balancer without session affinity will route a session's "
                "later requests to a replica that never created it, which "
                "terminates the session and surfaces as an intermittent "
                "'Session terminated' error to MCP clients. Either leave "
                "mcp_stateless_http at its default (True) or put "
                "client-IP-hash affinity in front of the ingress -- see "
                "docs/architecture.md."
            ),
            replica_count=settings.mcp_replica_count,
        )

    # --- Maintenance mode backend (config.py's maintenance_mode_backend): the
    # in_memory backend is process-local, so toggling maintenance mode (via
    # the admin API, api/admin.py) only takes effect on the replica that
    # handled the toggle -- every other replica keeps admitting requests as
    # if nothing changed. A single-replica or local-dev deployment
    # legitimately wants this default with no extra infra.
    if settings.maintenance_mode_backend == "in_memory" and multi_replica:
        logger.warning(
            "maintenance_mode_in_memory_multi_replica",
            message=(
                "maintenance_mode_backend=in_memory with more than one "
                "broker replica: toggling maintenance mode only affects the "
                "replica that handled the toggle, so other replicas keep "
                "serving normally. Select maintenance_mode_backend=vault or "
                "=postgres for a toggle that's visible to every replica."
            ),
            replica_count=settings.mcp_replica_count,
        )

    # --- Shared cross-replica state (shared_state.py): the Settings validator
    # has already refused more than one replica without a store unless the
    # operator opted into per-replica state; this logs the opt-in so it is
    # visible in pod logs, never silent.
    if not settings.shared_state_url and multi_replica:
        logger.warning(
            "per_replica_state",
            message=(
                "allow_per_replica_state with more than one broker replica "
                "and no shared_state_url: the unlock brute-force budget is "
                "multiplied by the replica count and replica-local caches "
                "are inconsistent. Set shared_state_url -- see "
                'docs/architecture.md "Replica consistency".'
            ),
            replica_count=settings.mcp_replica_count,
        )


@asynccontextmanager
async def lifespan(application: FastAPI) -> AsyncGenerator[dict[str, Any], None]:
    """Build every subsystem in dependency order and tear them down in reverse.

    Each resource with a close registers it on the exit stack as it is built,
    so a failure in any later step still closes the earlier ones.
    """
    async with AsyncExitStack() as stack:
        settings = Settings()
        configure_logging(settings.log_level, settings.audit_log_file)
        # Tracing initializes before any FastMCP object exists: fastmcp 4.0.4
        # acquires its tracer lazily per span, so this early placement is
        # conservative rather than load-bearing (see init_tracing's docstring)
        # -- but it guarantees nothing downstream can ever capture a pre-init
        # no-op tracer. A no-op unless TRACING_ENABLED is set.
        init_tracing(settings)
        # Teardown runs in reverse of the registrations below. Spans still
        # buffered in the batch processor are flushed (a no-op when tracing
        # was never enabled) after the audit output closes, which is after the
        # metering pipeline drains, so the last audit records' traces are
        # flushed too.
        stack.callback(shutdown_tracing)
        stack.callback(close_audit_logging)
        http_client = build_http_client(stack)

        dev_principal = build_dev_bypass_principal(settings)
        _warn_replica_hazards(settings)
        shared_state = open_shared_state(settings, stack)

        catalog = build_service_catalog(settings)
        targets = build_identity_targets(settings, catalog.services)

        # Created ahead of the aggregator: the cache invalidator below reads
        # it, and the credential providers the aggregator needs are built
        # over that invalidator.
        backend_providers = BackendProviders()
        list_cache_invalidator = build_list_cache_invalidator(
            shared_state, backend_providers, stack
        )
        credential_cache = build_credential_cache(
            settings, shared_state, list_cache_invalidator, stack
        )
        vault_kv = await build_vault_kv(settings, http_client)
        oauth21_token_store = build_oauth21_token_store(settings, vault_kv)
        oauth21_state_cipher = build_state_cipher(settings)
        broker_token_issuer = build_broker_token_issuer(settings)
        link_stores = (
            build_vault_link_stores(settings, vault_kv)
            if vault_kv is not None
            else VaultLinkStores()
        )
        providers = build_credential_providers(
            settings,
            service_registry=catalog.service_registry,
            cache=credential_cache,
            issuer=broker_token_issuer,
            token_store=oauth21_token_store,
            link_stores=link_stores,
            http_client=http_client,
        )
        await validate_services_gated(catalog.services, providers.registry)
        x509_provider = await resolve_x509_provider(
            providers.registry, targets.x509_targets
        )

        mcp_auth_code_store = build_mcp_auth_code_store(
            settings, oauth21_state_cipher, shared_state
        )
        token_registries = build_token_registry(settings, vault_kv, shared_state)
        principal_cache = build_principal_cache(
            settings,
            vault_kv,
            http_client,
            dev_bypass_active=dev_principal is not None,
        )
        maintenance_mode_store = await start_maintenance_store(
            settings, vault_kv, stack
        )

        # Where the tool-listing lint's findings are recorded for the admin
        # tables (lint_observations.py): shared, so every replica reports the
        # same.
        lint_observations = LintObservationStore(shared_state)
        usage_store = await start_usage_store(settings, stack)

        # OTel aggregate metrics (otel_metrics.py): a no-op unless
        # OTEL_METRICS_ENABLED. Installed before the pipeline so the worker's
        # first record is counted; flushed after the pipeline drains, so the
        # last records' measurements are exported too.
        init_otel_metrics(settings)
        stack.callback(shutdown_otel_metrics)
        metering = await start_metering_pipeline(settings, usage_store, stack)
        mcp_aggregator = build_mcp_aggregator(
            settings,
            catalog=catalog,
            targets=targets,
            providers=providers,
            backend_providers=backend_providers,
            broker_token_issuer=broker_token_issuer,
            job_credentials=build_job_credential_guide(settings, targets),
            shared_state=shared_state,
            usage_store=usage_store,
            lint_observations=lint_observations,
            metering=metering,
        )
        mcp_app = build_mcp_app(
            mcp_aggregator,
            settings,
            pat_backend=token_registries.backend,
            principal_cache=principal_cache,
            maintenance_mode_store=maintenance_mode_store,
            http_client=http_client,
        )

        metrics_port = start_metrics_server(settings, stack)

        credmon_sync = await start_credmon_sync(
            settings,
            targets=targets,
            credential_registry=providers.registry,
            issuer=broker_token_issuer,
            link_stores=link_stores,
            vault_kv=vault_kv,
            principal_cache=principal_cache,
            http_client=http_client,
            stack=stack,
        )
        application.state.broker = build_broker_state(
            settings,
            http_client=http_client,
            catalog=catalog,
            targets=targets,
            providers=providers,
            credential_cache=credential_cache,
            x509_provider=x509_provider,
            oauth21_token_store=oauth21_token_store,
            oauth21_state_cipher=oauth21_state_cipher,
            token_registry=token_registries.registry,
            principal_cache=principal_cache,
            mcp_auth_code_store=mcp_auth_code_store,
            broker_token_issuer=broker_token_issuer,
            usage_store=usage_store,
            maintenance_mode_store=maintenance_mode_store,
            lint_observations=lint_observations,
            shared_state=shared_state,
            link_stores=link_stores,
            credmon_sync=credmon_sync,
            mcp_aggregator=mcp_aggregator,
            mcp_app=mcp_app,
            dev_bypass_principal=dev_principal,
            metrics_port=metrics_port,
        )

        await prime_jwks_cache(settings, http_client)
        logger.info(
            "af_mcp_broker_started",
            version=__version__,
            oidc_issuer=settings.oidc_issuer,
            policy_file=settings.policy_file,
            services_file=settings.services_file,
            services_count=len(catalog.services),
            x509_targets=targets.x509_targets,
            identity_provider_aliases=list(providers.providers),
        )

        # Entered last: it runs the session manager's task group, which wraps
        # any error raised while it is open in an ExceptionGroup, so every
        # startup step that can fail runs before it. It starts the
        # StreamableHTTPSessionManager (omitting it makes every /mcp/**
        # request 500) and may yield ASGI lifespan state, passed on below.
        mcp_lifespan_state = await stack.enter_async_context(
            mcp_app.lifespan(application)
        )
        yield dict(mcp_lifespan_state or {})
    logger.info("af_mcp_broker_stopped")


# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------


async def _mcp_mount(scope: Scope, receive: Receive, send: Send) -> None:
    """Serve ``/mcp`` with the ASGI app the lifespan built, read from the broker state at request time.

    Starlette's Mount needs a concrete ASGI app at ``app.mount()`` time, which
    is before the lifespan has built the aggregator and its app.
    """
    await broker_state_of(app).mcp_app(scope, receive, send)


app = FastAPI(
    title="AF MCP Broker",
    version=__version__,
    description=(
        "Credential-brokered MCP gateway for an ATLAS Analysis Facility. "
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
# by the aggregator sub-application; they do not pass through the broker's
# FastAPI middleware chain after the mount point.
app.mount("/mcp", _mcp_mount)

app.include_router(v1_router)
app.include_router(wellknown_router)

# HTTP-level spans for the /v1 surface, only when tracing is enabled -- a
# no-op otherwise (no extra ASGI middleware). Health probes and the /mcp
# mount are excluded; see tracing._EXCLUDED_URLS for why /mcp must stay out.
# Instrumenting must happen before the app starts, so this reads the settings
# at import time, where no lifespan exists yet.
instrument_fastapi(app, get_settings())


# Kubelet's liveness/readiness probes hit these every few seconds; logging
# http.request.received/finished for them would flood the log for no
# operational benefit (no subject, no interesting failure mode) -- same
# reasoning as tracing.py's _EXCLUDED_URLS, which exempts them from HTTP
# spans for the same reason. Skipped entirely rather than logged at debug,
# since a busy broker would still mean a debug-level log configuration
# drowns in them.
_REQUEST_LOGGING_EXCLUDED_PATHS = frozenset({"/v1/healthz", "/v1/readyz"})


@app.middleware("http")
async def _bind_request_logging_context(request: Request, call_next):  # type: ignore[no-untyped-def]
    """Binds a fresh correlation_id to structlog's contextvars for every /v1 request (issue #281) and logs its receipt/completion (issue #322).

    ``keycloak_dependency`` binds ``subject`` alongside it once the caller's
    identity resolves (see identity.py's ``get_principal``/its own
    dev-bypass branch), so both fields appear on every log line for the
    rest of the request -- including ``_http_exception_handler``'s --
    without every call site threading them through by hand. Runs outside
    the /mcp mount entirely (see the mount comment above), which is why
    identity_mw.AsgiAuthMiddleware binds its own correlation_id the same
    way for that surface.

    ``http.request.received``/``http.request.finished`` are the only trace
    of a request that stalls or dies before anything downstream logs -- see
    ``logging.log_request_received``/``log_request_finished``'s docstrings
    for why and what they carry. The ``finally`` block below fires whether
    ``call_next`` returns normally or raises, so ``finished`` is always
    logged exactly once per request.
    """
    bind_new_correlation_id()
    if request.url.path in _REQUEST_LOGGING_EXCLUDED_PATHS:
        return await call_next(request)

    start_time = log_request_received(
        logger, method=request.method, path=request.url.path
    )
    status_code: int | None = None
    exc_type: str | None = None
    try:
        response = await call_next(request)
    except Exception as exc:
        exc_type = type(exc).__name__
        raise
    else:
        status_code = response.status_code
        return response
    finally:
        log_request_finished(
            logger, start_time=start_time, status_code=status_code, exc_type=exc_type
        )


@app.middleware("http")
async def _dev_bypass_header(request: Request, call_next):  # type: ignore[no-untyped-def]
    """Annotate every response with ``X-Dev-Bypass: true`` when the local-dev auth bypass is active.

    Making bypassed responses visibly different from real ones is the
    client-side half of the defence-in-depth: any curl/browser interaction
    against a "prod" URL that unexpectedly answers with this header is a
    signal the deployment is misconfigured.
    """
    # Read before call_next: a request routed into the mounted /mcp sub-app has
    # its scope's "app" rebound to that sub-app, which holds no BrokerState.
    dev_bypass_active = broker_state_of(request.app).dev_bypass_principal is not None
    response = await call_next(request)
    if dev_bypass_active:
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
    # metric_namespace prefixes the default http_* series to af_mcp_http_*,
    # matching the custom metrics' naming and the Grafana dashboard's
    # queries (issue #226).
    Instrumentator().instrument(app, metric_namespace="af_mcp")
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
    # af-mcp-platform#288: every /v1 request already gets a correlation_id
    # bound into structlog's contextvars at request start
    # (_bind_request_logging_context above / identity_mw's own equivalent
    # for /mcp), so it's already on the log line just above -- fold it into
    # the response body too, for any 5xx whose detail is a plain string, so
    # a user hitting a generic infra failure has something to quote back to
    # AF support instead of nothing. Scoped to 5xx only: 4xx details are
    # already meant to be user-actionable on their own (a correlation ID
    # doesn't help "wrong password"), and a dict-shaped detail (identity.py's
    # TokenAudienceError, this route's own NeedsUnlockError-derived 409s) is
    # already structured/already carries its own correlation_id where one
    # makes sense -- overwriting it here would be a regression, not a fix.
    # A 4xx opts in by raising CorrelatedHTTPException (issue #342).
    if (
        exc.status_code >= 500 or isinstance(exc, CorrelatedHTTPException)
    ) and isinstance(exc.detail, str):
        correlation_id = structlog.contextvars.get_contextvars().get("correlation_id")
        if correlation_id:
            return JSONResponse(
                status_code=exc.status_code,
                content={"detail": exc.detail, "correlation_id": correlation_id},
                headers=exc.headers,
            )
    return await http_exception_handler(request, exc)


# Everything below the edge raises domain exceptions rather than
# HTTPException. identity.py's are also reached from /mcp, which translates
# them itself in mcp/middleware/identity_mw.py; /v1 maps each onto an
# HTTPException, routed through _http_exception_handler so logging and 5xx
# correlation_id folding apply to it like to any other. The status code and
# headers live here, not on the domain classes.
_IDENTITY_ERROR_RESPONSES: dict[
    type[IdentityError], tuple[int, dict[str, str] | None]
] = {
    TokenExpiredError: (status.HTTP_401_UNAUTHORIZED, {"WWW-Authenticate": "Bearer"}),
    TokenAudienceError: (status.HTTP_401_UNAUTHORIZED, {"WWW-Authenticate": "Bearer"}),
    PrincipalDirectoryUnavailableError: (status.HTTP_503_SERVICE_UNAVAILABLE, None),
    InvalidTokenError: (status.HTTP_401_UNAUTHORIZED, {"WWW-Authenticate": "Bearer"}),
    NotAuthenticatedError: (
        status.HTTP_401_UNAUTHORIZED,
        {"WWW-Authenticate": "Bearer"},
    ),
    JwksUnavailableError: (status.HTTP_502_BAD_GATEWAY, None),
    AdminRequiredError: (status.HTTP_403_FORBIDDEN, None),
}

_CREDENTIAL_ERROR_STATUS: dict[type[CredentialError], int] = {
    CredentialNotFoundError: status.HTTP_404_NOT_FOUND,
    CredentialReauthRequiredError: status.HTTP_401_UNAUTHORIZED,
    CredentialForbiddenError: status.HTTP_403_FORBIDDEN,
    CredentialServiceError: status.HTTP_502_BAD_GATEWAY,
    CredentialRateLimitedError: status.HTTP_429_TOO_MANY_REQUESTS,
}


@app.exception_handler(IdentityError)
async def _identity_error_handler(request: Request, exc: IdentityError) -> Response:
    status_code, headers = _IDENTITY_ERROR_RESPONSES[type(exc)]
    return await _http_exception_handler(
        request,
        HTTPException(status_code=status_code, detail=exc.detail, headers=headers),
    )


@app.exception_handler(CredentialError)
async def _credential_error_handler(request: Request, exc: CredentialError) -> Response:
    headers = (
        {"Retry-After": exc.retry_after}
        if isinstance(exc, CredentialRateLimitedError) and exc.retry_after is not None
        else None
    )
    return await _http_exception_handler(
        request,
        HTTPException(
            status_code=_CREDENTIAL_ERROR_STATUS[type(exc)],
            detail=exc.detail,
            headers=headers,
        ),
    )


@app.exception_handler(MaintenanceModeError)
async def _maintenance_mode_error_handler(
    request: Request, exc: MaintenanceModeError
) -> Response:
    return await _http_exception_handler(
        request,
        HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=exc.detail
        ),
    )


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


@app.exception_handler(UnlockRateLimitError)
async def _rate_limit_error_handler(
    request: Request, exc: UnlockRateLimitError
) -> JSONResponse:
    # UnlockRateLimitError is raised by CredentialCache.record_failed_unlock()/
    # check_unlock_rate_limit() on the x509 credential-issuance path (bad
    # passphrase / minting-backend failures against a colocated user's
    # ~/.globus) -- plain cache misses never raise it (see cache.py's get()).
    # Map it to 429 with Retry-After so well-behaved clients — and the portal
    # — back off instead of hammering the endpoint.
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
