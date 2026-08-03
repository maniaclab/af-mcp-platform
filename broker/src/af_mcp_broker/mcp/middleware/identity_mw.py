from __future__ import annotations

from typing import TYPE_CHECKING, Any

import structlog
from fastapi import HTTPException
from fastmcp.exceptions import AuthorizationError
from fastmcp.server.dependencies import get_http_headers
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext

from af_mcp_broker.identity import build_dev_principal, get_principal, issuer_is_local

if TYPE_CHECKING:
    from af_mcp_broker.config import Settings
    from af_mcp_broker.token_registry import RevokedJtiCache

logger = structlog.get_logger(__name__)

# Extracts and validates the AF Keycloak Bearer token on every MCP request
# (initialize, tools/list, tools/call, ...) and stores the resulting
# Principal in request-scoped Context state for downstream middleware
# (entitlement_mw) to read. Reuses identity.get_principal() verbatim -- the
# aggregator is not a second JWT validator, just another caller of the same
# one /v1 uses.


class IdentityMiddleware(Middleware):
    def __init__(
        self, settings: Settings, revoked_jti_cache: RevokedJtiCache | None = None
    ) -> None:
        self.settings = settings
        # Populated by aggregator.populate_aggregator() once app.py's
        # lifespan has built the real token registry (issue #115) -- see
        # get_principal's docstring for why enforcing revocation here covers
        # /mcp the same way keycloak_dependency covers /v1.
        self.revoked_jti_cache = revoked_jti_cache

    async def on_request(
        self,
        context: MiddlewareContext[Any],
        call_next: CallNext[Any, Any],
    ) -> Any:
        settings = self.settings

        if settings.dev_insecure_principal is not None:
            # Local-dev auth bypass, mirroring app.py's lifespan check
            # (settings-driven, same build_dev_principal helper).
            #
            # keycloak_dependency cannot be reused here: inside this mounted
            # FastMCP sub-app, request.app is NOT the parent FastAPI app, so
            # app.state.dev_bypass_active/dev_bypass_principal (which that
            # dependency reads) are unreachable. app.py's own lifespan
            # already refuses to start at all when dev_insecure_principal is
            # set against a non-local issuer, so by the time any request
            # reaches this middleware in the real process that invariant
            # already holds; the issuer_is_local check below is
            # defense-in-depth for this middleware used in isolation (e.g.
            # tests that construct it directly, bypassing app.py's lifespan).
            if not issuer_is_local(settings.oidc_issuer):
                raise AuthorizationError(
                    "BROKER_DEV_INSECURE_PRINCIPAL is set but OIDC_ISSUER "
                    "does not look like a local development host"
                )
            principal = build_dev_principal(settings.dev_insecure_principal)
        else:
            # include={"authorization"} is required: get_http_headers strips
            # Authorization by default so it isn't accidentally forwarded by
            # naive proxy code elsewhere.
            headers = get_http_headers(include={"authorization"})
            auth_header = headers.get("authorization")
            if not auth_header or not auth_header.lower().startswith("bearer "):
                raise AuthorizationError("Missing Authorization: Bearer <token> header")
            token = auth_header[len("Bearer ") :]
            try:
                principal = await get_principal(token, settings, self.revoked_jti_cache)
            except HTTPException as exc:
                logger.warning("mcp_identity_validation_failed", error=str(exc.detail))
                raise AuthorizationError(str(exc.detail)) from exc

        if context.fastmcp_context is None:
            # Should not happen for a real request; fail closed rather than
            # silently skip identity for anything that reaches here.
            raise AuthorizationError("No FastMCP context available for this request")

        # serializable=False: Principal carries a SecretStr (not JSON
        # serializable) and is deliberately request-scoped rather than
        # session-scoped -- a long-lived MCP session must re-validate the
        # caller's bearer token on every request, not cache the first one.
        await context.fastmcp_context.set_state(
            "principal", principal, serializable=False
        )

        return await call_next(context)
