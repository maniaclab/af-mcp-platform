from __future__ import annotations

from typing import TYPE_CHECKING, Any

import structlog
from fastapi import HTTPException
from fastmcp.exceptions import AuthorizationError
from fastmcp.server.dependencies import get_http_request
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext
from starlette.responses import JSONResponse

from af_mcp_broker.identity import (
    PrincipalDirectoryUnavailableError,
    TokenExpiredError,
    build_dev_principal,
    get_principal,
    issuer_is_local,
)
from af_mcp_broker.pat import PAT_PREFIX
from af_mcp_broker.pat_auth import LastUsedTracker, resolve_pat_principal

if TYPE_CHECKING:
    from starlette.types import Receive, Scope, Send

    from af_mcp_broker.config import Settings
    from af_mcp_broker.principal_cache import PrincipalCache
    from af_mcp_broker.token_registry import RevokedJtiCache, TokenRegistryBackend

logger = structlog.get_logger(__name__)

# Identity enforcement for every /mcp request (initialize, tools/list,
# tools/call, ...) is split across two cooperating layers:
#
# 1. AsgiAuthMiddleware -- a plain ASGI middleware wrapping the aggregator's
#    whole http_app (installed via FastMCP.http_app's ``middleware=``
#    argument in app.py), running *before* a request is accepted into
#    FastMCP's streamable-HTTP session/message-processing pipeline. This is
#    the only layer that can still choose the HTTP status code: anything
#    raised once a request has entered FastMCP's own message dispatch is
#    caught by the mcp SDK's catch-all (mcp/shared/session.py) and reported
#    as a JSONRPCError over HTTP 200 -- meaningless to the caller and unable
#    to trigger MCP client OAuth discovery, which is gated on
#    ``response.status_code == 401`` (issues #138, #140, #144 step 1). On
#    success it stashes the resolved Principal onto the ASGI scope's
#    ``state`` dict, which the mcp SDK's own Request wrapper (reachable via
#    fastmcp's ``get_http_request()``) exposes as ``request.state`` for the
#    rest of the pipeline to read.
#
# 2. IdentityMiddleware -- one of FastMCP's own Middleware subclasses,
#    registered in the aggregator's middleware chain (aggregator.py) exactly
#    as before this fix. It performs no JWT validation of its own; it is a
#    thin hand-off that reads the Principal AsgiAuthMiddleware already
#    stashed and republishes it as FastMCP Context state ("principal") the
#    way EntitlementMiddleware/AuthorizationMiddleware/the aggregator's
#    client factories already expect. Kept rather than removed because that
#    hand-off -- a plain ASGI scope dict becoming FastMCP's own
#    request-scoped Context state -- has no other point in the pipeline to
#    happen; downstream code has no other way to reach the Principal. It
#    fails closed (raises AuthorizationError) if no Principal was stashed,
#    which should never happen in the real app (AsgiAuthMiddleware always
#    runs first and never calls into this pipeline without one) but guards
#    against a future embedding that forgets to install AsgiAuthMiddleware.
#
# Bearer recognition (issue #144 step 2a): AsgiAuthMiddleware dispatches on
# the bearer's prefix alone. A ``mcp_pat_...`` bearer goes to
# ``pat_auth.resolve_pat_principal`` (broker-issued identity PAT); anything
# else falls through to ``identity.get_principal`` (Keycloak JWT) EXACTLY as
# before this step -- no behavior change for existing JWT-bearing clients.
# Both paths converge on the same Principal shape and the same stash-onto-
# scope["state"] handoff below; IdentityMiddleware (layer 2 above) republishes
# whichever kind was resolved identically, since it never inspects the token
# itself. This is deliberately a *recognition* dispatch, not a replacement --
# ``/mcp`` accepts both credential types until #144 step 5 flips it to
# PAT-only, once OAuth bootstrap gives every client a way to obtain a PAT.


def _get_authorization_header(scope: Scope) -> str | None:
    """Extract the raw Authorization header value from an ASGI scope.

    Read directly off ``scope["headers"]`` rather than via fastmcp's
    ``get_http_headers()`` -- that helper depends on FastMCP's own request
    context, which is not established yet at this point in the pipeline
    (this middleware runs before the request is accepted into FastMCP's
    message dispatch at all).
    """
    headers = dict(scope.get("headers") or [])
    value = headers.get(b"authorization")
    return value.decode("latin-1") if value is not None else None


async def _send_error(
    scope: Scope,
    receive: Receive,
    send: Send,
    status_code: int,
    detail: str,
    *,
    headers: dict[str, str] | None = None,
) -> None:
    response = JSONResponse(
        {"detail": detail}, status_code=status_code, headers=headers
    )
    await response(scope, receive, send)


def _www_authenticate_header(settings: Settings) -> str:
    """Build the ``WWW-Authenticate`` header value for /mcp's 401 responses.

    Carries a ``resource_metadata`` pointer (RFC 9728, MCP spec's 2025-11-25
    revision) at the ``/mcp``-suffixed protected-resource metadata path
    (api/wellknown.py) whenever ``broker_public_origin`` is configured -- PR
    #145 deliberately omitted this parameter because the metadata endpoint
    did not exist yet (issue #140); it does now. Omitted (bare ``Bearer``,
    the pre-#140 behavior) when ``broker_public_origin`` is unset, since no
    resolvable metadata URL exists to point at -- a client without the
    header still falls back to the well-known root path per spec.
    """
    if not settings.broker_public_origin:
        return "Bearer"
    origin = settings.broker_public_origin.rstrip("/")
    return (
        f'Bearer resource_metadata="{origin}/.well-known/oauth-protected-resource/mcp"'
    )


async def _send_401(
    scope: Scope, receive: Receive, send: Send, detail: str, settings: Settings
) -> None:
    await _send_error(
        scope,
        receive,
        send,
        401,
        detail,
        headers={"WWW-Authenticate": _www_authenticate_header(settings)},
    )


class AsgiAuthMiddleware:
    """Enforces identity at the ASGI layer, in front of the /mcp aggregator's whole http_app.

    See the module docstring above for why this has to live here rather
    than as a FastMCP Middleware.

    Reads settings/revoked_jti_cache off *identity_mw* rather than holding
    its own copy: identity_mw's attributes are already the single mutable
    config handle ``aggregator.populate_aggregator()`` updates once app.py's
    lifespan has the real Settings/RevokedJtiCache. This middleware is
    constructed once, from a placeholder Settings(), at app.py
    module-import time (see its comment on why ``_mcp_aggregator_app`` must
    exist before Settings() is loaded) -- reusing identity_mw's handle
    avoids a second, separately-updated copy of the same mutable state that
    could drift out of sync.
    """

    def __init__(self, app: Any, identity_mw: IdentityMiddleware) -> None:
        self.app = app
        self._identity_mw = identity_mw

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        settings = self._identity_mw.settings
        revoked_jti_cache = self._identity_mw.revoked_jti_cache
        pat_backend = self._identity_mw.pat_backend
        principal_cache = self._identity_mw.principal_cache

        if settings.dev_insecure_principal is not None:
            # Local-dev auth bypass, mirroring app.py's lifespan check
            # (settings-driven, same build_dev_principal helper). This
            # middleware wraps a mounted sub-app, not the parent FastAPI
            # app, so app.state.dev_bypass_active/dev_bypass_principal are
            # unreachable here -- re-derive the bypass from settings
            # directly, exactly like the lifespan does.
            if not issuer_is_local(settings.oidc_issuer):
                # app.py's own lifespan already refuses to start in this
                # configuration; reaching here means this invariant is being
                # violated some other way (e.g. exercised directly in a
                # test). This is a server misconfiguration, not something
                # the caller's credentials could ever fix -- fail closed
                # with an uncaught error (Starlette's ServerErrorMiddleware
                # turns it into a 500) rather than a misleading 401.
                raise RuntimeError(
                    "BROKER_DEV_INSECURE_PRINCIPAL is set but OIDC_ISSUER "
                    "does not look like a local development host"
                )
            principal = build_dev_principal(settings.dev_insecure_principal)
        else:
            auth_header = _get_authorization_header(scope)
            if not auth_header or not auth_header.lower().startswith("bearer "):
                await _send_401(
                    scope,
                    receive,
                    send,
                    "Missing Authorization: Bearer <token> header",
                    settings,
                )
                return
            token = auth_header[len("Bearer ") :]
            is_pat = token.startswith(PAT_PREFIX)
            if is_pat and (pat_backend is None or principal_cache is None):
                # PAT support isn't configured (no Keycloak admin service
                # account -- see Settings.keycloak_admin_client_id/_secret)
                # -- reject the same vague way as any other invalid PAT
                # rather than crash or leak config state.
                await _send_401(scope, receive, send, "Invalid bearer token", settings)
                return
            try:
                if is_pat:
                    # Identity PAT (issue #144 step 2a) -- recognized purely
                    # by prefix, so a non-mcp_pat_ bearer always falls
                    # through to the existing JWT path below unchanged.
                    # Both are guaranteed non-None here by the guard above;
                    # asserted rather than re-checked so mypy can narrow them.
                    assert pat_backend is not None
                    assert principal_cache is not None
                    principal = await resolve_pat_principal(
                        token,
                        settings,
                        pat_backend,
                        principal_cache,
                        self._identity_mw.pat_last_used_tracker,
                    )
                else:
                    principal = await get_principal(
                        token, settings, principal_cache, revoked_jti_cache
                    )
            except TokenExpiredError:
                # Safe to state explicitly -- expiry alone reveals nothing
                # about why any *other* token would be rejected.
                portal = settings.portal_url.rstrip("/")
                await _send_401(
                    scope,
                    receive,
                    send,
                    "Your access token has expired — mint a new one at "
                    f"{portal}/tokens",
                    settings,
                )
                return
            except PrincipalDirectoryUnavailableError as exc:
                # Distinct from the vague-401 catch-all below (issue #144
                # step 3): this JWT's signature/issuer/audience/expiry all
                # verified -- the caller proved who they are. What failed is
                # the platform's ability to resolve their current groups, a
                # platform outage, not a bad credential -- see that
                # exception's docstring. 503 with the actionable detail,
                # not a vague 401, so a caller can tell the difference.
                logger.exception(
                    "mcp_principal_directory_unavailable", error=str(exc.detail)
                )
                await _send_error(scope, receive, send, exc.status_code, exc.detail)
                return
            except HTTPException as exc:
                logger.warning("mcp_identity_validation_failed", error=str(exc.detail))
                # Deliberately vague -- see the module docstring: never
                # repeat which claim, issuer/audience, or JWKS detail failed
                # to a client.
                await _send_401(scope, receive, send, "Invalid bearer token", settings)
                return

        scope.setdefault("state", {})
        scope["state"]["principal"] = principal
        await self.app(scope, receive, send)


class IdentityMiddleware(Middleware):
    def __init__(
        self,
        settings: Settings,
        revoked_jti_cache: RevokedJtiCache | None = None,
        pat_backend: TokenRegistryBackend | None = None,
        principal_cache: PrincipalCache | None = None,
    ) -> None:
        # on_request below reads none of these directly -- it is a thin
        # hand-off (see the module docstring). They're kept here anyway
        # because this instance is the single mutable config handle
        # aggregator.populate_aggregator() already updates once app.py's
        # lifespan has the real Settings/RevokedJtiCache/PAT store/principal
        # cache; AsgiAuthMiddleware reads all of them off *this* instance
        # rather than holding a second, separately-updated copy.
        self.settings = settings
        self.revoked_jti_cache = revoked_jti_cache
        self.pat_backend = pat_backend
        self.principal_cache = principal_cache
        # Purely in-process, ephemeral throttle state for PAT last_used_at
        # writes (see pat_auth.LastUsedTracker) -- constructed unconditionally
        # (not a constructor param) since it has no external dependency and
        # is harmless to build even when PAT support itself isn't configured.
        self.pat_last_used_tracker = LastUsedTracker()

    async def on_request(
        self,
        context: MiddlewareContext[Any],
        call_next: CallNext[Any, Any],
    ) -> Any:
        if context.fastmcp_context is None:
            # Should not happen for a real request; fail closed rather than
            # silently skip identity for anything that reaches here.
            raise AuthorizationError("No FastMCP context available for this request")

        principal = getattr(get_http_request().state, "principal", None)
        if principal is None:
            # Should not happen in the real app -- AsgiAuthMiddleware always
            # runs first and never calls into this pipeline without stashing
            # a validated Principal (see the module docstring). Guards
            # against a future embedding that forgets to install it.
            raise AuthorizationError(
                "No authenticated principal available for this request"
            )

        # serializable=False: Principal carries a SecretStr (not JSON
        # serializable) and is deliberately request-scoped rather than
        # session-scoped -- a long-lived MCP session must re-validate the
        # caller's bearer token on every request, not cache the first one.
        await context.fastmcp_context.set_state(
            "principal", principal, serializable=False
        )

        return await call_next(context)
