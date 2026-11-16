"""FastAPI authentication dependencies for the ``/v1`` edge."""

from __future__ import annotations

from typing import Annotated

import structlog
from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from af_mcp_broker.authorization import is_admin
from af_mcp_broker.broker_state import get_broker_state, get_state_settings
from af_mcp_broker.config import (
    Settings,  # noqa: TC001 -- FastAPI resolves the dependency annotations at runtime
)
from af_mcp_broker.identity import (
    AdminRequiredError,
    NotAuthenticatedError,
    get_principal,
)
from af_mcp_broker.logging import bind_subject
from af_mcp_broker.principal import Principal

logger = structlog.get_logger(__name__)

# ``auto_error=False`` so we can decide the auth outcome ourselves — HTTPBearer
# would otherwise raise before the dev-bypass short-circuit gets a chance.
_bearer_scheme = HTTPBearer(auto_error=False)


async def keycloak_dependency(
    request: Request,
    credentials: Annotated[
        HTTPAuthorizationCredentials | None, Depends(_bearer_scheme)
    ],
    settings: Annotated[Settings, Depends(get_state_settings)],
) -> Principal:
    """FastAPI dependency that resolves to the authenticated Principal.

    Inject this into route handlers that require authentication:

        @router.get("/example")
        async def example(
            principal: Annotated[Principal, Depends(keycloak_dependency)],
        ):
            ...

    When the local-dev auth bypass is active (see ``BROKER_DEV_INSECURE_PRINCIPAL``
    and the lifespan startup check), this returns the pre-parsed dev principal
    without inspecting the request. That path is unconditional: a real bearer
    token, if present, is ignored.
    """
    state = get_broker_state(request)
    dev_principal = state.dev_bypass_principal
    if dev_principal is not None:
        bind_subject(dev_principal.subject)
        # Emit an audit-visible line on every bypassed request so the trail
        # captures every call that skipped real authentication.
        logger.info(
            "dev_bypass.used",
            path=request.url.path,
            unixname=dev_principal.unixname,
            uid=dev_principal.uid,
        )
        return dev_principal

    if credentials is None:
        raise NotAuthenticatedError("Not authenticated")
    # None only when the deployment has no PrincipalDirectory: app.py's
    # lifespan refuses to start without either one or the dev bypass (issue
    # #144 step 3), and the bypass check above already returned.
    # get_principal surfaces a None cache as PrincipalDirectoryUnavailableError.
    principal_cache = state.principal_cache
    return await get_principal(
        credentials.credentials,
        settings,
        principal_cache,
        state.http_client,
        caller_path=request.url.path,
    )


async def require_admin(
    principal: Annotated[Principal, Depends(keycloak_dependency)],
    settings: Annotated[Settings, Depends(get_state_settings)],
) -> Principal:
    """FastAPI dependency: 403s unless *principal* is in ``settings.admin_group``.

    Depends on ``keycloak_dependency`` so every admin route gets identity
    resolution AND admin-group enforcement from one dependency -- inject this
    in place of ``keycloak_dependency`` on any admin-only route:

        @router.post("/admin/example")
        async def example(
            principal: Annotated[Principal, Depends(require_admin)],
        ):
            ...
    """
    if not is_admin(principal, settings):
        raise AdminRequiredError("This action requires membership in the admin group.")
    return principal
