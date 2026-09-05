from __future__ import annotations

from fastapi import APIRouter, Depends

from af_mcp_broker.api import (
    admin,
    catalog_tools,
    credentials,
    health,
    identities,
    mcp_oauth,
    oauth21,
    permissions,
    tokens,
    usage,
)
from af_mcp_broker.identity import require_not_in_maintenance

# All routes are grouped under /v1 at the application level. Sub-routers
# carry their own path prefixes relative to this root.
router = APIRouter(prefix="/v1")

# Health probes must never be gated by maintenance mode -- Kubernetes
# liveness/readiness checks have to keep passing during a deliberate
# maintenance window, or the platform restarts pods exactly when it
# shouldn't.
router.include_router(health.router)

_maintenance_gated = [Depends(require_not_in_maintenance)]
router.include_router(identities.router, dependencies=_maintenance_gated)
router.include_router(permissions.router, dependencies=_maintenance_gated)
router.include_router(catalog_tools.router, dependencies=_maintenance_gated)
router.include_router(credentials.router, dependencies=_maintenance_gated)
# credentials.backend_router carries only /credentials/x509/redeem, which
# authenticates callers with an AF Broker Identity Token, never a Keycloak
# one -- require_not_in_maintenance's admin-bypass check resolves the
# caller via keycloak_dependency, which a broker identity token can never
# satisfy, so gating this route the same way as the rest of
# credentials.router 401'd every backend redeem call regardless of
# maintenance state. Left ungated for the same reason as admin.router
# below: not consulting maintenance state at all, rather than being
# unconditionally exempt from it.
router.include_router(credentials.backend_router)
router.include_router(oauth21.router, dependencies=_maintenance_gated)
router.include_router(tokens.router, dependencies=_maintenance_gated)
# mcp_oauth.router carries the credential-less MCP OAuth bootstrap flow
# (issue #140): /oauth/authorize, /oauth/keycloak-login/callback, and
# /oauth/token authenticate via CIMD client-id validation, a state-token/
# nonce-cookie pair, and PKCE/auth-code redemption respectively -- never a
# Keycloak bearer token. require_not_in_maintenance's admin-bypass check
# resolves the caller via keycloak_dependency, which a credential-less
# request can never satisfy, so gating this router the same way as
# oauth21.router/tokens.router 401'd every /oauth/authorize hit regardless
# of maintenance state (the same class of bug as credentials.backend_router
# above). Left ungated for the same reason.
router.include_router(mcp_oauth.router)
router.include_router(usage.router, dependencies=_maintenance_gated)

# No maintenance-mode dependency here -- GET must stay reachable during
# maintenance (see api/admin.py's GET route docstring), and POST is gated by
# require_admin instead, which doesn't consult maintenance state at all (an
# admin is never blocked by require_not_in_maintenance either, but this
# router simply isn't wired with that dependency in the first place).
router.include_router(admin.router)
