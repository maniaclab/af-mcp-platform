from __future__ import annotations

from fastapi import APIRouter, Depends

from af_mcp_broker.api import (
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
router.include_router(oauth21.router, dependencies=_maintenance_gated)
router.include_router(tokens.router, dependencies=_maintenance_gated)
router.include_router(mcp_oauth.router, dependencies=_maintenance_gated)
router.include_router(usage.router, dependencies=_maintenance_gated)
