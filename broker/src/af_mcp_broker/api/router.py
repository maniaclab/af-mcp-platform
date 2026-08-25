from __future__ import annotations

from fastapi import APIRouter

from af_mcp_broker.api import (
    catalog_tools,
    credentials,
    health,
    identities,
    mcp_oauth,
    oauth21,
    permissions,
    tokens,
)

# All routes are grouped under /v1 at the application level. Sub-routers
# carry their own path prefixes relative to this root.
router = APIRouter(prefix="/v1")

router.include_router(health.router)
router.include_router(identities.router)
router.include_router(permissions.router)
router.include_router(catalog_tools.router)
router.include_router(credentials.router)
router.include_router(oauth21.router)
router.include_router(tokens.router)
router.include_router(mcp_oauth.router)
