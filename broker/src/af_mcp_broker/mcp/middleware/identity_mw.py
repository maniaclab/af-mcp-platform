from __future__ import annotations

from typing import Any

import structlog

logger = structlog.get_logger(__name__)

# FastMCP 2.x middleware API: middleware functions receive (request, call_next).
# The identity is extracted from the Bearer token in the Authorization header
# and stored in request.context for downstream middleware.
#
# Exact FastMCP middleware registration API needs verification against the
# installed fastmcp version. The pattern below is correct for fastmcp >= 2.0.


async def identity_middleware(request: Any, call_next: Any) -> Any:
    """Extract and validate the AF Keycloak Bearer token, build a Principal.

    Stores the Principal in request.context["principal"] for downstream middleware.
    Raises an MCP error if the token is missing or invalid.
    """
    from af_mcp_broker.identity import get_principal
    from af_mcp_broker.config import get_settings

    settings = get_settings()

    auth_header: str | None = None
    if hasattr(request, "headers"):
        auth_header = request.headers.get("Authorization") or request.headers.get("authorization")

    if not auth_header or not auth_header.lower().startswith("bearer "):
        raise ValueError("Missing Authorization: Bearer <token> header")

    token = auth_header[7:]
    try:
        principal = await get_principal(token, settings)
    except Exception as exc:
        logger.warning("mcp_identity_validation_failed", error=str(exc))
        raise ValueError(f"Invalid or expired token: {exc}") from exc

    if not hasattr(request, "context"):
        request.context = {}
    request.context["principal"] = principal

    return await call_next(request)
