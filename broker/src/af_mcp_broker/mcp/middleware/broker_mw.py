from __future__ import annotations

import time
import uuid
from typing import TYPE_CHECKING, Any

import structlog

from af_mcp_broker.audit import AuditRecord, write_audit
from af_mcp_broker.config import get_settings
from af_mcp_broker.http import get_http_client

if TYPE_CHECKING:
    from af_mcp_broker.mcp.registry import BackendRegistry

logger = structlog.get_logger(__name__)

# on_call_tool middleware: authorizes, acquires a credential, injects it, audits.
#
# The broker contract is HTTP from day one — even when co-located, this
# middleware calls /v1/authorize and /v1/credential over HTTP loopback
# rather than in-process calls. This keeps the aggregation layer swappable.


async def broker_middleware(request: Any, call_next: Any) -> Any:
    """Authorize + credential inject for every MCP tool call."""
    settings = get_settings()
    broker_base_url = settings.broker_internal_url

    principal = getattr(request, "context", {}).get("principal")
    if principal is None:
        raise ValueError("No authenticated principal in request context")

    tool_name: str = getattr(request, "tool_name", "") or ""
    tool_args: dict = getattr(request, "arguments", {}) or {}

    registry: BackendRegistry | None = getattr(request, "app_registry", None)
    if registry is None:
        raise ValueError("No backend registry available")

    backend = registry.get_by_tool_prefix(tool_name)
    if backend is None:
        raise ValueError(f"No backend registered for tool '{tool_name}'")

    bearer_token = principal.raw_token.get_secret_value()
    request_id = str(uuid.uuid4())

    # 1. Authorize
    auth_resp = await get_http_client().post(
        f"{broker_base_url}/v1/authorize",
        json={
            "capability": backend.required_capability,
            "target": backend.name,
            "action": tool_name,
            "context": {"args_keys": list(tool_args.keys())},
        },
        headers={"Authorization": f"Bearer {bearer_token}"},
        timeout=5.0,
    )

    if auth_resp.status_code != 200:
        raise ValueError(f"Authorization denied for tool '{tool_name}'")

    auth_data = auth_resp.json()
    if not auth_data.get("allow"):
        reason = auth_data.get("reason", "denied")
        raise ValueError(f"Authorization denied: {reason}")

    action_type = auth_data.get("action_type", "read")

    # 2. Acquire credential if the backend needs one
    credential: dict | None = None
    if backend.auth_type != "none":
        cred_resp = await get_http_client().post(
            f"{broker_base_url}/v1/credential",
            json={"target": backend.name},
            headers={"Authorization": f"Bearer {bearer_token}"},
            timeout=5.0,
        )

        if cred_resp.status_code == 409:
            detail = cred_resp.json()
            portal = settings.portal_url.rstrip("/")
            raise ValueError(
                f"Credential unlock required. Visit the portal: "
                f"{portal}{detail.get('unlock_endpoint', '/status')}"
            )
        if cred_resp.status_code != 200:
            raise ValueError(f"Failed to acquire credential for '{backend.name}'")

        credential = cred_resp.json()

    # 3. Inject credential into the request. Only bearer credentials carry a
    # token in the response; x509 proxies are read server-side from a shared
    # path and never transit the response body.
    if credential and credential.get("kind") == "bearer":
        access_token = credential.get("token")
        if access_token and hasattr(request, "headers"):
            request.headers["Authorization"] = f"Bearer {access_token}"

    # 4. Forward to backend
    response = await call_next(request)

    # 5. Audit every tool invocation (docs/architecture.md promises a line per
    # call, not just per state change).
    args_summary = ", ".join(f"{k}=..." for k in list(tool_args.keys())[:10])
    await write_audit(
        AuditRecord(
            principal_sub=principal.subject,
            principal_uid=principal.uid,
            capability=backend.required_capability,
            target=backend.name,
            action=tool_name,
            action_type=action_type,
            args_summary=args_summary,
            timestamp=time.time(),
            request_id=request_id,
            mcp_backend=backend.name,
        )
    )

    return response
