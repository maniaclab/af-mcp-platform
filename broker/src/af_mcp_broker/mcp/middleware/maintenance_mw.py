from __future__ import annotations

from typing import TYPE_CHECKING, Any

from af_mcp_broker.maintenance import check_not_maintenance_or_fail_open
from af_mcp_broker.mcp.middleware.identity_mw import send_error

if TYPE_CHECKING:
    from collections.abc import Callable

    from starlette.types import Receive, Scope, Send

    from af_mcp_broker.broker_state import BrokerState


class AsgiMaintenanceMiddleware:
    """Turns non-admin callers away with a 503 while maintenance mode is on, at the ASGI layer, in front of the /mcp aggregator's whole http_app.

    Must sit *inside* ``identity_mw.AsgiAuthMiddleware``: the gate needs the
    resolved Principal (is the caller an admin?), which AsgiAuthMiddleware
    stashes on ``scope["state"]["principal"]`` once it has authenticated the
    request. A caller who cannot be authenticated therefore gets that
    middleware's 401, never this one's 503. Mirrors /v1's
    ``api.maintenance_gate.require_not_in_maintenance``, including its
    fail-open behavior when the maintenance store is unreachable (see
    ``maintenance.check_not_maintenance_or_fail_open``'s docstring for the
    full reasoning and the resulting limitation -- that function is also
    where the fail-open logging/counting shared with /v1 lives).

    Reads settings and the maintenance store from the broker state at request
    time, through *get_state*: this middleware is constructed at import time,
    before the lifespan has built either.
    """

    def __init__(self, app: Any, get_state: Callable[[], BrokerState]) -> None:
        self.app = app
        self._get_state = get_state

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        principal = scope.get("state", {}).get("principal")
        if principal is None:
            # AsgiAuthMiddleware always runs first and never calls inward
            # without stashing a validated Principal; reaching here means
            # this middleware was installed outside it. Fail closed with an
            # uncaught error (a 500) rather than waving the request through.
            raise RuntimeError(
                "AsgiMaintenanceMiddleware requires AsgiAuthMiddleware to run first"
            )

        state = self._get_state()
        maintenance_exc = await check_not_maintenance_or_fail_open(
            principal, state.settings, state.maintenance_mode_store
        )
        if maintenance_exc is not None:
            await send_error(
                scope,
                receive,
                send,
                maintenance_exc.status_code,
                str(maintenance_exc.detail),
            )
            return

        await self.app(scope, receive, send)
