from __future__ import annotations

from typing import Annotated

from fastapi import Depends, Request

from af_mcp_broker.config import Settings, get_settings
from af_mcp_broker.identity import keycloak_dependency
from af_mcp_broker.maintenance import check_not_maintenance_or_fail_open
from af_mcp_broker.principal import Principal


async def require_not_in_maintenance(
    request: Request,
    principal: Annotated[Principal, Depends(keycloak_dependency)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> Principal:
    """FastAPI dependency: 503s when maintenance mode is on and the caller isn't an admin.

    A separate dependency from keycloak_dependency (not folded into it)
    because GET /v1/admin/maintenance (api/admin.py) must stay reachable by
    every caller (so the portal can show a maintenance banner to non-admins
    too) and /v1's health probes must never be gated (Kubernetes would
    otherwise restart pods during a deliberate maintenance window) -- see
    api/router.py for exactly which routers this is applied to.

    Store-unavailability decision: fail OPEN. If the maintenance store
    backend itself is unreachable (a Vault or Postgres outage),
    ``check_not_maintenance``'s ``store.get()`` call raises an unclassified
    exception (its docstring notes this explicitly is not handled there).
    Unlike ``PrincipalDirectoryUnavailableError`` -- which fails CLOSED
    because it answers a security-relevant question ("what groups/POSIX
    identity does this principal currently have") that every authorization
    decision on /v1 depends on -- maintenance mode is an operational
    convenience toggle, not a security boundary: it is normally disabled,
    and an admin used it to voluntarily take the platform offline. Failing
    closed here would mean a transient outage of an auxiliary store turns
    into a broker-wide 503 for every non-admin caller on /v1, which is a
    strictly worse outcome than momentarily not knowing whether a
    maintenance window is active. So a store failure is treated the same as
    a disabled store: the request proceeds, and the failure is logged (and
    counted -- ``metrics.maintenance_store_unavailable_total``) so it's
    visible to operators. That logging/counting -- shared with /mcp's
    identical fail-open behavior -- lives in
    ``maintenance.check_not_maintenance_or_fail_open``, which this dependency
    calls rather than ``check_not_maintenance`` directly.

    IMPORTANT LIMITATION this implies: non-admins keep their pre-incident
    access whenever the maintenance store can't be reached, rather than
    being blocked. ``is_admin`` is checked before ``store.get()`` (see
    ``check_not_maintenance``), so fail-open only ever changes the outcome
    for non-admins -- an admin's own access is never affected by the
    store's health either way. But it does mean maintenance mode must NOT
    be relied on as an incident-containment control (e.g. "lock everyone
    out right now because something is actively wrong") if the maintenance
    store could plausibly be within that incident's blast radius -- the
    same outage or attack that motivated the lockdown could also be what
    takes out Vault/Postgres, silently defeating the lockdown for exactly
    the population it was meant to stop. Maintenance mode is a planned-
    maintenance convenience feature; it is not, and should not be treated
    as, an incident-response kill switch.
    """
    store = getattr(request.app.state, "maintenance_mode_store", None)
    exc = await check_not_maintenance_or_fail_open(principal, settings, store)
    if exc is not None:
        raise exc
    return principal
