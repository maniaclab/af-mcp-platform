"""Integration tests for maintenance-mode enforcement on /v1."""

from __future__ import annotations

import asyncio
from typing import Any

from prometheus_client import REGISTRY

from af_mcp_broker.maintenance import (
    InMemoryMaintenanceModeStore,
    MaintenanceModeStore,
    MaintenanceState,
)

_STORE_UNAVAILABLE_COUNTER = "af_mcp_maintenance_store_unavailable_total"


def _store_unavailable_count() -> float:
    # No labels on this counter -- see metrics.py's maintenance_store_unavailable_total.
    return REGISTRY.get_sample_value(_STORE_UNAVAILABLE_COUNTER) or 0.0


def test_non_admin_blocked_when_maintenance_enabled(app_client_factory, monkeypatch):
    monkeypatch.setenv("ADMIN_GROUP", "af-admins")
    with app_client_factory() as (client, _state):
        client.app.state.maintenance_mode_store = InMemoryMaintenanceModeStore()
        asyncio.run(
            client.app.state.maintenance_mode_store.set(
                MaintenanceState(
                    enabled=True, reason="r", enabled_by="a", enabled_at=1.0
                )
            )
        )
        resp = client.get("/v1/identities")
        assert resp.status_code == 503


def test_admin_not_blocked_when_maintenance_enabled(
    app_client_factory, monkeypatch, make_principal
):
    monkeypatch.setenv("ADMIN_GROUP", "af-admins")
    with app_client_factory() as (client, state):
        state["principal"] = make_principal(groups=["af-admins"])
        client.app.state.maintenance_mode_store = InMemoryMaintenanceModeStore()
        asyncio.run(
            client.app.state.maintenance_mode_store.set(
                MaintenanceState(
                    enabled=True, reason="r", enabled_by="a", enabled_at=1.0
                )
            )
        )
        resp = client.get("/v1/identities")
        assert resp.status_code == 200


def test_health_probe_never_blocked(app_client_factory):
    with app_client_factory() as (client, _state):
        client.app.state.maintenance_mode_store = InMemoryMaintenanceModeStore()
        asyncio.run(
            client.app.state.maintenance_mode_store.set(
                MaintenanceState(
                    enabled=True, reason="r", enabled_by="a", enabled_at=1.0
                )
            )
        )
        resp = client.get("/v1/healthz")
        assert resp.status_code == 200


class _BrokenMaintenanceModeStore(MaintenanceModeStore):
    """Store double whose ``get()`` raises, simulating a Vault/Postgres outage."""

    async def start(self) -> None:
        """Nothing to acquire."""

    async def aclose(self) -> None:
        """Nothing to release."""

    async def get(self) -> MaintenanceState:
        raise RuntimeError("maintenance store unreachable (test)")

    async def set(self, state: MaintenanceState) -> None:
        raise AssertionError("not exercised by this test")


def test_non_admin_not_blocked_when_store_unavailable(app_client_factory):
    """Store-unavailability decision: fail OPEN.

    Maintenance mode is a convenience feature, not a security boundary (see
    require_not_in_maintenance's docstring for the full reasoning) -- a
    Vault/Postgres blip on this auxiliary store must not turn into a
    broker-wide 503 for every /v1 caller. The request goes through as if
    maintenance mode were disabled.
    """
    with app_client_factory() as (client, _state):
        client.app.state.maintenance_mode_store = _BrokenMaintenanceModeStore()
        resp = client.get("/v1/identities")
        assert resp.status_code == 200


def test_store_unavailable_is_logged_at_error_with_traceback_and_counted(
    app_client_factory, monkeypatch
):
    """The fail-open path must stay observable even though it's silent to
    the caller: an ERROR-level structlog line with a full traceback (this is
    more security-significant than principal_cache.py's analogous
    .warning()-level stale-serving cases -- it's silently overriding an
    admin's explicit lockdown, not just serving stale group data), plus a
    Prometheus counter so a rate of these is visible without tailing logs.

    Asserts ``logger.exception(...)`` was used specifically (not
    ``.error(..., exc_info=True)``, which ruff's G201 flags and which this
    module already avoids for the comparable ``_fetch_jwks`` case) --
    structlog's ``BoundLogger.exception`` guarantees ERROR level and
    ``exc_info=True`` by construction, so calling it is sufficient without
    re-deriving that guarantee here.

    configure_logging() rewrites the root logger's handlers during the app
    lifespan, which would otherwise swallow pytest's caplog handler (see
    test_health.py::test_startup_warns_on_no_backends), so this asserts
    directly against the module's logger call instead, the same way.

    The fail-open observability itself (this ``logger.exception`` call and
    the counter increment) lives in
    ``maintenance.check_not_maintenance_or_fail_open`` -- shared verbatim
    with /mcp's identical fail-open path (test_mcp_middleware_identity.py)
    -- so this patches ``maintenance``'s module-level logger, not
    ``identity``'s.
    """
    from af_mcp_broker import maintenance as maintenance_module

    calls: list[dict[str, Any]] = []
    original_exception = maintenance_module.logger.exception

    def _capture(event: str, **kwargs: Any) -> Any:
        calls.append({"event": event, **kwargs})
        return original_exception(event, **kwargs)

    monkeypatch.setattr(maintenance_module.logger, "exception", _capture)

    with app_client_factory() as (client, _state):
        client.app.state.maintenance_mode_store = _BrokenMaintenanceModeStore()
        before = _store_unavailable_count()
        resp = client.get("/v1/identities")
        assert resp.status_code == 200
        assert _store_unavailable_count() == before + 1

    matching = [c for c in calls if c["event"] == "maintenance_store_unavailable"]
    assert len(matching) == 1
    assert "maintenance store unreachable" in matching[0]["error"]
