"""Integration tests pinning where the maintenance gate sits relative to authentication, on both /v1 and /mcp.

The gate answers "is the platform in maintenance, and is this caller an
admin?", which needs a resolved principal. So authentication always runs
first: a caller who cannot be authenticated gets a 401 (never a 503) even
while maintenance mode is on, and only an authenticated non-admin is turned
away with a 503. These tests drive the same compositions production uses
(the real FastAPI app for /v1, ``build_aggregator`` behind its ASGI
middleware for /mcp) so they hold wherever the gate is implemented.
"""

from __future__ import annotations

import asyncio
import time
from typing import TYPE_CHECKING, Any

import pytest
from broker_state_helpers import aggregator_stores, set_broker_state
from conftest import make_claims, run_aggregator_async, run_inprocess_server
from fastmcp import FastMCP

from af_mcp_broker import identity
from af_mcp_broker.authorization import EntitlementPolicy
from af_mcp_broker.config import get_settings
from af_mcp_broker.credentials import CredentialRegistry
from af_mcp_broker.maintenance import (
    InMemoryMaintenanceModeStore,
    MaintenanceModeStore,
    MaintenanceState,
)
from af_mcp_broker.mcp.aggregator import build_aggregator
from af_mcp_broker.service_registry import ServiceRegistry, ServiceSpec

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    import httpx2
    from fastmcp.utilities.tests import ASGIServer

_MAINTENANCE_ON = MaintenanceState(
    enabled=True, reason="down for updates", enabled_by="a", enabled_at=1.0
)

_INIT_BODY = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "test", "version": "0"},
    },
}


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


# ---------------------------------------------------------------------------
# /v1
# ---------------------------------------------------------------------------


class TestV1GateOrdering:
    def test_unauthenticated_request_gets_401_not_503(self, app_client_factory):
        with app_client_factory() as (client, _state):
            client.app.dependency_overrides.clear()
            store = InMemoryMaintenanceModeStore()
            asyncio.run(store.set(_MAINTENANCE_ON))
            set_broker_state(client.app, maintenance_mode_store=store)

            resp = client.get("/v1/identities")

        assert resp.status_code == 401

    def test_invalid_bearer_gets_401_not_503(
        self, app_client_factory, sig_key, monkeypatch
    ):
        with app_client_factory() as (client, _state):
            client.app.dependency_overrides.clear()
            # Seed the JWKS cache for the app's own issuer so the bearer is
            # judged invalid rather than the JWKS fetch failing (502).
            monkeypatch.setitem(
                identity._jwks_cache,
                get_settings().oidc_jwks_uri,
                identity._JwksEntry(keys=[sig_key.jwk], fetched_at=time.monotonic()),
            )
            store = InMemoryMaintenanceModeStore()
            asyncio.run(store.set(_MAINTENANCE_ON))
            set_broker_state(client.app, maintenance_mode_store=store)

            resp = client.get(
                "/v1/identities", headers={"Authorization": "Bearer not-a-jwt"}
            )

        assert resp.status_code == 401

    def test_authenticated_non_admin_gets_503_naming_the_reason(
        self, app_client_factory, monkeypatch
    ):
        monkeypatch.setenv("ADMIN_GROUP", "af-admins")
        with app_client_factory() as (client, _state):
            store = InMemoryMaintenanceModeStore()
            asyncio.run(store.set(_MAINTENANCE_ON))
            set_broker_state(client.app, maintenance_mode_store=store)

            resp = client.get("/v1/identities")

        assert resp.status_code == 503
        assert "down for updates" in resp.json()["detail"]

    def test_maintenance_status_endpoint_stays_reachable(self, app_client_factory):
        with app_client_factory() as (client, _state):
            store = InMemoryMaintenanceModeStore()
            asyncio.run(store.set(_MAINTENANCE_ON))
            set_broker_state(client.app, maintenance_mode_store=store)

            resp = client.get("/v1/admin/maintenance")

        assert resp.status_code == 200
        assert resp.json()["enabled"] is True


# ---------------------------------------------------------------------------
# /mcp
# ---------------------------------------------------------------------------


def _open_backend() -> FastMCP:
    mcp = FastMCP(name="open-backend")

    @mcp.tool
    def ping() -> str:
        return "pong"

    return mcp


@pytest.fixture
async def open_backend_url() -> AsyncIterator[str]:
    async with run_inprocess_server(_open_backend(), path="/mcp") as url:
        yield url


@pytest.fixture
def registry(open_backend_url: str) -> ServiceRegistry:
    registry = ServiceRegistry()
    registry.register(
        ServiceSpec(
            name="open",
            prefix="open",
            url=open_backend_url,
            transport="http",
            required_permission="__none__",
            auth_type="none",
        )
    )
    return registry


async def _post_initialize(
    server: ASGIServer, headers: dict[str, str]
) -> httpx2.Response:
    full_headers = {
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
        **headers,
    }
    async with server.http_client() as client:
        return await client.post(server.url, json=_INIT_BODY, headers=full_headers)


async def _serve_mcp(
    settings: Any,
    registry: ServiceRegistry,
    principal_cache: Any,
    store: MaintenanceModeStore,
) -> Any:
    mcp = build_aggregator(
        registry,
        settings,
        EntitlementPolicy(group_permissions={"__authenticated__": []}),
        CredentialRegistry(),
        **aggregator_stores(),
    )
    return run_aggregator_async(
        mcp,
        path="/mcp",
        maintenance_mode_store=store,
        settings=settings,
        principal_cache=principal_cache,
    )


@pytest.fixture
async def maintenance_store() -> InMemoryMaintenanceModeStore:
    store = InMemoryMaintenanceModeStore()
    await store.set(_MAINTENANCE_ON)
    return store


@pytest.fixture
async def mcp_server(
    settings: Any,
    registry: ServiceRegistry,
    static_principal_cache: Any,
    maintenance_store: InMemoryMaintenanceModeStore,
) -> AsyncIterator[ASGIServer]:
    principal_cache, _directory = static_principal_cache
    async with await _serve_mcp(
        settings, registry, principal_cache, maintenance_store
    ) as server:
        yield server


class TestMcpGateOrdering:
    async def test_missing_bearer_gets_401_not_503(self, mcp_server):
        resp = await _post_initialize(mcp_server, {})

        assert resp.status_code == 401
        assert resp.json()["detail"] == "Missing Authorization: Bearer <token> header"

    async def test_invalid_bearer_gets_401_not_503(self, mcp_server):
        resp = await _post_initialize(
            mcp_server, {"Authorization": "Bearer not-a-real-jwt"}
        )

        assert resp.status_code == 401
        assert resp.json()["detail"] == "Invalid bearer token"

    async def test_authenticated_non_admin_gets_503_naming_the_reason(
        self, mcp_server, sig_key, prime_jwks
    ):
        prime_jwks([sig_key.jwk])
        token = sig_key.sign(make_claims())

        resp = await _post_initialize(mcp_server, {"Authorization": f"Bearer {token}"})

        assert resp.status_code == 503
        assert "down for updates" in resp.json()["detail"]


async def test_mcp_admin_is_not_blocked_during_maintenance(
    settings, registry, static_principal_cache, maintenance_store, sig_key, prime_jwks
):
    principal_cache, directory = static_principal_cache
    directory.groups_by_subject["user-123"] = ["af-admins"]
    admin_settings = settings.model_copy(update={"admin_group": "af-admins"})
    prime_jwks([sig_key.jwk])
    token = sig_key.sign(make_claims())

    async with await _serve_mcp(
        admin_settings, registry, principal_cache, maintenance_store
    ) as server:
        resp = await _post_initialize(server, {"Authorization": f"Bearer {token}"})

    assert resp.status_code == 200


async def test_mcp_non_admin_not_blocked_when_store_unavailable(
    settings, registry, static_principal_cache, sig_key, prime_jwks
):
    principal_cache, _directory = static_principal_cache
    prime_jwks([sig_key.jwk])
    token = sig_key.sign(make_claims())

    async with await _serve_mcp(
        settings, registry, principal_cache, _BrokenMaintenanceModeStore()
    ) as server:
        resp = await _post_initialize(server, {"Authorization": f"Bearer {token}"})

    assert resp.status_code == 200
