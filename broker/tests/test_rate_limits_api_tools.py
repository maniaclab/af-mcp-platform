"""Tests for the per-rule ``tools`` GET /v1/rate-limits returns: the caller's tools each rule covers, computed with the limiter's own matcher.

Real in-process MCP backends and the real catalog listing path; only the route
is driven in-process through httpx2's ASGITransport, as test_catalog_tools.py
does.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, Any

import httpx2
import pytest
from broker_state_helpers import make_broker_state
from conftest import run_inprocess_server
from fastapi import FastAPI
from fastmcp import FastMCP
from fastmcp.utilities.http import find_available_port

from af_mcp_broker.api import rate_limits
from af_mcp_broker.api.auth import keycloak_dependency
from af_mcp_broker.authorization import EntitlementPolicy, RateLimitRule
from af_mcp_broker.service_registry import ServiceRegistry, ServiceSpec

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable

WRITE_RULE = RateLimitRule(60, 300, action_type="state_change")
DATA_RULE = RateLimitRule(5, 300, tool="data_*")
UNMATCHED_RULE = RateLimitRule(1, 300, tool="nothing_*")


def _data_backend() -> FastMCP:
    backend = FastMCP(name="data-backend")

    @backend.tool
    def replica() -> str:
        """Return a replica."""
        return "ok"

    @backend.tool
    def submit(payload: str) -> str:
        """Submit something."""
        return payload

    return backend


def _gated_backend() -> FastMCP:
    backend = FastMCP(name="gated-backend")

    @backend.tool
    def secret() -> str:
        """Only holders of the gating permission may see this."""
        return "ok"

    return backend


@pytest.fixture
async def data_backend_url() -> AsyncIterator[str]:
    async with run_inprocess_server(_data_backend(), path="/mcp") as url:
        yield url


@pytest.fixture
async def gated_backend_url() -> AsyncIterator[str]:
    async with run_inprocess_server(_gated_backend(), path="/mcp") as url:
        yield url


@pytest.fixture
def dead_backend_url() -> str:
    return f"http://127.0.0.1:{find_available_port()}/mcp"


def _spec(name: str, url: str, **overrides: Any) -> ServiceSpec:
    defaults: dict[str, Any] = {
        "prefix": name,
        "transport": "http",
        "required_permission": "__none__",
        "auth_type": "none",
        "description": f"The {name} backend.",
        "display_name": name.title(),
    }
    defaults.update(overrides)
    return ServiceSpec(name=name, url=url, **defaults)


def _policy(*rules: RateLimitRule) -> EntitlementPolicy:
    return EntitlementPolicy(
        group_permissions={"atlas": ["read_data"], "__authenticated__": []},
        # data_submit is the one state-changing tool of the data backend.
        target_action_types={"data": {"data_submit": "state_change"}},
        rate_limits=list(rules),
    )


def _make_app(
    registry: ServiceRegistry, policy: EntitlementPolicy, principal: Any
) -> FastAPI:
    app = FastAPI()
    app.include_router(rate_limits.router, prefix="/v1")
    app.state.broker = make_broker_state(
        service_registry=registry, entitlement_policy=policy
    )
    app.dependency_overrides[keycloak_dependency] = lambda: principal
    return app


@asynccontextmanager
async def _client(app: FastAPI) -> AsyncIterator[httpx2.AsyncClient]:
    transport = httpx2.ASGITransport(app=app)
    async with httpx2.AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


async def _get(app: FastAPI) -> dict[str, Any]:
    async with _client(app) as client:
        resp = await client.get("/v1/rate-limits")
    assert resp.status_code == 200, resp.text
    return resp.json()


async def test_each_rule_lists_the_callers_tools_it_covers(
    make_principal: Callable[..., Any], data_backend_url: str
) -> None:
    registry = ServiceRegistry()
    registry.register(_spec("data", data_backend_url))
    app = _make_app(
        registry,
        _policy(WRITE_RULE, DATA_RULE, UNMATCHED_RULE),
        make_principal(groups=["atlas"]),
    )

    body = await _get(app)

    write, data, unmatched = body["rate_limits"]
    assert write["tools"] == ["data_submit"]
    assert data["tools"] == ["data_replica", "data_submit"]
    assert unmatched["tools"] == []
    assert body["unlisted_services"] == []


async def test_tools_the_caller_is_not_entitled_to_are_not_listed(
    make_principal: Callable[..., Any], data_backend_url: str, gated_backend_url: str
) -> None:
    registry = ServiceRegistry()
    registry.register(_spec("data", data_backend_url))
    registry.register(_spec("gated", gated_backend_url, required_permission="admin"))
    rule = RateLimitRule(1, 300, tool="*")
    app = _make_app(registry, _policy(rule), make_principal(groups=["atlas"]))

    body = await _get(app)

    [only] = body["rate_limits"]
    assert only["tools"] == ["data_replica", "data_submit"]
    # No permission, no listing attempt: the service is reported as unlisted so
    # a reader knows the list covers only part of the registry.
    assert body["unlisted_services"] == ["gated"]


async def test_an_unreachable_service_is_reported_not_fatal(
    make_principal: Callable[..., Any], data_backend_url: str, dead_backend_url: str
) -> None:
    registry = ServiceRegistry()
    registry.register(_spec("data", data_backend_url))
    registry.register(_spec("dead", dead_backend_url))
    app = _make_app(registry, _policy(DATA_RULE), make_principal(groups=["atlas"]))

    body = await _get(app)

    [rule] = body["rate_limits"]
    assert rule["tools"] == ["data_replica", "data_submit"]
    assert body["unlisted_services"] == ["dead"]


async def test_no_rules_lists_no_service(
    make_principal: Callable[..., Any], dead_backend_url: str
) -> None:
    # A dead backend would cost a connection attempt, so an empty body proves
    # nothing was listed for a policy without rules.
    registry = ServiceRegistry()
    registry.register(_spec("dead", dead_backend_url))
    app = _make_app(registry, _policy(), make_principal(groups=["atlas"]))

    body = await _get(app)

    assert body["rate_limits"] == []
    assert body["unlisted_services"] == []
