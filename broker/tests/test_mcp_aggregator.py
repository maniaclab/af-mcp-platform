from __future__ import annotations

from typing import Any

import pytest
from fastmcp import FastMCP
from fastmcp.client import Client
from fastmcp.client.transports import SSETransport, StreamableHttpTransport

from af_mcp_broker.authorization import EntitlementPolicy
from af_mcp_broker.mcp.aggregator import (
    _make_client_factory,
    build_aggregator,
    populate_aggregator,
)
from af_mcp_broker.mcp.middleware.entitlement_mw import EntitlementMiddleware
from af_mcp_broker.mcp.middleware.identity_mw import IdentityMiddleware
from af_mcp_broker.mcp.registry import BackendRegistry, BackendSpec


def _spec(**overrides: Any) -> BackendSpec:
    defaults: dict[str, Any] = {
        "name": "example",
        "prefix": "example",
        "url": "http://example.invalid/mcp",
        "transport": "http",
        "required_capability": "__none__",
    }
    defaults.update(overrides)
    return BackendSpec(**defaults)


def test_build_aggregator_returns_fastmcp(settings: Any) -> None:
    mcp = build_aggregator(BackendRegistry(), settings, EntitlementPolicy())
    assert isinstance(mcp, FastMCP)


def test_build_aggregator_wires_identity_before_entitlement(settings: Any) -> None:
    """First-registered middleware runs outermost -- identity must extract
    the Principal before entitlement filtering reads it. FastMCP itself
    prepends its own DereferenceRefsMiddleware, so assert relative order
    between ours rather than absolute list positions."""
    mcp = build_aggregator(BackendRegistry(), settings, EntitlementPolicy())
    identity_index = next(
        i for i, mw in enumerate(mcp.middleware) if isinstance(mw, IdentityMiddleware)
    )
    entitlement_index = next(
        i
        for i, mw in enumerate(mcp.middleware)
        if isinstance(mw, EntitlementMiddleware)
    )
    assert identity_index < entitlement_index


def test_build_aggregator_registers_one_provider_per_backend(settings: Any) -> None:
    registry = BackendRegistry()
    registry.register(_spec(name="a", prefix="a"))
    registry.register(_spec(name="b", prefix="b"))

    mcp = build_aggregator(registry, settings, EntitlementPolicy())

    assert len(mcp.providers) == 2


def test_populate_aggregator_replaces_providers_not_appends(settings: Any) -> None:
    registry_a = BackendRegistry()
    registry_a.register(_spec(name="a", prefix="a"))
    mcp = build_aggregator(registry_a, settings, EntitlementPolicy())
    assert len(mcp.providers) == 1

    registry_b = BackendRegistry()
    registry_b.register(_spec(name="b", prefix="b"))
    registry_b.register(_spec(name="c", prefix="c"))
    populate_aggregator(mcp, registry_b, settings, EntitlementPolicy())

    assert len(mcp.providers) == 2


def test_populate_aggregator_refreshes_middleware_state(settings: Any) -> None:
    mcp = build_aggregator(BackendRegistry(), settings, EntitlementPolicy())
    identity_mw = next(
        mw for mw in mcp.middleware if isinstance(mw, IdentityMiddleware)
    )
    entitlement_mw = next(
        mw for mw in mcp.middleware if isinstance(mw, EntitlementMiddleware)
    )

    new_registry = BackendRegistry()
    new_registry.register(_spec(name="a", prefix="a"))
    new_policy = EntitlementPolicy(group_capabilities={"atlas": ["read_data"]})
    new_settings = settings.model_copy(update={"oidc_audience": "something-else"})

    populate_aggregator(mcp, new_registry, new_settings, new_policy)

    assert identity_mw.settings is new_settings
    assert entitlement_mw.registry is new_registry
    assert entitlement_mw.policy is new_policy


def test_populate_aggregator_raises_if_middleware_missing(settings: Any) -> None:
    mcp = FastMCP(name="bare")
    with pytest.raises(RuntimeError, match="build_aggregator"):
        populate_aggregator(mcp, BackendRegistry(), settings, EntitlementPolicy())


@pytest.mark.parametrize(
    ("transport", "expected_type"),
    [("http", StreamableHttpTransport), ("sse", SSETransport)],
)
def test_client_factory_selects_transport_by_spec(
    transport: str, expected_type: type
) -> None:
    spec = _spec(transport=transport, url="http://example.invalid/mcp")
    factory = _make_client_factory(spec)
    client = factory()
    assert isinstance(client, Client)
    assert isinstance(client.transport, expected_type)
    # The security property this whole factory exists for: plain Client +
    # an explicit transport object never sets forward_incoming_headers,
    # unlike fastmcp's ProxyClient convenience wrapper (which this code
    # deliberately avoids using).
    assert client.transport.forward_incoming_headers is False
