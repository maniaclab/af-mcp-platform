"""Integration tests for policy.yaml's ``rate_limits`` (issue #165) through the real aggregator middleware chain, served in-process, with a real MCP client."""

from __future__ import annotations

import io
import json
from typing import TYPE_CHECKING, Any

import pytest
from conftest import make_claims, run_aggregator_async, run_inprocess_server
from fastmcp import Client, FastMCP
from fastmcp.exceptions import ToolError

from af_mcp_broker.audit.logger import init_audit_logger
from af_mcp_broker.authorization import EntitlementPolicy, RateLimitRule
from af_mcp_broker.credentials import CredentialRegistry
from af_mcp_broker.mcp.aggregator import build_aggregator
from af_mcp_broker.mcp.registry import ServiceRegistry, ServiceSpec

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from fastmcp.utilities.tests import ASGIServer


def _backend() -> FastMCP:
    mcp = FastMCP(name="rate-limit-backend")

    @mcp.tool
    def ping() -> str:
        return "pong"

    @mcp.tool
    def other() -> str:
        return "other"

    return mcp


@pytest.fixture
async def backend_url() -> AsyncIterator[str]:
    async with run_inprocess_server(_backend(), path="/mcp") as url:
        yield url


@pytest.fixture
def registry(backend_url: str) -> ServiceRegistry:
    registry = ServiceRegistry()
    registry.register(
        ServiceSpec(
            name="open",
            prefix="open",
            url=backend_url,
            transport="http",
            required_permission="__none__",
            auth_type="none",
        )
    )
    return registry


def _policy(*rules: RateLimitRule) -> EntitlementPolicy:
    return EntitlementPolicy(
        group_permissions={"__authenticated__": []}, rate_limits=list(rules)
    )


def _serve(
    settings: Any,
    registry: ServiceRegistry,
    principal_cache: Any,
    policy: EntitlementPolicy,
) -> Any:
    mcp = build_aggregator(
        registry,
        settings,
        policy,
        CredentialRegistry(),
        principal_cache=principal_cache,
    )
    return run_aggregator_async(mcp, path="/mcp")


def _client(server: ASGIServer, token: str) -> Client:
    return server.client(headers={"Authorization": f"Bearer {token}"})


async def test_calls_past_the_limit_are_refused_with_retry_info_and_audited(
    settings: Any,
    registry: ServiceRegistry,
    static_principal_cache: Any,
    sig_key: Any,
    prime_jwks: Any,
) -> None:
    prime_jwks([sig_key.jwk])
    token = sig_key.sign(make_claims())
    principal_cache, _directory = static_principal_cache
    audit_buffer = io.StringIO()
    init_audit_logger(audit_buffer)
    policy = _policy(RateLimitRule(2, 3600, tool="open_ping"))

    async with (
        _serve(settings, registry, principal_cache, policy) as server,
        _client(server, token) as client,
    ):
        assert (await client.call_tool("open_ping", {})).data == "pong"
        assert (await client.call_tool("open_ping", {})).data == "pong"
        with pytest.raises(ToolError) as excinfo:
            await client.call_tool("open_ping", {})
        # A tool the rule does not match is unaffected.
        assert (await client.call_tool("open_other", {})).data == "other"

    message = str(excinfo.value)
    assert "Rate limit of 2 calls per 3600s exceeded for open_ping" in message
    assert "Retry-After: " in message
    assert "retry_at: " in message
    lines = [json.loads(line) for line in audit_buffer.getvalue().splitlines()]
    outcomes = [(line["action"], line["outcome"]) for line in lines]
    assert outcomes.count(("open_ping", "rate_limited")) == 1
    limited = next(line for line in lines if line["outcome"] == "rate_limited")
    assert limited["mcp_service"] == "open"
    assert limited["principal_sub"] == "user-123"


async def test_budget_is_per_principal_through_the_chain(
    settings: Any,
    registry: ServiceRegistry,
    static_principal_cache: Any,
    sig_key: Any,
    prime_jwks: Any,
) -> None:
    prime_jwks([sig_key.jwk])
    alice = sig_key.sign(make_claims(sub="alice"))
    bob = sig_key.sign(make_claims(sub="bob"))
    principal_cache, _directory = static_principal_cache
    init_audit_logger(io.StringIO())
    policy = _policy(RateLimitRule(1, 3600, tool="open_ping"))

    async with _serve(settings, registry, principal_cache, policy) as server:
        async with _client(server, alice) as client:
            await client.call_tool("open_ping", {})
            with pytest.raises(ToolError):
                await client.call_tool("open_ping", {})
        async with _client(server, bob) as client:
            assert (await client.call_tool("open_ping", {})).data == "pong"


async def test_absent_rate_limits_never_refuse(
    settings: Any,
    registry: ServiceRegistry,
    static_principal_cache: Any,
    sig_key: Any,
    prime_jwks: Any,
) -> None:
    prime_jwks([sig_key.jwk])
    token = sig_key.sign(make_claims())
    principal_cache, _directory = static_principal_cache
    audit_buffer = io.StringIO()
    init_audit_logger(audit_buffer)

    async with (
        _serve(settings, registry, principal_cache, _policy()) as server,
        _client(server, token) as client,
    ):
        for _ in range(10):
            assert (await client.call_tool("open_ping", {})).data == "pong"

    assert "rate_limited" not in audit_buffer.getvalue()
