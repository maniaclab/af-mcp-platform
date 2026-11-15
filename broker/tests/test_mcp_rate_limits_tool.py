"""Tests for af_rate_limits: the caller's own rate limits, which of their entitled tools each covers, and their usage so far.

Exercised through a real aggregator, real in-process backends and a real
redis server, because "only entitled tools" and "only my count" mean
something only through the real middleware and store.
"""

from __future__ import annotations

import uuid
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, Any

import pytest
import structlog
from conftest import (
    AUDIENCE,
    ISSUER,
    make_claims,
    run_aggregator_async,
    run_inprocess_server,
)
from fastmcp import FastMCP

from af_mcp_broker.authorization import EntitlementPolicy, RateLimitRule
from af_mcp_broker.authorization import rate_limit as rate_limit_module
from af_mcp_broker.authorization.rate_limit import tool_rate_limit_key
from af_mcp_broker.config import Settings
from af_mcp_broker.credentials import CredentialRegistry
from af_mcp_broker.mcp.aggregator import build_aggregator
from af_mcp_broker.service_registry import (
    DIAGNOSTIC_TOOL_NAMES,
    RATE_LIMITS_TOOL_NAME,
    ServiceRegistry,
    ServiceSpec,
)
from af_mcp_broker.shared_state import RedisSharedState

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable

    from fastmcp import Client

DATA_RULE = RateLimitRule(5, 300, tool="data_*")
WRITE_RULE = RateLimitRule(60, 300, action_type="state_change")
SECRET_RULE = RateLimitRule(1, 300, tool="secret_*")


def _data_backend() -> FastMCP:
    backend = FastMCP(name="data-backend")

    @backend.tool(description="Return one replica of a dataset.")
    def replica() -> str:
        return "ok"

    @backend.tool(description="Enumerate things.")
    def replica_list() -> str:
        return "ok"

    return backend


def _secret_backend() -> FastMCP:
    backend = FastMCP(name="secret-backend")

    @backend.tool(description="Return a replica only admins may see.")
    def replica() -> str:
        return "ok"

    return backend


@pytest.fixture
def subject() -> str:
    # The redis server outlives each test, so a subject unique to this one.
    return f"user-{uuid.uuid4()}"


@pytest.fixture
async def rate_limit_client(
    sig_key: Any,
    prime_jwks: Any,
    static_principal_cache: Any,
    subject: str,
    shared_state_url: str,
) -> AsyncIterator[Callable[..., Any]]:
    """Yield a builder of clients for a gateway enforcing the given rules."""
    principal_cache, directory = static_principal_cache
    directory.groups_by_subject[subject] = ["af-atlas-users"]
    prime_jwks([sig_key.jwk])
    token = sig_key.sign(make_claims(sub=subject))
    stores: list[RedisSharedState] = []

    @asynccontextmanager
    async def _build(
        *rules: RateLimitRule, store_url: str | None = None
    ) -> AsyncIterator[Client]:
        store = RedisSharedState(store_url or shared_state_url)
        stores.append(store)
        registry = ServiceRegistry()
        async with (
            run_inprocess_server(_data_backend()) as data_url,
            run_inprocess_server(_secret_backend()) as secret_url,
        ):
            for name, url, permission in (
                ("data", data_url, "read_data"),
                ("secret", secret_url, "admin_data"),
            ):
                registry.register(
                    ServiceSpec(
                        name=f"{name}_service",
                        prefix=name,
                        url=url,
                        transport="http",
                        required_permission=permission,
                        auth_type="none",
                    )
                )
            policy = EntitlementPolicy(
                group_permissions={"af-atlas-users": ["read_data"]}
            )
            policy.rate_limits = list(rules)
            mcp = build_aggregator(
                registry,
                Settings(oidc_issuer=ISSUER, oidc_audience=AUDIENCE),
                policy,
                CredentialRegistry(),
                principal_cache=principal_cache,
                shared_state=store,
            )
            async with (
                run_aggregator_async(mcp, path="/mcp") as server,
                server.client(headers={"Authorization": f"Bearer {token}"}) as client,
            ):
                yield client

    yield _build
    for store in stores:
        await store.close()


async def _rate_limits(client: Client) -> dict[str, Any]:
    result = await client.call_tool(RATE_LIMITS_TOOL_NAME, {})
    return result.structured_content


async def test_tool_is_a_diagnostic_read_only_tool_with_an_output_schema(
    rate_limit_client,
) -> None:
    assert RATE_LIMITS_TOOL_NAME == "af_rate_limits"
    assert RATE_LIMITS_TOOL_NAME in DIAGNOSTIC_TOOL_NAMES
    async with rate_limit_client(DATA_RULE) as client:
        tool = next(
            t for t in await client.list_tools() if t.name == RATE_LIMITS_TOOL_NAME
        )

    assert tool.annotations is not None
    assert tool.annotations.read_only_hint is True
    assert tool.annotations.open_world_hint is False
    assert tool.output_schema is not None
    assert tool.output_schema["type"] == "object"
    # N2: the first description line is a one-line summary.
    first_line = (tool.description or "").splitlines()[0]
    assert first_line
    assert len(first_line) <= 120


async def test_reports_rules_usage_and_the_entitled_tools_each_covers(
    rate_limit_client,
) -> None:
    async with rate_limit_client(DATA_RULE, WRITE_RULE, SECRET_RULE) as client:
        await client.call_tool("data_replica", {})
        await client.call_tool("data_replica", {})
        body = await _rate_limits(client)

    assert body["usage_available"] is True
    data, write, secret = body["rules"]
    assert (data["tool"], data["action_type"]) == ("data_*", None)
    assert (data["limit"], data["window_seconds"]) == (5, 300)
    assert data["used"] == 2
    assert 0 < data["resets_in_seconds"] <= 300
    assert data["tools"] == ["data_replica", "data_replica_list"]
    assert data["tool_count"] == 2
    # Nothing the caller may call changes state, and nothing was counted.
    assert (write["used"], write["resets_in_seconds"]) == (0, None)
    assert write["tools"] == []
    # An unentitled tool is never listed, even though the rule's glob matches.
    assert secret["tools"] == []
    assert "\n" not in body["summary"]
    assert "3 rate limits" in body["summary"]


async def test_usage_is_the_callers_own(rate_limit_client, shared_state_url) -> None:
    other = RedisSharedState(shared_state_url)
    try:
        for _ in range(4):
            await other.incr_window(tool_rate_limit_key(DATA_RULE, "someone-else"), 300)
        async with rate_limit_client(DATA_RULE) as client:
            body = await _rate_limits(client)
    finally:
        await other.close()

    assert body["rules"][0]["used"] == 0


async def test_unreachable_store_gives_unknown_usage_and_a_note(
    rate_limit_client,
    unreachable_shared_state_url,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A booted app pins module loggers; give this one a fresh logger so
    # capture_logs sees it.
    monkeypatch.setattr(
        rate_limit_module, "logger", structlog.get_logger(rate_limit_module.__name__)
    )
    async with rate_limit_client(
        DATA_RULE, store_url=unreachable_shared_state_url
    ) as client:
        with structlog.testing.capture_logs() as logs:
            body = await _rate_limits(client)

    assert body["usage_available"] is False
    [rule] = body["rules"]
    assert (rule["limit"], rule["used"], rule["resets_in_seconds"]) == (5, None, None)
    assert rule["tools"] == ["data_replica", "data_replica_list"]
    assert "usage" in body["note"].lower()
    assert "rate_limits.shared_state_unavailable" in [log["event"] for log in logs]


async def test_no_rules_gives_an_actionable_empty_result(rate_limit_client) -> None:
    async with rate_limit_client() as client:
        body = await _rate_limits(client)

    assert body["rules"] == []
    assert body["summary"] == "No rate limits are configured."
    assert "not rate limited" in body["note"]
