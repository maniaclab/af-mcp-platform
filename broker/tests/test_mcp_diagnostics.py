from __future__ import annotations

import io
import json
import time
from typing import TYPE_CHECKING, Any

import pytest
from conftest import make_claims, run_aggregator_async
from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport
from fastmcp.exceptions import ToolError
from tokencost import calculate_cost_by_tokens  # type: ignore[import-untyped]

from af_mcp_broker.audit import AuditRecord
from af_mcp_broker.audit.logger import init_audit_logger
from af_mcp_broker.authorization import EntitlementPolicy
from af_mcp_broker.config import KeycloakBrokeredProviderConfig
from af_mcp_broker.credentials import (
    CredentialProvider,
    CredentialRegistry,
    ExecutionModel,
)
from af_mcp_broker.mcp.aggregator import build_aggregator
from af_mcp_broker.mcp.registry import (
    LINK_IDENTITY_TOOL_NAME,
    LIST_IDENTITIES_TOOL_NAME,
    LIST_MCP_SERVERS_TOOL_NAME,
    USAGE_TOOL_NAME,
    WHOAMI_TOOL_NAME,
    ServiceRegistry,
    ServiceSpec,
    identity_provider_url,
)
from af_mcp_broker.usage import aclose_usage_store, init_usage_store

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from af_mcp_broker.identity import Principal
    from af_mcp_broker.usage import UsageStore

# ---------------------------------------------------------------------------
# End-to-end tests for the af_* diagnostic tools (issue #153), exercised
# through a real aggregator (build_aggregator + run_aggregator_async) rather
# than by calling the tool closures directly -- register_diagnostic_tools()
# defines them as closures local to that function, so a real MCP round trip
# (the same harness test_mcp_call_time_errors.py already uses) is the
# natural way to invoke them and also proves they're actually reachable
# through EntitlementMiddleware/AuthorizationMiddleware's bypass, not just
# correct in isolation.
# ---------------------------------------------------------------------------


class _FakeIdentityProvider(CredentialProvider):
    """A minimal CredentialProvider double whose is_linked() outcome is fixed at construction -- af_list_identities never calls issue(), so it's left unimplemented."""

    cred_class = "fake-identity"
    execution_model = ExecutionModel.DELEGATED

    def __init__(self, *, linked: bool) -> None:
        self._linked = linked

    async def is_linked(self, principal: Principal) -> bool:
        return self._linked

    async def issue(self, principal: Principal, target: str, **kwargs: Any) -> Any:
        raise NotImplementedError


def _idp_config(display_name: str, enables: str) -> KeycloakBrokeredProviderConfig:
    return KeycloakBrokeredProviderConfig(
        alias=display_name.lower(),
        display_name=display_name,
        enables=enables,
    )


async def test_af_tools_declare_a_proper_object_output_schema(
    settings: Any, sig_key: Any, prime_jwks: Any, static_principal_cache: Any
) -> None:
    """Every af_* tool must advertise an authored object outputSchema (issue
    #216 A.1): a non-null ``{"type": "object", ...}`` a client can type-check
    and compose against. FastMCP auto-wraps a bare ``list[...]`` return under a
    synthetic single ``result`` key stamped ``x-fastmcp-wrap-result: true`` --
    that IS an object schema, but ``result`` is a meaningless machine name, no
    real contract, so it doesn't count here; the list-returning tools declare
    their own wrapper model with a self-describing field instead."""
    principal_cache, directory = static_principal_cache
    directory.groups_by_subject["user-123"] = []
    prime_jwks([sig_key.jwk])
    token = sig_key.sign(make_claims())

    mcp = build_aggregator(
        ServiceRegistry(),
        settings,
        EntitlementPolicy(),
        CredentialRegistry(),
        principal_cache=principal_cache,
    )

    async with run_aggregator_async(mcp, path="/mcp") as agg_url:
        transport = StreamableHttpTransport(
            agg_url, headers={"Authorization": f"Bearer {token}"}
        )
        async with Client(transport) as client:
            tools = await client.list_tools()

    by_name = {t.name: t for t in tools}
    for name in (
        WHOAMI_TOOL_NAME,
        LIST_IDENTITIES_TOOL_NAME,
        LIST_MCP_SERVERS_TOOL_NAME,
        LINK_IDENTITY_TOOL_NAME,
        USAGE_TOOL_NAME,
    ):
        schema = by_name[name].outputSchema
        assert schema is not None, f"{name} has no outputSchema"
        assert schema.get("type") == "object", f"{name} outputSchema is not an object"
        assert not schema.get("x-fastmcp-wrap-result"), (
            f"{name} relies on FastMCP's synthetic result wrapper rather than "
            "an authored object schema"
        )


async def test_af_whoami_returns_subject_groups_and_permissions(
    settings: Any, sig_key: Any, prime_jwks: Any, static_principal_cache: Any
) -> None:
    principal_cache, directory = static_principal_cache
    directory.groups_by_subject["user-123"] = ["atlas"]
    prime_jwks([sig_key.jwk])
    token = sig_key.sign(make_claims())
    policy = EntitlementPolicy(group_permissions={"atlas": ["read_data"]})

    mcp = build_aggregator(
        ServiceRegistry(),
        settings,
        policy,
        CredentialRegistry(),
        principal_cache=principal_cache,
    )

    async with run_aggregator_async(mcp, path="/mcp") as agg_url:
        transport = StreamableHttpTransport(
            agg_url, headers={"Authorization": f"Bearer {token}"}
        )
        async with Client(transport) as client:
            result = await client.call_tool(WHOAMI_TOOL_NAME, {})

    assert result.structured_content["subject"] == "user-123"
    assert result.structured_content["groups"] == ["atlas"]
    assert result.structured_content["permissions"] == ["read_data"]


async def test_af_list_identities_reflects_linkage_per_provider(
    settings: Any, sig_key: Any, prime_jwks: Any, static_principal_cache: Any
) -> None:
    principal_cache, directory = static_principal_cache
    directory.groups_by_subject["user-123"] = []
    prime_jwks([sig_key.jwk])
    token = sig_key.sign(make_claims())

    identity_providers = {
        "linked-idp": _FakeIdentityProvider(linked=True),
        "unlinked-idp": _FakeIdentityProvider(linked=False),
    }
    identity_provider_configs = {
        "linked-idp": _idp_config("Linked IdP", "VOMS proxy generation"),
        "unlinked-idp": _idp_config("Unlinked IdP", "GitLab access"),
    }

    mcp = build_aggregator(
        ServiceRegistry(),
        settings,
        EntitlementPolicy(),
        CredentialRegistry(),
        principal_cache=principal_cache,
        identity_providers=identity_providers,
        identity_provider_configs=identity_provider_configs,
    )

    async with run_aggregator_async(mcp, path="/mcp") as agg_url:
        transport = StreamableHttpTransport(
            agg_url, headers={"Authorization": f"Bearer {token}"}
        )
        async with Client(transport) as client:
            result = await client.call_tool(LIST_IDENTITIES_TOOL_NAME, {})

    rows = {row["id"]: row for row in result.structured_content["identities"]}
    assert rows["linked-idp"] == {
        "id": "linked-idp",
        "display_name": "Linked IdP",
        "enables": "VOMS proxy generation",
        "linked": True,
    }
    assert rows["unlinked-idp"]["linked"] is False
    assert rows["unlinked-idp"]["enables"] == "GitLab access"


async def test_af_link_identity_returns_portal_url_and_linked_status(
    settings: Any, sig_key: Any, prime_jwks: Any, static_principal_cache: Any
) -> None:
    """af_link_identity (stage 1 of the elicitation/link-identity design)
    returns the exact portal deep link af_list_identities' `linked: false`
    should send the caller to, plus the provider's current linkage status
    (informational -- re-linking an already-linked provider, e.g. to rotate
    an x509 passphrase, is a valid call too)."""
    principal_cache, directory = static_principal_cache
    directory.groups_by_subject["user-123"] = []
    prime_jwks([sig_key.jwk])
    token = sig_key.sign(make_claims())

    identity_providers = {
        "linked-idp": _FakeIdentityProvider(linked=True),
        "unlinked-idp": _FakeIdentityProvider(linked=False),
    }
    identity_provider_configs = {
        "linked-idp": _idp_config("Linked IdP", "VOMS proxy generation"),
        "unlinked-idp": _idp_config("Unlinked IdP", "GitLab access"),
    }

    mcp = build_aggregator(
        ServiceRegistry(),
        settings,
        EntitlementPolicy(),
        CredentialRegistry(),
        principal_cache=principal_cache,
        identity_providers=identity_providers,
        identity_provider_configs=identity_provider_configs,
    )

    async with run_aggregator_async(mcp, path="/mcp") as agg_url:
        transport = StreamableHttpTransport(
            agg_url, headers={"Authorization": f"Bearer {token}"}
        )
        async with Client(transport) as client:
            linked_result = await client.call_tool(
                LINK_IDENTITY_TOOL_NAME, {"provider": "linked-idp"}
            )
            unlinked_result = await client.call_tool(
                LINK_IDENTITY_TOOL_NAME, {"provider": "unlinked-idp"}
            )

    assert linked_result.structured_content == {
        "id": "linked-idp",
        "display_name": "Linked IdP",
        "url": identity_provider_url(settings, "linked-idp"),
        "already_linked": True,
    }
    assert unlinked_result.structured_content == {
        "id": "unlinked-idp",
        "display_name": "Unlinked IdP",
        "url": identity_provider_url(settings, "unlinked-idp"),
        "already_linked": False,
    }


async def test_af_link_identity_unknown_provider_raises_tool_error(
    settings: Any, sig_key: Any, prime_jwks: Any, static_principal_cache: Any
) -> None:
    principal_cache, directory = static_principal_cache
    directory.groups_by_subject["user-123"] = []
    prime_jwks([sig_key.jwk])
    token = sig_key.sign(make_claims())

    identity_providers = {"linked-idp": _FakeIdentityProvider(linked=True)}
    identity_provider_configs = {"linked-idp": _idp_config("Linked IdP", "Some access")}

    mcp = build_aggregator(
        ServiceRegistry(),
        settings,
        EntitlementPolicy(),
        CredentialRegistry(),
        principal_cache=principal_cache,
        identity_providers=identity_providers,
        identity_provider_configs=identity_provider_configs,
    )

    async with run_aggregator_async(mcp, path="/mcp") as agg_url:
        transport = StreamableHttpTransport(
            agg_url, headers={"Authorization": f"Bearer {token}"}
        )
        async with Client(transport) as client:
            with pytest.raises(ToolError) as excinfo:
                await client.call_tool(
                    LINK_IDENTITY_TOOL_NAME, {"provider": "no-such-provider"}
                )

    assert "no-such-provider" in str(excinfo.value)
    assert "linked-idp" in str(excinfo.value)
    assert LIST_IDENTITIES_TOOL_NAME in str(excinfo.value)


async def test_af_list_mcp_servers_reuses_service_status_and_identity_join(
    settings: Any, sig_key: Any, prime_jwks: Any, static_principal_cache: Any
) -> None:
    """Reuses api/permissions.py's _service_status() (issue #123) and the
    target_to_alias identity<->backend join (issue #90) rather than
    reimplementing either -- this asserts the same statuses/joins /v1/catalog
    would report for the identical setup, through the MCP tool instead."""
    principal_cache, directory = static_principal_cache
    directory.groups_by_subject["user-123"] = []
    prime_jwks([sig_key.jwk])
    token = sig_key.sign(make_claims())

    registry = ServiceRegistry()
    registry.register(
        ServiceSpec(
            name="open",
            prefix="open",
            url="http://open.invalid/mcp",
            transport="http",
            required_permission="__none__",
            auth_type="none",
            display_name="Open Backend",
        )
    )
    registry.register(
        ServiceSpec(
            name="gated",
            prefix="gated",
            url="http://gated.invalid/mcp",
            transport="http",
            required_permission="read_data",
            auth_type="none",
            display_name="Gated Backend",
        )
    )
    registry.register(
        ServiceSpec(
            name="needs-link",
            prefix="needslink",
            url="http://needslink.invalid/mcp",
            transport="http",
            required_permission="__none__",
            auth_type="bearer",
            display_name="Needs Link Backend",
        )
    )
    credential_registry = CredentialRegistry()
    unlinked_provider = _FakeIdentityProvider(linked=False)
    credential_registry.register("needs-link", unlinked_provider)
    target_to_alias = {"needs-link": "unlinked-idp"}

    mcp = build_aggregator(
        registry,
        settings,
        EntitlementPolicy(group_permissions={"atlas": ["read_data"]}),
        credential_registry,
        principal_cache=principal_cache,
        target_to_alias=target_to_alias,
    )

    async with run_aggregator_async(mcp, path="/mcp") as agg_url:
        transport = StreamableHttpTransport(
            agg_url, headers={"Authorization": f"Bearer {token}"}
        )
        async with Client(transport) as client:
            result = await client.call_tool(LIST_MCP_SERVERS_TOOL_NAME, {})

    rows = {row["name"]: row for row in result.structured_content["servers"]}
    assert rows["open"]["status"] == "available"
    assert rows["open"]["prefix"] == "open"
    assert rows["open"]["credential_provider"] is None
    assert rows["gated"]["status"] == "permission_required"
    assert rows["needs-link"]["status"] == "link_required"
    assert rows["needs-link"]["credential_provider"] == "unlinked-idp"
    # The gateway lists itself too (issue #240): the builtin af-mcp service
    # is always present and available -- even to this zero-permission caller
    # -- with no identity provider servicing it.
    assert rows["gateway_service"]["status"] == "available"
    assert rows["gateway_service"]["prefix"] == "af"
    assert rows["gateway_service"]["credential_provider"] is None
    assert rows["gateway_service"]["display_name"]


async def test_diagnostic_tools_visible_to_principal_with_no_permissions(
    settings: Any, sig_key: Any, prime_jwks: Any, static_principal_cache: Any
) -> None:
    """Requirement: the af_* methods must be visible regardless of
    entitlements -- a principal with zero group memberships (so zero
    permissions) still sees all five, even while a permission-gated
    backend's own tools stay hidden (proving this isn't just "entitlement
    filtering is broken"). Since issue #240 the visibility comes from the
    builtin af-mcp service's "__none__" permission on the normal filtering
    path, not a name-based bypass."""
    principal_cache, directory = static_principal_cache
    directory.groups_by_subject["user-123"] = []
    prime_jwks([sig_key.jwk])
    token = sig_key.sign(make_claims())

    registry = ServiceRegistry()
    registry.register(
        ServiceSpec(
            name="gated",
            prefix="gated",
            url="http://gated.invalid/mcp",
            transport="http",
            required_permission="read_data",
            auth_type="none",
        )
    )
    policy = EntitlementPolicy(group_permissions={"atlas": ["read_data"]})

    mcp = build_aggregator(
        registry,
        settings,
        policy,
        CredentialRegistry(),
        principal_cache=principal_cache,
    )

    async with run_aggregator_async(mcp, path="/mcp") as agg_url:
        transport = StreamableHttpTransport(
            agg_url, headers={"Authorization": f"Bearer {token}"}
        )
        async with Client(transport) as client:
            tools = await client.list_tools()

    names = {t.name for t in tools}
    assert {
        WHOAMI_TOOL_NAME,
        LIST_IDENTITIES_TOOL_NAME,
        LIST_MCP_SERVERS_TOOL_NAME,
        LINK_IDENTITY_TOOL_NAME,
        USAGE_TOOL_NAME,
    } <= names
    # The permission-gated backend's own tool is correctly still hidden --
    # proves the af_* visibility above is a deliberate bypass, not a broken
    # entitlement filter that would let everything through.
    assert not any(n.startswith("gated_") for n in names)


async def test_af_whoami_call_is_audited_and_metered_as_the_gateway_service(
    settings: Any, sig_key: Any, prime_jwks: Any, static_principal_cache: Any
) -> None:
    """Issue #240: with the DIAGNOSTIC_TOOL_NAMES bypass gone, a successful
    af_* call produces an audit line like any other call -- service af-mcp,
    measured result (bytes/token estimate) and duration included -- proven
    through a real aggregator round trip by a principal with zero
    permissions (the builtin service's "__none__" admits them)."""
    principal_cache, directory = static_principal_cache
    directory.groups_by_subject["user-123"] = []
    prime_jwks([sig_key.jwk])
    token = sig_key.sign(make_claims())

    buffer = io.StringIO()
    init_audit_logger(buffer)

    mcp = build_aggregator(
        ServiceRegistry(),
        settings,
        EntitlementPolicy(),
        CredentialRegistry(),
        principal_cache=principal_cache,
    )

    async with run_aggregator_async(mcp, path="/mcp") as agg_url:
        transport = StreamableHttpTransport(
            agg_url, headers={"Authorization": f"Bearer {token}"}
        )
        async with Client(transport) as client:
            await client.call_tool(WHOAMI_TOOL_NAME, {})

    line = json.loads(buffer.getvalue().strip())
    assert line["event"] == "audit"
    assert line["outcome"] == "success"
    assert line["mcp_service"] == "gateway_service"
    assert line["target"] == "gateway_service"
    assert line["action"] == WHOAMI_TOOL_NAME
    assert line["permission"] == "__none__"
    assert line["principal_sub"] == "user-123"
    assert line["duration_ms"] >= 0.0
    # The success path measures the result exactly like a proxied call's --
    # af_whoami returned a non-empty structured payload, so both fields are
    # populated (no pipeline installed in this harness, so the fallback
    # measured and wrote synchronously).
    assert line["result_bytes"] > 0
    assert line["result_tokens_est"] > 0


async def test_no_diagnostic_tool_response_contains_a_url(
    settings: Any, sig_key: Any, prime_jwks: Any, static_principal_cache: Any
) -> None:
    """Never leak: no af_* diagnostic tool's response may contain a URL
    -- not a backend's internal address, not the portal's own link URL. The
    generic "go to the portal" instruction lives in the *static* tool
    description / the pre-existing not-linked ToolError, never in this
    per-call structured data (see mcp/diagnostics.py's module docstring and
    api/permissions.py's canned status_detail sentences, which this reuses)."""
    principal_cache, directory = static_principal_cache
    directory.groups_by_subject["user-123"] = []
    prime_jwks([sig_key.jwk])
    token = sig_key.sign(make_claims())

    registry = ServiceRegistry()
    registry.register(
        ServiceSpec(
            name="needs-link",
            prefix="needslink",
            # .invalid (RFC 2606) instead of .cluster.local: macOS routes
            # .local lookups through mDNS with a ~5s timeout, which this test
            # paid twice (~10s) when the aggregator dialed the backend; an
            # NXDOMAIN in .invalid fails in milliseconds and is still an
            # unreachable cluster-internal-looking address.
            url="http://internal.svc.cluster.invalid/mcp",
            transport="http",
            required_permission="__none__",
            auth_type="bearer",
        )
    )
    credential_registry = CredentialRegistry()
    credential_registry.register("needs-link", _FakeIdentityProvider(linked=False))
    identity_providers = {"idp": _FakeIdentityProvider(linked=False)}
    identity_provider_configs = {"idp": _idp_config("Some IdP", "Some access")}
    target_to_alias = {"needs-link": "idp"}

    mcp = build_aggregator(
        registry,
        settings,
        EntitlementPolicy(),
        credential_registry,
        principal_cache=principal_cache,
        identity_providers=identity_providers,
        identity_provider_configs=identity_provider_configs,
        target_to_alias=target_to_alias,
    )

    async with run_aggregator_async(mcp, path="/mcp") as agg_url:
        transport = StreamableHttpTransport(
            agg_url, headers={"Authorization": f"Bearer {token}"}
        )
        async with Client(transport) as client:
            whoami = await client.call_tool(WHOAMI_TOOL_NAME, {})
            identities = await client.call_tool(LIST_IDENTITIES_TOOL_NAME, {})
            servers = await client.call_tool(LIST_MCP_SERVERS_TOOL_NAME, {})

    for result in (whoami, identities, servers):
        blob = json.dumps(result.structured_content)
        assert "http://" not in blob
        assert "https://" not in blob


# ---------------------------------------------------------------------------
# af_usage -- the caller's own usage summary through the MCP surface, the
# same data GET /v1/usage serves (both are thin wrappers over
# usage/summary.py's build_usage_summary). Seeded through the process-wide
# usage store (init_usage_store), which is what the tool reads at call time
# -- the aggregator harness runs in-process, so the module-level store the
# app lifespan would install is visible to the tool closure here too.
# ---------------------------------------------------------------------------


@pytest.fixture
async def usage_store(settings: Any) -> AsyncIterator[UsageStore]:
    """Install (and tear down) the process-wide in-memory usage store, as app.py's lifespan would."""
    store = await init_usage_store(settings)
    yield store
    await aclose_usage_store()


def _usage_record(**overrides: Any) -> AuditRecord:
    fields: dict[str, Any] = {
        "principal_sub": "user-123",
        "principal_uid": 1000,
        "permission": "read_data",
        "target": "rucio",
        "action": "rucio_list_dids",
        "action_type": "read",
        "args_summary": "scope=...",
        "timestamp": time.time(),
        "request_id": "req-1",
        "mcp_service": "rucio",
        "outcome": "success",
        "duration_ms": 10.0,
        "result_bytes": 100,
        "result_tokens_est": 1000,
    }
    fields.update(overrides)
    return AuditRecord(**fields)


async def _call_af_usage(
    settings: Any, principal_cache: Any, token: str, args: dict[str, Any]
) -> Any:
    """Round-trip one af_usage call through a real aggregator (the same harness the other af_* tests use)."""
    mcp = build_aggregator(
        ServiceRegistry(),
        settings,
        EntitlementPolicy(),
        CredentialRegistry(),
        principal_cache=principal_cache,
    )
    async with run_aggregator_async(mcp, path="/mcp") as agg_url:
        transport = StreamableHttpTransport(
            agg_url, headers={"Authorization": f"Bearer {token}"}
        )
        async with Client(transport) as client:
            return await client.call_tool(USAGE_TOOL_NAME, args)


async def test_af_usage_returns_only_the_callers_usage(
    settings: Any,
    sig_key: Any,
    prime_jwks: Any,
    static_principal_cache: Any,
    usage_store: UsageStore,
) -> None:
    """Seed two subjects; the caller sees only their own aggregates -- there
    is no parameter that reaches anyone else's (same isolation contract as
    GET /v1/usage, proven through the MCP surface)."""
    principal_cache, directory = static_principal_cache
    directory.groups_by_subject["user-123"] = []
    prime_jwks([sig_key.jwk])
    token = sig_key.sign(make_claims())

    await usage_store.record(_usage_record())
    await usage_store.record(
        _usage_record(outcome="error", result_bytes=10, result_tokens_est=None)
    )
    await usage_store.record(
        _usage_record(principal_sub="someone-else", result_tokens_est=7)
    )

    result = await _call_af_usage(settings, principal_cache, token, {})

    body = result.structured_content
    assert body["subject"] == "user-123"
    assert body["window_days"] == 30
    assert body["cost_model"] == settings.cost_reference_model
    expected_cost = float(
        calculate_cost_by_tokens(
            1000, settings.cost_reference_model, token_type="input"
        )
    )
    assert body["totals"]["calls"] == 2
    assert body["totals"]["errors"] == 1
    # someone-else's 7 tokens must never leak into user-123's summary.
    assert body["totals"]["result_tokens_est"] == 1000
    assert body["totals"]["estimated_cost_usd"] == pytest.approx(expected_cost)
    assert [s["service"] for s in body["by_service"]] == ["rucio"]
    assert body["by_service"][0]["calls"] == 2
    assert body["by_service"][0]["errors"] == 1
    assert len(body["by_day"]) == 1
    assert body["by_day"][0]["calls"] == 2


async def test_af_usage_days_and_model_parameters(
    settings: Any,
    sig_key: Any,
    prime_jwks: Any,
    static_principal_cache: Any,
    usage_store: UsageStore,
) -> None:
    """days narrows the trailing window; model reprices it -- the same
    semantics as GET /v1/usage's query parameters."""
    principal_cache, directory = static_principal_cache
    directory.groups_by_subject["user-123"] = []
    prime_jwks([sig_key.jwk])
    token = sig_key.sign(make_claims())

    await usage_store.record(_usage_record())
    await usage_store.record(
        _usage_record(timestamp=time.time() - 10 * 86400, result_tokens_est=500)
    )

    narrow = await _call_af_usage(settings, principal_cache, token, {"days": 7})
    assert narrow.structured_content["window_days"] == 7
    assert narrow.structured_content["totals"]["calls"] == 1
    assert narrow.structured_content["totals"]["result_tokens_est"] == 1000

    # Any second Claude key from the bundled table works; pinned so a
    # tokencost upgrade that drops it fails loudly (same reasoning as
    # test_usage_api.py's PINNED_MODEL).
    other = "claude-3-5-sonnet-20241022"
    repriced = await _call_af_usage(
        settings, principal_cache, token, {"days": 30, "model": other}
    )
    body = repriced.structured_content
    assert body["cost_model"] == other
    # af_usage now meters itself (issue #240): the narrow call above shows up
    # here as one af-mcp call -- an accepted, deliberately visible side
    # effect of routing af_* through the normal audit/metering path. The
    # seeded rucio rows still price exactly as before.
    per_service = {s["service"]: s for s in body["by_service"]}
    assert per_service["rucio"]["calls"] == 2
    assert per_service["gateway_service"]["calls"] == 1
    assert body["totals"]["calls"] == 3
    assert per_service["rucio"]["estimated_cost_usd"] == pytest.approx(
        float(calculate_cost_by_tokens(1500, other, token_type="input"))
    )


async def test_af_usage_unknown_model_raises_tool_error(
    settings: Any,
    sig_key: Any,
    prime_jwks: Any,
    static_principal_cache: Any,
    usage_store: UsageStore,
) -> None:
    """An unknown price-table key is a clean ToolError naming the model --
    mirroring the endpoint's 422 -- and must not enumerate the table."""
    principal_cache, directory = static_principal_cache
    directory.groups_by_subject["user-123"] = []
    prime_jwks([sig_key.jwk])
    token = sig_key.sign(make_claims())

    with pytest.raises(ToolError) as excinfo:
        await _call_af_usage(
            settings, principal_cache, token, {"model": "not-a-real-model"}
        )

    assert "not-a-real-model" in str(excinfo.value)
    # The table has thousands of keys -- the error must not enumerate them.
    assert settings.cost_reference_model not in str(excinfo.value)


async def test_af_usage_without_installed_store_degrades_to_empty_window(
    settings: Any, sig_key: Any, prime_jwks: Any, static_principal_cache: Any
) -> None:
    """No process-wide store (outside the lifespan) means an empty window,
    never a crash -- the same degrade GET /v1/usage applies."""
    principal_cache, directory = static_principal_cache
    directory.groups_by_subject["user-123"] = []
    prime_jwks([sig_key.jwk])
    token = sig_key.sign(make_claims())

    result = await _call_af_usage(settings, principal_cache, token, {})

    body = result.structured_content
    assert body["totals"]["calls"] == 0
    assert body["by_service"] == []
    assert body["by_day"] == []
