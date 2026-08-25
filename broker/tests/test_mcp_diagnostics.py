from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import pytest
from conftest import make_claims, run_aggregator_async
from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport
from fastmcp.exceptions import ToolError

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
    WHOAMI_TOOL_NAME,
    ServiceRegistry,
    ServiceSpec,
    identity_provider_url,
)

if TYPE_CHECKING:
    from af_mcp_broker.identity import Principal

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


async def test_af_whoami_returns_subject_groups_and_capabilities(
    settings: Any, sig_key: Any, prime_jwks: Any, static_principal_cache: Any
) -> None:
    principal_cache, directory = static_principal_cache
    directory.groups_by_subject["user-123"] = ["atlas"]
    prime_jwks([sig_key.jwk])
    token = sig_key.sign(make_claims())
    policy = EntitlementPolicy(group_capabilities={"atlas": ["read_data"]})

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
    assert result.structured_content["capabilities"] == ["read_data"]


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

    rows = {row["id"]: row for row in result.structured_content["result"]}
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
    """Reuses api/capabilities.py's _service_status() (issue #123) and the
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
            required_capability="__none__",
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
            required_capability="read_data",
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
            required_capability="__none__",
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
        EntitlementPolicy(group_capabilities={"atlas": ["read_data"]}),
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

    rows = {row["name"]: row for row in result.structured_content["result"]}
    assert rows["open"]["status"] == "available"
    assert rows["open"]["prefix"] == "open"
    assert rows["open"]["credential_provider"] is None
    assert rows["gated"]["status"] == "capability_required"
    assert rows["needs-link"]["status"] == "link_required"
    assert rows["needs-link"]["credential_provider"] == "unlinked-idp"


async def test_diagnostic_tools_visible_to_principal_with_no_capabilities(
    settings: Any, sig_key: Any, prime_jwks: Any, static_principal_cache: Any
) -> None:
    """Requirement: the af_* tools must be visible regardless of entitlements
    -- a principal with zero group memberships (so zero capabilities) still
    sees all three, even while a capability-gated backend's own tools stay
    hidden (proving this isn't just "entitlement filtering is broken")."""
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
            required_capability="read_data",
            auth_type="none",
        )
    )
    policy = EntitlementPolicy(group_capabilities={"atlas": ["read_data"]})

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
    } <= names
    # The capability-gated backend's own tool is correctly still hidden --
    # proves the af_* visibility above is a deliberate bypass, not a broken
    # entitlement filter that would let everything through.
    assert not any(n.startswith("gated_") for n in names)


async def test_no_diagnostic_tool_response_contains_a_url(
    settings: Any, sig_key: Any, prime_jwks: Any, static_principal_cache: Any
) -> None:
    """Never leak: none of the three af_* tools' responses may contain a URL
    -- not a backend's internal address, not the portal's own link URL. The
    generic "go to the portal" instruction lives in the *static* tool
    description / the pre-existing not-linked ToolError, never in this
    per-call structured data (see mcp/diagnostics.py's module docstring and
    api/capabilities.py's canned status_detail sentences, which this reuses)."""
    principal_cache, directory = static_principal_cache
    directory.groups_by_subject["user-123"] = []
    prime_jwks([sig_key.jwk])
    token = sig_key.sign(make_claims())

    registry = ServiceRegistry()
    registry.register(
        ServiceSpec(
            name="needs-link",
            prefix="needslink",
            url="http://internal.svc.cluster.local/mcp",
            transport="http",
            required_capability="__none__",
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
