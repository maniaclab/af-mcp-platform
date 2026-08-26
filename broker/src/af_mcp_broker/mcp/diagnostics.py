from __future__ import annotations

import contextlib
from typing import TYPE_CHECKING, Annotated

from fastmcp.exceptions import ToolError
from fastmcp.server.dependencies import get_context
from pydantic import BaseModel, ConfigDict, Field

from af_mcp_broker.api.permissions import ServiceStatus, _service_status
from af_mcp_broker.authorization import get_principal_permissions
from af_mcp_broker.mcp.registry import (
    LINK_IDENTITY_TOOL_NAME,
    LIST_IDENTITIES_TOOL_NAME,
    LIST_MCP_SERVERS_TOOL_NAME,
    USAGE_TOOL_NAME,
    WHOAMI_TOOL_NAME,
    identity_provider_url,
)
from af_mcp_broker.usage import get_usage_store
from af_mcp_broker.usage.summary import (
    UnknownCostModelError,
    UsageResponse,
    build_usage_summary,
)

if TYPE_CHECKING:
    from fastmcp import FastMCP

    from af_mcp_broker.authorization import EntitlementPolicy
    from af_mcp_broker.config import IdentityProviderConfig, Settings
    from af_mcp_broker.credentials import CredentialProvider, CredentialRegistry
    from af_mcp_broker.identity import Principal
    from af_mcp_broker.mcp.registry import ServiceRegistry

# Broker-native diagnostic tools (issue #153), registered directly on the
# aggregator's FastMCP instance -- never as a services.yaml entry -- for two
# reasons worth keeping explicit:
#
#   1. They are needed precisely when a service is broken, so a separate
#      aggregated MCP server (itself just another service) could be the very
#      thing that is down.
#   2. They describe the broker's own in-process state (identity linkage,
#      per-service availability, the caller's own permissions) rather than
#      proxying to anything, so they need no credential and no ProxyProvider
#      at all -- calling register_diagnostic_tools() below adds them as
#      ordinary local tools, never a provider.
#
# To EntitlementMiddleware/AuthorizationMiddleware these are ordinary methods
# of the builtin af-mcp service the ServiceRegistry always carries (issue
# #240, replacing issue #153's name-based bypass): the af prefix maps to that
# entry on the normal get_by_tool_prefix path, its "__none__" permission
# keeps them visible/callable for every authenticated caller regardless of
# entitlements, and the calls are audited/metered with service=af-mcp like
# everything else. ProxyProvider still never enters the picture -- the
# builtin spec gets no provider (aggregator.py's _register_services skips
# it), so dispatch stays local to the tools registered below.
#
# Reuses rather than reimplements: af_list_mcp_servers calls api/permissions.py's
# _service_status() (issue #123's per-service status derivation, same
# "available"/"link_required"/"permission_required"/"unavailable"/
# "misconfigured" taxonomy and canned sentences /v1/catalog already returns),
# and both af_list_identities/af_list_mcp_servers read the identity<->service
# join (target_to_alias) issue #90 added for /v1/catalog's credential_provider
# field. No second status taxonomy, no second join.


class WhoamiResult(BaseModel):
    """The caller's own identity as the broker currently sees it -- af_whoami's return value."""

    model_config = ConfigDict(frozen=True)

    subject: str
    groups: list[str]
    permissions: list[str]


class DiagnosticIdentityProvider(BaseModel):
    """One configured identity provider and whether the caller has linked it -- af_list_identities' per-provider row."""

    model_config = ConfigDict(frozen=True)

    id: str
    display_name: str
    enables: str
    linked: bool


# af_list_identities/af_list_mcp_servers wrap their rows in these single-field
# models rather than returning a bare list[...] (issue #216 A.1). An MCP
# outputSchema MUST be a JSON *object* schema; FastMCP does emit one for a
# bare-list return, but only by auto-wrapping it under a synthetic ``result``
# key stamped ``x-fastmcp-wrap-result`` -- a meaningless machine name, not a
# contract a client or LLM can read. A named wrapper field (``identities`` /
# ``servers``) is the authored object schema the convention asks every tool to
# declare, and reads naturally as the tool's return value.
class ListIdentitiesResult(BaseModel):
    """The broker's configured identity providers and the caller's linkage to each -- af_list_identities' return value."""

    model_config = ConfigDict(frozen=True)

    identities: list[DiagnosticIdentityProvider]


class LinkIdentityResult(BaseModel):
    """The portal deep link for one identity provider -- af_link_identity's return value."""

    model_config = ConfigDict(frozen=True)

    id: str
    display_name: str
    url: str
    already_linked: bool


class DiagnosticMcpServer(BaseModel):
    """One configured MCP service's tool prefix, identity, and availability -- af_list_mcp_servers' per-service row."""

    model_config = ConfigDict(frozen=True)

    name: str
    display_name: str
    prefix: str
    # The identity-provider alias that powers this service's credential (see
    # api/identities.py's identity_providers / issue #90's target_to_alias
    # join), or None for a service that needs no per-user identity at all
    # (auth_type: none).
    credential_provider: str | None
    status: ServiceStatus
    status_detail: str


class ListMcpServersResult(BaseModel):
    """The broker's configured MCP services and each one's identity/availability -- af_list_mcp_servers' return value. Wraps the rows in a named field for the same reason as ListIdentitiesResult (issue #216 A.1)."""

    model_config = ConfigDict(frozen=True)

    servers: list[DiagnosticMcpServer]


async def _require_principal() -> Principal:
    """Fetch the calling Principal that IdentityMiddleware stamped onto request-scoped state, or fail closed.

    Mirrors the identical defensive check in aggregator.py's _bearer_factory
    and entitlement_mw.py/authorization_mw.py: IdentityMiddleware runs
    outermost and always sets this before any tool body runs, so a missing
    principal here means something upstream is broken, not a caller error.
    """
    ctx = get_context()
    principal = await ctx.get_state("principal")
    if principal is None:
        raise ToolError("No authenticated principal available for this tool call")
    return principal


def register_diagnostic_tools(
    mcp: FastMCP,
    registry: ServiceRegistry,
    policy: EntitlementPolicy,
    credential_registry: CredentialRegistry,
    identity_providers: dict[str, CredentialProvider],
    identity_provider_configs: dict[str, IdentityProviderConfig],
    target_to_alias: dict[str, str],
    settings: Settings,
) -> None:
    """(Re)register the af_* diagnostic tools on *mcp*, bound to the given state.

    Called from both aggregator.py's build_aggregator() and
    populate_aggregator(), mirroring _register_services()'s rebuild-from-
    scratch pattern rather than middleware's mutate-in-place one: a fresh
    populate_aggregator() call always supplies fresh registry/policy/
    credential_registry/identity provider objects rather than mutating the
    previous ones, so the tool closures below must be rebuilt to close over
    the current ones -- any previous registration is removed first so this
    is safe to call repeatedly without FastMCP logging a duplicate-tool
    warning on every lifespan entry (including every test that calls
    populate_aggregator() more than once).
    """
    for name in (
        WHOAMI_TOOL_NAME,
        LIST_IDENTITIES_TOOL_NAME,
        LIST_MCP_SERVERS_TOOL_NAME,
        LINK_IDENTITY_TOOL_NAME,
        USAGE_TOOL_NAME,
    ):
        with contextlib.suppress(KeyError):
            mcp.local_provider.remove_tool(name)

    @mcp.tool(name=WHOAMI_TOOL_NAME)
    async def _whoami() -> WhoamiResult:
        """Return the caller's own subject, groups, and effective permissions.

        Call this when a tool call fails with a permission/permission error
        (e.g. "requires permission '...'") to see exactly which groups and
        permissions the caller currently holds, so you can tell them
        whether the fix is a missing group membership or something else.
        Needs no permission of its own and never contacts a service, so it
        always answers even when every other service is down.
        """
        principal = await _require_principal()
        caps = get_principal_permissions(principal, policy)
        return WhoamiResult(
            subject=principal.subject,
            groups=sorted(principal.groups),
            permissions=sorted(caps),
        )

    @mcp.tool(name=LIST_IDENTITIES_TOOL_NAME)
    async def _list_identities() -> ListIdentitiesResult:
        """List the broker's configured identity providers and whether the caller has linked each one.

        Call this when a tool call fails with a "not linked" error, or when
        a service's tools are missing or non-functional and you need to
        find out which identity provider it depends on and whether this
        caller has connected it yet (link it from the portal's Identities
        page). Needs no permission of its own and never contacts a service.
        """
        principal = await _require_principal()
        providers: list[DiagnosticIdentityProvider] = []
        for alias, provider in identity_providers.items():
            cfg = identity_provider_configs[alias]
            providers.append(
                DiagnosticIdentityProvider(
                    id=alias,
                    display_name=cfg.display_name,
                    enables=cfg.enables,
                    linked=await provider.is_linked(principal),
                )
            )
        return ListIdentitiesResult(identities=providers)

    @mcp.tool(name=LINK_IDENTITY_TOOL_NAME)
    async def _link_identity(provider: str) -> LinkIdentityResult:
        """Return the portal URL to link (or re-link) one identity provider.

        Call this after a tool call fails with a "not linked" error, or
        after `af_list_identities` shows `linked: false` for a provider a
        service needs, to get the exact link to hand the user. `provider`
        is the identity-provider alias -- the same `id` field
        `af_list_identities` returns. Calling this for an already-linked
        provider is fine too (e.g. to get the link again so the user can
        re-link and rotate a passphrase); `already_linked` just reports the
        current state, it never blocks the call.
        """
        principal = await _require_principal()
        if provider not in identity_providers:
            valid = sorted(identity_providers)
            raise ToolError(
                f"Unknown identity provider {provider!r}. Valid providers: "
                f"{valid}. Call `{LIST_IDENTITIES_TOOL_NAME}` first to see "
                "the configured providers and their aliases."
            )
        cfg = identity_provider_configs[provider]
        return LinkIdentityResult(
            id=provider,
            display_name=cfg.display_name,
            url=identity_provider_url(settings, provider),
            already_linked=await identity_providers[provider].is_linked(principal),
        )

    @mcp.tool(name=USAGE_TOOL_NAME)
    async def _usage(
        days: Annotated[int, Field(ge=1, le=365)] = 30,
        model: str | None = None,
    ) -> UsageResponse:
        """Return the caller's own tool-call usage over a trailing window.

        The same data `GET /v1/usage` serves: window totals plus
        per-service and per-day aggregates of the caller's tool calls (and
        nobody else's -- the subject comes from the authenticated
        principal, never a parameter). Honesty caveats to relay to the
        user: token counts are a tiktoken (o200k) ESTIMATE of the
        tool-result text injected into the LLM client's context -- not
        provider-reported usage, and not the user's full LLM spend -- and
        `estimated_cost_usd` is that estimate priced at the chosen model's
        *input* rate. `days` is the trailing window in UTC calendar days
        (1..365, today inclusive); `model` picks the tokencost price-table
        key to price at (default: the broker's configured reference
        model). Needs no permission of its own and never contacts a
        service.
        """
        principal = await _require_principal()
        # The process-wide store app.py's lifespan installed -- None outside
        # the lifespan, which build_usage_summary degrades to an empty
        # window (mirroring GET /v1/usage's own bare-router behavior).
        try:
            return await build_usage_summary(
                get_usage_store(),
                principal.subject,
                days,
                model,
                settings.cost_reference_model,
            )
        except UnknownCostModelError as exc:
            # Mirror the endpoint's 422 semantics: same message, tool-error
            # shape (never enumerates the table's thousands of keys).
            raise ToolError(str(exc)) from exc

    @mcp.tool(name=LIST_MCP_SERVERS_TOOL_NAME)
    async def _list_mcp_servers() -> ListMcpServersResult:
        """List every configured MCP service, the identity that powers it, and whether it's currently available to the caller.

        Call this first when an expected tool is missing from tools/list,
        or a tool call fails for a reason that isn't obviously a bad
        argument, to see each service's tool-name prefix, which identity
        provider (if any) it needs, and a short reason if it's unavailable
        (linking required, permission required, temporarily down, or
        misconfigured). Needs no permission of its own and never contacts a
        service -- the status reported is the broker's own last-known state,
        the same data the portal's Catalog page shows.
        """
        principal = await _require_principal()
        caps = get_principal_permissions(principal, policy)
        servers: list[DiagnosticMcpServer] = []
        for spec in registry.all_services():
            status, status_detail, _correlation_id = await _service_status(
                spec, principal, caps, credential_registry, registry
            )
            servers.append(
                DiagnosticMcpServer(
                    name=spec.name,
                    display_name=spec.display_name or spec.name,
                    prefix=spec.prefix,
                    credential_provider=target_to_alias.get(spec.name),
                    status=status,
                    status_detail=status_detail,
                )
            )
        return ListMcpServersResult(servers=servers)
