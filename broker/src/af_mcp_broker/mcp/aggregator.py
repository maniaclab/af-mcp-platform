from __future__ import annotations

# Aggregator entry point — builds the FastMCP application that proxies tool
# calls to downstream MCP services after the broker has validated identity,
# applied entitlement filtering, checked authorization, and (for
# auth_type="bearer" services) minted and injected a per-user credential.
#
# app.py's lifespan builds the aggregator once SERVICES_FILE/POLICY_FILE/the
# credential subsystem have been loaded. The client_factory below deliberately
# never forwards the caller's inbound Authorization header to a service; see
# its docstring.
import asyncio
import time
from typing import TYPE_CHECKING, Any

import structlog
from fastapi import HTTPException
from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from fastmcp.server.dependencies import get_context
from fastmcp.server.elicitation import AcceptedElicitation
from fastmcp.server.providers.proxy import (
    ClientFactoryT,
    ProxyProvider,
    ProxyTool,
)
from mcp.types import (
    ClientCapabilities,
    ElicitationCapability,
)
from mcp.types import Tool as McpTool
from starlette.middleware import Middleware

from af_mcp_broker import metrics
from af_mcp_broker.authorization import get_principal_permissions
from af_mcp_broker.backend_client import (
    bearer_injection,
    build_client,
    classify_failure,
    require_linked_to_list,
    require_signing_issuer,
    resolve_list_time_headers,
)
from af_mcp_broker.backend_errors import (
    ListDeadlineExceededError,
    NotEntitledForListingError,
    NotLinkedForListingError,
)
from af_mcp_broker.credentials.errors import NeedsUnlockError
from af_mcp_broker.errors import require
from af_mcp_broker.mcp.diagnostics import register_diagnostic_tools
from af_mcp_broker.mcp.instructions import compose_agent_instructions
from af_mcp_broker.mcp.middleware.authorization_mw import AuthorizationMiddleware
from af_mcp_broker.mcp.middleware.entitlement_mw import EntitlementMiddleware
from af_mcp_broker.mcp.middleware.identity_mw import (
    AsgiAuthMiddleware,
    IdentityMiddleware,
)
from af_mcp_broker.mcp.middleware.maintenance_mw import AsgiMaintenanceMiddleware
from af_mcp_broker.service_registry import (
    LINK_IDENTITY_TOOL_NAME,
    LIST_IDENTITIES_TOOL_NAME,
    LIST_MCP_SERVERS_TOOL_NAME,
    ToolRouting,
    identity_provider_url,
)
from af_mcp_broker.service_status import RELINK_DETAIL

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Sequence

    from fastmcp import Context
    from fastmcp.client import Client
    from fastmcp.prompts import Prompt
    from fastmcp.resources import Resource, ResourceTemplate
    from fastmcp.tools.base import Tool
    from fastmcp.utilities.versions import VersionSpec

    from af_mcp_broker.authorization import EntitlementPolicy
    from af_mcp_broker.config import IdentityProviderConfig, Settings
    from af_mcp_broker.credentials import (
        CredentialProvider,
        CredentialRegistry,
    )
    from af_mcp_broker.credentials.broker_issued import BrokerTokenIssuer
    from af_mcp_broker.credmon.guidance import JobCredentialGuide
    from af_mcp_broker.lint_observations import LintObservationStore
    from af_mcp_broker.maintenance import MaintenanceModeStore
    from af_mcp_broker.principal import Principal
    from af_mcp_broker.principal_cache import PrincipalCache
    from af_mcp_broker.service_registry import ServiceRegistry, ServiceSpec
    from af_mcp_broker.shared_state import SharedState
    from af_mcp_broker.token_registry import TokenRegistryBackend
    from af_mcp_broker.usage import UsageStore

logger = structlog.get_logger(__name__)


async def _classify_list_failure(exc: Exception, service_name: str) -> tuple[str, str]:
    """Classify a ``_list_tools()`` failure for structured logging.

    Consults the per-service request-scoped state ``_bearer_factory``'s
    list-time branch records (keyed per service since one ``tools/list``
    request fans out to every service concurrently), then applies
    ``classify_failure``'s shared decision core. A ``NotLinkedForListingError``
    (the client factory turned the caller away before any request) is
    ``"not_linked"`` outright, or ``"unauthorized"`` -- the stored credential
    was rejected -- when it says ``rejected``.
    """
    if isinstance(exc, NotEntitledForListingError):
        return "not_entitled", str(exc)
    if isinstance(exc, NotLinkedForListingError):
        return ("unauthorized" if exc.rejected else "not_linked"), str(exc)
    if isinstance(exc, ListDeadlineExceededError):
        return "unavailable", str(exc)
    ctx = get_context()
    status = await ctx.get_state(f"__list_credential_status__:{service_name}")
    injected, skip_reason = status if status is not None else (False, None)
    return classify_failure(exc, injected=injected, skip_reason=skip_reason), str(exc)


def _might_be_entitled(
    principal: Principal, spec: ServiceSpec, policy: EntitlementPolicy
) -> bool:
    """Return whether *principal* may list *spec*'s tools at all: whether it holds any permission *spec* can require.

    Runs for a caller with no specific tool_name in hand yet (a tools/list
    request, or a stale-cache _get_tool() refresh), so it is a whole-service
    check. It is not the security boundary: EntitlementMiddleware hides the
    service's tools from a caller with no chance of using any of them, and a
    caller who slips past this and calls one anyway is still stopped by
    AuthorizationMiddleware's real per-tool check. It decides only whether a
    listing is worth attempting: ``_require_entitled_list_principal`` skips
    the service for a caller it rejects, before any credential is minted or
    request sent. True if *spec* has no permission gate at all, or the caller
    holds at least one of the permissions it can require across any of its
    tools.
    """
    required = spec.all_required_permissions()
    return not required or bool(required & get_principal_permissions(principal, policy))


async def _require_entitled_list_principal(
    ctx: Context, spec: ServiceSpec, policy: EntitlementPolicy
) -> Principal:
    """Return the caller's principal for a list-time connection to *spec*, or raise before any credential is minted or request is sent.

    Shared by every credentialed client factory so the rule lives in one
    place. A caller holding none of the permissions *spec* can require is
    skipped with ``NotEntitledForListingError``: EntitlementMiddleware hides
    the service's tools from them, so a listing could only be discarded --
    and a bare request would make a backend that needs a credential answer
    401, logged as a failure. IdentityMiddleware sets the principal on every
    authenticated /mcp request, so its absence is a broker bug, not a caller
    state.
    """
    principal = await ctx.get_state("principal")
    if principal is None:
        msg = (
            f"Cannot list tools for service '{spec.name}': no authenticated "
            "principal on the request context."
        )
        raise RuntimeError(msg)
    if not _might_be_entitled(principal, spec, policy):
        msg = (
            f"Service '{spec.name}' lists its tools only for callers holding "
            "one of its required permissions."
        )
        raise NotEntitledForListingError(msg)
    return principal


async def _identity_token_list_client(
    ctx: Context,
    spec: ServiceSpec,
    credential_registry: CredentialRegistry,
    policy: EntitlementPolicy,
    issuer: BrokerTokenIssuer,
) -> Client:
    """List-time client for an x509/krb5/servicex service: an identity header for a caller who has linked the credential the backend will redeem.

    Minting is a local signature, so there is no network to fail. An
    unentitled caller (``_require_entitled_list_principal``) or an unlinked
    one (``require_linked_to_list``) raises before anything is minted or any
    request is made.
    """
    principal = await _require_entitled_list_principal(ctx, spec, policy)
    await require_linked_to_list(spec, credential_registry, principal)
    token, _ = issuer.mint(principal.subject, spec.effective_audience)
    await ctx.set_state(
        f"__list_credential_status__:{spec.name}",
        (True, None),
        serializable=False,
    )
    return build_client(spec, headers={"Authorization": f"Bearer {token}"})


def _identity_link_url(settings: Settings, alias: str | None) -> str:
    """Build the portal deep link for linking one identity provider.

    Shared by ``_not_linked_error`` (the plain-text hint) and
    ``_require_linked`` (the elicitation message below) so the URL can never
    drift between the two. Falls back to the bare Identities page when
    *alias* is ``None`` -- shouldn't happen for a service that resolved a
    credential provider at all, but keeps this defensive rather than raising
    a second, more confusing error over a missing join entry.
    """
    if alias is None:
        portal = settings.portal_url.rstrip("/")
        return f"{portal}/identities"
    return identity_provider_url(settings, alias)


def _identity_display_name(
    provider: CredentialProvider,
    alias: str | None,
    identity_provider_configs: dict[str, IdentityProviderConfig] | None,
) -> str:
    """Best human-readable name for the identity a not-linked caller needs to connect.

    Prefers the configured ``IdentityProviderConfig.display_name`` (the same
    text ``af_list_identities``/``af_link_identity`` show), keyed by *alias*
    (``target_to_alias.get(spec.name)``); falls back to the credential
    provider's class name -- the same fallback ``_not_linked_error`` already
    used -- when no alias is known, no config was supplied, or the
    configured provider left ``display_name`` blank.
    """
    if alias is not None and identity_provider_configs is not None:
        cfg = identity_provider_configs.get(alias)
        if cfg is not None and cfg.display_name:
            return cfg.display_name
    return type(provider).__name__


def _not_linked_error(
    provider: CredentialProvider,
    settings: Settings,
    alias: str | None,
    *,
    rejected: bool = False,
) -> ToolError:
    """Build the "identity not linked" ``ToolError``, or, when *rejected*, the "credential rejected, re-link" one.

    Shared by ``_bearer_factory`` and ``_x509_factory`` (via
    ``_require_linked``) so the message text -- and the portal deep link it
    names -- can never drift between the two ``auth_type`` branches (stage 1
    of the elicitation/link-identity design: today's LLM clients already
    relay a URL from a tool error reliably, so this is deliberately plain
    text). Stage 2a (``_require_linked`` below) now tries a real MCP
    elicitation first and falls back to this exact error when that isn't
    possible or the caller doesn't complete it.

    *alias* is the identity-provider alias servicing this service
    (``target_to_alias.get(spec.name)``), used to deep-link straight to that
    provider's card via ``_identity_link_url`` -- the same URL
    ``af_link_identity`` (mcp/diagnostics.py) returns. Falls back to the bare
    Identities page (and omits the ``provider=`` argument from the
    ``af_link_identity`` hint) when no alias is known.

    *rejected* is the provider's ``is_rejected()``: the caller did link, and a
    backend rejected the stored credential, so the message is the catalog's
    re-link sentence (``RELINK_DETAIL``) plus the same link and hint.
    """
    url = _identity_link_url(settings, alias)
    if alias is None:
        link_hint = f"`{LINK_IDENTITY_TOOL_NAME}`"
    else:
        link_hint = f'`{LINK_IDENTITY_TOOL_NAME}` (provider="{alias}")'
    if rejected:
        return ToolError(
            f"{RELINK_DETAIL} Visit {url} to re-link it, or call {link_hint} "
            "to get this link."
        )
    return ToolError(
        f"{type(provider).__name__} not linked. Visit {url} to connect it, "
        f"or call {link_hint} to get this link. Call "
        f"`{LIST_IDENTITIES_TOOL_NAME}` to see which identity provider this "
        f"service needs, or `{LIST_MCP_SERVERS_TOOL_NAME}` for this "
        "service's current status."
    )


def _client_supports_elicitation(ctx: Context) -> bool:
    """Best-effort check of whether the connected client declared elicitation support.

    Mirrors the ``ClientCapabilities``-based introspection fastmcp's own
    sampling code uses (``fastmcp.server.sampling.run.determine_handler_mode``)
    to decide whether to even attempt a client round trip:
    ``ctx.session.check_client_capability(...)`` inspects the
    ``ClientCapabilities`` the client declared at MCP initialize time, so a
    client that never declared elicitation support can be skipped before
    ever calling ``ctx.elicit()`` -- a round trip such a client would just
    error on anyway. Note this only confirms the client declared *some*
    elicitation mode: the MCP spec's ``ElicitationCapability`` further
    distinguishes "form" vs "url" mode, and ``check_client_capability``
    (as pinned, fastmcp 3.4.4) does not drill into that distinction -- a
    client that declared only URL-mode support (issue #194, not implemented
    here) still passes this check. ``_require_linked``'s own ``except``
    around the ``elicit()`` call is what actually catches that case, so this
    function is purely an optimization to skip a doomed round trip, never
    the sole safety net.

    Returns True (attempt elicitation) if the session or its client params
    aren't available for any reason, for the same "never the sole safety
    net" reason.
    """
    try:
        return ctx.session.check_client_capability(
            ClientCapabilities(elicitation=ElicitationCapability())
        )
    except Exception:  # noqa: BLE001 -- purely an optimization, see docstring
        return True


# The two elicitation response options _require_linked offers a not-linked
# caller, kept as module constants so tests can assert against the exact
# strings without duplicating them.
_ELICIT_RETRY_OPTION = "I've linked it — try again"
_ELICIT_CANCEL_OPTION = "Cancel"


async def _require_linked(
    provider: CredentialProvider,
    principal: Principal,
    spec: ServiceSpec,
    settings: Settings,
    target_to_alias: dict[str, str] | None,
    identity_provider_configs: dict[str, IdentityProviderConfig] | None = None,
) -> None:
    """Gate a call on *principal* having linked *provider*, trying a real elicitation before giving up.

    Shared by ``_bearer_factory`` and ``_x509_factory`` -- stage 2a of the
    elicitation/link-identity design (following stage 1's plain-text
    ``_not_linked_error``). Returns normally (proceed) if already linked --
    the common case, and the only path that doesn't need a request context
    at all. Otherwise, tries one form-mode ``ctx.elicit()`` round trip
    asking the caller to link then retry, before falling back to stage 1's
    plain ``ToolError``. There is no URL-mode elicitation in the pinned
    fastmcp version (3.4.4) -- no way to have the client auto-open the
    portal link for the caller -- so this is deliberately form-mode only;
    true URL-mode elicitation is tracked separately (issue #194).

    Never surfaces anything other than stage 1's ``ToolError`` or the
    distinct "still not linked" one below: a client that doesn't declare
    elicitation support (``_client_supports_elicitation``), or whose
    ``elicit()`` call raises for any reason (declined transport, protocol
    mismatch, anything), falls back to exactly stage 1's error rather than
    a worse or different one. Exactly one elicitation attempt is made --
    a caller who accepts but is still not linked afterward is told so, not
    re-elicited.
    """
    if await provider.is_linked(principal):
        return

    alias = (target_to_alias or {}).get(spec.name)
    rejected = await provider.is_rejected(principal)
    not_linked = _not_linked_error(provider, settings, alias, rejected=rejected)

    ctx = get_context()
    if not _client_supports_elicitation(ctx):
        raise not_linked

    display_name = _identity_display_name(provider, alias, identity_provider_configs)
    url = _identity_link_url(settings, alias)
    try:
        result = await ctx.elicit(
            f"Your linked {display_name} credential was rejected. Visit {url} "
            "to re-link it, then let me know when you're done."
            if rejected
            else f"You need to link {display_name} before I can do this. Visit "
            f"{url} to link it, then let me know when you're done.",
            [_ELICIT_RETRY_OPTION, _ELICIT_CANCEL_OPTION],  # type: ignore[arg-type]
            # mypy 2.3.0 misresolves fastmcp 3.4.4's Context.elicit overloads
            # for a plain list[str] (it picks the response_type=None-only
            # overload regardless of the argument's actual type -- reproduced
            # with a minimal repro outside this codebase, so this is a
            # library/mypy interaction, not a real type error); the select
            # (list[str]) overload's runtime behavior is exercised directly
            # by this module's tests.
        )
    except Exception:  # noqa: BLE001 -- fall back to stage 1, see docstring
        raise not_linked from None

    if (
        not isinstance(result, AcceptedElicitation)
        or result.data != _ELICIT_RETRY_OPTION
    ):
        # Declined, cancelled, or (defensively) accepted with the "Cancel"
        # option -- one attempt only, no re-elicit loop.
        raise not_linked

    if await provider.is_linked(principal):
        return

    if rejected:
        raise ToolError(
            f"{display_name} is still rejected. Visit {url} to re-link it, then "
            "try again."
        )
    raise ToolError(
        f"{display_name} still not linked. Visit {url} to connect it, then try again."
    )


def _make_client_factory(
    spec: ServiceSpec,
    credential_registry: CredentialRegistry,
    settings: Settings,
    policy: EntitlementPolicy,
    *,
    broker_token_issuer: BrokerTokenIssuer | None = None,
    target_to_alias: dict[str, str] | None = None,
    identity_provider_configs: dict[str, IdentityProviderConfig] | None = None,
) -> ClientFactoryT:
    """Build a ProxyProvider client_factory for one service.

    Security property: constructing a plain ``Client`` around an explicit
    transport object never sets ``forward_incoming_headers`` -- it stays
    unset (``Client._transport_options is None``), so ``TransportOptions``'s
    own default of False applies. fastmcp's ``ProxyClient`` convenience
    wrapper unconditionally sets that flag to True for HTTP transports
    (intended for proxies that should forward the caller's credentials), so
    it is deliberately not used here: the broker's own AF-internal bearer
    token must never reach a service regardless. The ``headers`` passed to
    the transport below come exclusively from a credential this factory
    itself minted -- never copied from the inbound request -- so passing
    them does not reintroduce that forwarding behavior.

    Trace-context propagation extends the same invariant, for the trace keys
    specifically: no inbound HTTP header -- ``traceparent`` included -- is
    ever forwarded to a service. The ``Client`` built here (fastmcp's
    ``Client.call_tool``) injects the broker's own then-current span context
    into the outbound MCP request's ``_meta`` (SEP-414), which is
    broker-generated by construction: the inbound ``_meta`` traceparent is
    only ever parsed as a remote parent of AuthorizationMiddleware's span
    (see mcp/middleware/authorization_mw.py). Confirmed still true on
    fastmcp v4: ``telemetry.inject_trace_context`` spreads its own
    ``trace_meta`` keys *after* whatever meta it was given
    (``{**meta, **trace_meta}``), unconditionally overwriting any
    ``traceparent``/``tracestate`` a caller's own ``_meta`` supplied --
    except when telemetry is off (``FASTMCP_TELEMETRY_MODE=off``), where
    ``inject_trace_context`` is a bare passthrough and a caller-supplied
    traceparent would cross unmodified; low-stakes (nothing consumes it on
    the backend side without telemetry enabled there too), but worth
    knowing if telemetry is ever toggled off selectively.

    **Correction from fastmcp v4: non-trace ``_meta`` keys are no longer
    universally blocked.** ``ProxyTool.run()``'s own
    ``_forwardable_request_meta`` (``server/providers/proxy.py``) now
    forwards the inbound request's progress-token, task, and
    application-metadata ``_meta`` keys verbatim to the backend -- only the
    three connection-owned keys (protocol version, client info, client
    capabilities) are stripped. This is fastmcp's own proxy-dispatch code
    (``ProxyTool.run()``/``_relay_read_resource()``), a layer above the
    ``Client``/``client_factory`` this function builds, and applies
    regardless of ``auth_type``. Not a security regression for anything
    this module gates (no credential or header data rides in application
    ``_meta``), but it means a caller can now pass arbitrary ``_meta``
    through to a backend that reads it, which was not previously possible.

    ``auth_type`` selects the branch:
      - "none": no credential is resolved at all; the service needs no
        per-user credential (e.g. it authorizes via a platform k8s SA).
      - "x509": inject an AF Broker Identity Token (aud = this service);
        the service redeems the caller's VOMS proxy server-side via
        POST /v1/credentials/x509/redeem (issue #112's "service calls
        back" wire format). The proxy PEM itself never transits the
        aggregator. Gated on ``credential_registry``'s linkage the same way
        as "bearer" below (see ``_not_linked_error``) before any token is
        minted -- ``target_to_alias`` supplies the alias used to build that
        error's portal deep link.
      - "krb5": identical "mint and inject, let the backend redeem
        separately" shape as "x509" above, just against
        POST /v1/credentials/krb5/redeem instead -- no krb5 ccache ever
        transits the aggregator either. No ``services.yaml`` entry declares
        this ``auth_type`` yet (plumbing only, per the krb5-credentials-
        redeem plan).
      - "bearer" (default): resolves the caller's Principal from the
        current request context, mints a credential in-process the same
        way ``POST /v1/credential`` does (api/credentials.py's
        ``issue_credential``), and injects it as ``Authorization: Bearer``.
        This branch is async because minting a credential requires
        awaiting the credential provider; ``ProxyTool._get_client()``
        already awaits the factory's return value when it is awaitable.

    The "x509", "krb5", and "bearer" branches all key off ``authorized_call_target``
    (request-scoped state set by ``AuthorizationMiddleware`` right before it
    calls ``call_next``) to tell an authorized tools/call targeting this
    service apart from any other invocation reaching this factory --
    ``ProxyTool.run()`` always hits the former; ``ProxyProvider._list_tools()``
    (which answers a ``tools/list`` request, and which ``_get_tool()`` also
    calls on a stale-cache lookup) hits the latter, and the two are otherwise
    indistinguishable from inside this factory.

    For "x509" (and "krb5" and "servicex", identically), absent the
    authorized-call signal the factory attaches an identity header for a
    caller who has linked the credential, and raises ``NotLinkedForListingError``
    for one who has not -- before minting anything or contacting the
    backend, so that service simply contributes no tools to that caller's
    list. A caller holding none of the service's permissions
    (``_might_be_entitled``) is skipped the same way, with
    ``NotEntitledForListingError``, for every auth type below.

    For "bearer", that same "wasteful and wrong" framing used to justify
    skipping credential resolution entirely during a listing -- until issue
    #121: a service whose MCP endpoint itself requires a bearer token to
    respond to ``tools/list`` (rucio-mcp) then 401s on every listing and
    becomes permanently invisible to every caller, with no user-facing
    error at all. Resolved by attempting a *best-effort* mint during a
    listing too, gated on the caller holding at least one of the service's
    required permissions (``_might_be_entitled``, a coarser whole-service
    version of the per-tool check ``AuthorizationMiddleware`` uses) -- the
    in-process ``CredentialCache`` already makes repeat mints for the same
    ``(uid, target)`` cheap, so
    "wasteful" no longer applies. A caller who has not linked the credential
    gets no listing at all, exactly like x509/krb5/servicex above: the
    factory raises ``NotLinkedForListingError`` before minting anything or
    contacting the backend (``_ObservableProxyProvider._get_tool`` then
    resolves a direct call to one of its tools to a stand-in, so the caller
    still gets the not-linked error). Any other failure to mint (no provider
    configured, a mint error) does NOT prevent the connection
    attempt, unlike the authorized tools/call path below -- see
    ``resolve_list_time_headers``'s docstring for why raising there instead
    would reintroduce a worse bug (a permanently unpopulated schema cache
    poisoning a *different* caller's later, genuinely authorized tools/call).
    ``_ObservableProxyProvider`` (below) classifies and structured-logs
    whatever the resulting connection attempt produces, then lets it
    propagate so the existing warn-and-skip behavior drops the service from
    the list exactly like a dead service would.

    This does mean a listing fetched with one user's credential can leave
    ``ProxyProvider``'s ``_tools_cache`` (used by ``_get_tool()`` for
    individual by-name lookups, e.g. during a tools/call's tool resolution)
    holding a schema fetched under a different principal than the one who
    next triggers a stale-cache refresh. Harmless for tool *schemas*
    (name/description/parameters) that aren't user-specific -- true for
    rucio-mcp, one ``--read-only`` tool set per site -- since each
    ``ProxyTool`` only carries a reference back to this same
    ``client_factory`` (which mints fresh per call) rather than a baked-in
    credential. A service whose tool list genuinely does personalize per
    caller should set ``ServiceSpec.tools_cache_ttl: 0`` to disable that
    cache outright -- ``_ObservableProxyProvider``'s own per-(subject,
    service) ``tools/list`` cache (issue #320) honors the same knob, so a 0
    there disables both.
    """
    if spec.auth_type == "none":

        def _none_factory() -> Client:
            return build_client(spec)

        return _none_factory

    if spec.auth_type == "x509":
        issuer = require_signing_issuer(spec, broker_token_issuer)

        async def _x509_factory() -> Client:
            ctx = get_context()
            if await ctx.get_state("authorized_call_target") != spec.name:
                return await _identity_token_list_client(
                    ctx, spec, credential_registry, policy, issuer
                )

            principal = await ctx.get_state("principal")
            if principal is None:
                raise ToolError(
                    "No authenticated principal available for this tool call"
                )
            try:
                provider = await credential_registry.resolve(spec.name)
            except KeyError as exc:
                raise ToolError(str(exc)) from exc

            # Same linkage gate _bearer_factory applies BEFORE minting --
            # without it an unlinked caller got a broker identity token
            # unconditionally, and the failure only ever surfaced as
            # whatever generic error the service's own redeem call happened
            # to produce (e.g. a bare 404 from POST /v1/credentials/x509/
            # redeem), never a "go link your identity" message. Now also
            # tries a real elicitation before giving up -- see
            # _require_linked's docstring.
            await _require_linked(
                provider,
                principal,
                spec,
                settings,
                target_to_alias,
                identity_provider_configs,
            )

            # Identity assertion only (sub/aud): the service redeems the proxy
            # with this token; it has no use for POSIX claims.
            token, _ = issuer.mint(principal.subject, spec.effective_audience)
            return build_client(spec, headers={"Authorization": f"Bearer {token}"})

        return _x509_factory

    if spec.auth_type == "krb5":
        issuer = require_signing_issuer(spec, broker_token_issuer)

        async def _krb5_factory() -> Client:
            ctx = get_context()
            if await ctx.get_state("authorized_call_target") != spec.name:
                return await _identity_token_list_client(
                    ctx, spec, credential_registry, policy, issuer
                )

            principal = await ctx.get_state("principal")
            if principal is None:
                raise ToolError(
                    "No authenticated principal available for this tool call"
                )
            try:
                provider = await credential_registry.resolve(spec.name)
            except KeyError as exc:
                raise ToolError(str(exc)) from exc

            # Same linkage gate _bearer_factory applies BEFORE minting --
            # without it an unlinked caller got a broker identity token
            # unconditionally, and the failure only ever surfaced as
            # whatever generic error the service's own redeem call happened
            # to produce (e.g. a bare 404 from POST /v1/credentials/krb5/
            # redeem), never a "go link your identity" message. Now also
            # tries a real elicitation before giving up -- see
            # _require_linked's docstring.
            await _require_linked(
                provider,
                principal,
                spec,
                settings,
                target_to_alias,
                identity_provider_configs,
            )

            # Identity assertion only (sub/aud): the service redeems the
            # ticket with this token; it has no use for POSIX claims.
            token, _ = issuer.mint(principal.subject, spec.effective_audience)
            return build_client(spec, headers={"Authorization": f"Bearer {token}"})

        return _krb5_factory

    if spec.auth_type == "servicex":
        issuer = require_signing_issuer(spec, broker_token_issuer)

        async def _servicex_factory() -> Client:
            ctx = get_context()
            if await ctx.get_state("authorized_call_target") != spec.name:
                return await _identity_token_list_client(
                    ctx, spec, credential_registry, policy, issuer
                )

            principal = await ctx.get_state("principal")
            if principal is None:
                raise ToolError(
                    "No authenticated principal available for this tool call"
                )
            try:
                provider = await credential_registry.resolve(spec.name)
            except KeyError as exc:
                raise ToolError(str(exc)) from exc

            # Same linkage gate _bearer_factory applies BEFORE minting --
            # without it an unlinked caller got a broker identity token
            # unconditionally, and the failure only ever surfaced as
            # whatever generic error the service's own redeem call happened
            # to produce (e.g. a bare 404 from POST /v1/credentials/
            # servicex/redeem), never a "go link your identity" message. Now
            # also tries a real elicitation before giving up -- see
            # _require_linked's docstring.
            await _require_linked(
                provider,
                principal,
                spec,
                settings,
                target_to_alias,
                identity_provider_configs,
            )

            # Identity assertion only (sub/aud): the service redeems the
            # access token with this token; it has no use for POSIX claims.
            token, _ = issuer.mint(principal.subject, spec.effective_audience)
            return build_client(spec, headers={"Authorization": f"Bearer {token}"})

        return _servicex_factory

    async def _bearer_factory() -> Client:
        ctx = get_context()
        if await ctx.get_state("authorized_call_target") != spec.name:
            # Not an authorized tools/call for this service -- most commonly
            # a tools/list request (or a stale-cache _get_tool() refresh
            # triggered by one). See the docstring above for why a
            # best-effort mint is attempted here rather than skipped
            # outright, and resolve_list_time_headers for the non-fatal
            # failure handling this requires (an unlinked caller raises
            # NotLinkedForListingError instead).
            principal = await _require_entitled_list_principal(ctx, spec, policy)
            resolved = await resolve_list_time_headers(
                spec, credential_registry, principal
            )
            # Keyed per service (not a single shared key) since one
            # tools/list request fans out to every service's factory
            # concurrently -- see _classify_list_failure's use of this.
            await ctx.set_state(
                f"__list_credential_status__:{spec.name}",
                (resolved.headers is not None, resolved.skip_reason),
                serializable=False,
            )
            return build_client(
                spec,
                headers=resolved.headers or {},
                on_unauthorized=resolved.on_unauthorized,
            )

        principal = await ctx.get_state("principal")
        if principal is None:
            # identity_mw should always have set this by now; fail closed
            # rather than mint a credential for no one.
            raise ToolError("No authenticated principal available for this tool call")

        try:
            provider = await credential_registry.resolve(spec.name)
        except KeyError as exc:
            raise ToolError(str(exc)) from exc

        # Gate on linkage BEFORE issue() so an unlinked user gets a clean
        # error instead of an opaque failure surfacing from inside the
        # provider -- mirrors api/credentials.py's issue_credential() check.
        # Now also tries a real elicitation before giving up -- see
        # _require_linked's docstring.
        await _require_linked(
            provider,
            principal,
            spec,
            settings,
            target_to_alias,
            identity_provider_configs,
        )

        try:
            cred = await provider.issue(principal, spec.name)
        except NeedsUnlockError as exc:
            portal = settings.portal_url.rstrip("/")
            raise ToolError(
                f"Credential unlock required. Visit the portal: "
                f"{portal}{exc.unlock_endpoint}"
            ) from exc
        except HTTPException as exc:
            # OIDCProvider.issue() raises HTTPException directly (401 session
            # expired, 404 no stored token) rather than NeedsUnlockError -- surface
            # its detail the same way FastAPI's own handler would at /v1.
            raise ToolError(str(exc.detail)) from exc

        call_headers, on_unauthorized = bearer_injection(provider, principal, cred)
        return build_client(spec, headers=call_headers, on_unauthorized=on_unauthorized)

    return _bearer_factory


# Negative-cache TTL for a failed per-subject listing (issue #320): short
# enough that an outage recovers quickly, long enough that a client hammering
# tools/call (the SEP-2243 per-call listing path this cache originally
# existed for) doesn't re-hit a backend that just 401'd or timed out on
# every single call. Shared by all four listing kinds (tools, resources,
# resource templates, prompts) -- a failed listing is a failed listing
# regardless of which kind fetched it.
_NEGATIVE_LIST_CACHE_TTL_SECONDS: float = 30.0


class _SubjectListCacheEntry:
    """One subject's cached listing outcome against one service and one kind (tools/resources/resource templates/prompts) -- either a successful listing or a failure to re-raise.

    Exactly one of ``items``/``error`` is set. ``timestamp`` is a
    ``time.monotonic()`` reading, compared against the provider's
    ``_cache_ttl`` (success) or ``_NEGATIVE_LIST_CACHE_TTL_SECONDS`` (failure)
    by ``is_fresh`` -- mirroring fastmcp's own ``_CacheEntry`` in
    ``server/providers/proxy.py``, which this cache sits above rather than
    replaces (see ``_ObservableProxyProvider._cached_list``'s docstring).
    """

    __slots__ = ("error", "items", "timestamp")

    def __init__(
        self,
        *,
        items: Sequence[Any] | None = None,
        error: Exception | None = None,
        timestamp: float,
    ) -> None:
        self.items = items
        self.error = error
        self.timestamp = timestamp

    def is_fresh(self, ttl: float) -> bool:
        return (time.monotonic() - self.timestamp) < ttl


# How many unroutable tool names one aggregator.tool_prefix_mismatch warning
# carries; the full set is on GET /v1/admin/tool-mapping-drift.
_PREFIX_MISMATCH_LOG_SAMPLE = 5


class _ObservableProxyProvider(ProxyProvider):
    """ProxyProvider that structured-logs a classified reason when its ``tools/list`` fails, then re-raises so ``AggregateProvider``'s existing ``provider_error_strategy="warn"`` still drops this service's contribution and keeps every other service's listing unaffected -- exactly today's degrade-gracefully behavior, just with an ``aggregator.service_list_failed`` structlog event on record instead of only fastmcp's own unparseable stdlib WARNING (see issue #121).

    Overrides only the private ``_list_tools()`` extension hook that
    ``fastmcp.server.providers.proxy.ProxyProvider`` (pinned at 3.4.4, see
    pixi.lock) itself documents as a subclassing point -- but it's still
    third-party internals, not a public contract fastmcp guarantees stable.
    If ``_list_tools()``'s signature, its call sites (``_get_tool()``'s
    stale-cache refresh in particular -- see ``resolve_list_time_headers``'s
    docstring for why that path matters here), or its cache-write-only-on-
    success behavior change on a future fastmcp bump, re-check this class.

    Also records the classified reason onto ``registry`` (ServiceRegistry.
    record_list_failure) so /v1/catalog's per-service status derivation
    (issue #123) can factor in a recent listing failure -- e.g. downgrading
    an otherwise "available" service to "unavailable" -- without an extra
    live probe of its own. A subsequent successful listing clears that
    recorded reason (ServiceRegistry.clear_list_failure) -- otherwise a
    service that recovers from one transient failure would keep reporting
    "unavailable" for the life of the process, since record_list_failure()
    on its own has no expiry or reset path.

    ``_list_tools()`` additionally caches per (caller subject, this service)
    -- issue #320: fastmcp's own ``ProxyProvider._list_tools()`` never
    consults ``_tools_cache`` (only ``_get_tool()`` does), and the mcp SDK's
    SEP-2243 param-validation path runs a full server-side ``tools/list`` on
    every ``tools/call`` that carries arguments, so an uncached listing meant
    every tool call re-listed every backend -- redeeming a per-user
    credential each time. Keyed per subject rather than one shared/merged
    listing, because a listing's outcome can depend on the caller's
    credential (rucio-mcp 401s an unlinked caller); see ``_list_tools``'s own
    docstring for the caching mechanics.

    ``_list_resources()``/``_list_resource_templates()``/``_list_prompts()``
    are cached the same way, via the shared ``_cached_list()`` helper: fastmcp's
    base implementations of those three never consult their own freshness
    caches either (same "only the per-lookup ``_get_*`` does" gap as
    ``_list_tools``), so a client reconnecting and re-listing resources or
    prompts fanned out to every backend uncached exactly like tools/list did
    before issue #320. The classify/log/``record_list_failure`` behavior
    above stays tools-only (fastmcp's ``ProxyProvider`` has no equivalent
    failure-classification hook for the other three kinds) -- only the
    per-subject caching mechanics are shared.

    ``exclude_tools`` (issue #173) omits configured native tool names from
    ``_list_tools_uncached``'s return -- so they're absent from every kind of
    tools/list, cached or not -- AND makes ``_get_tool()`` return ``None`` for
    them before delegating, exactly like ``_route_prefix``'s short-circuit
    above. Both are necessary: fastmcp's base ``_get_tool()`` (which
    ``super()._get_tool()`` below calls) reads ``self._tools_cache`` directly,
    a plain instance attribute the base ``_list_tools()`` writes with the
    *unfiltered* upstream listing as a side effect -- filtering only this
    class's own ``_list_tools()`` return value never touches that attribute,
    so a direct ``tools/call`` for an excluded name would still resolve it
    from the untouched cache.
    """

    def __init__(
        self,
        service_name: str,
        client_factory: ClientFactoryT,
        registry: ServiceRegistry,
        cache_ttl: float | None = None,
        route_prefix: str | None = None,
        exclude_tools: frozenset[str] = frozenset(),
        list_timeout_seconds: float | None = None,
    ) -> None:
        super().__init__(client_factory, cache_ttl=cache_ttl)
        self._service_name = service_name
        # Deadline for one upstream tools/list including the client factory's
        # credential setup; None disables it (see _list_tools_uncached).
        self._list_timeout_seconds = list_timeout_seconds
        self._registry = registry
        # Set only for an un-namespaced service (apply_namespace: false):
        # fastmcp's prefix-based dispatch skips that filtering for an
        # un-namespaced mount, so this provider is asked about EVERY tool
        # name in an aggregate tools/call, not just its own.
        self._route_prefix = route_prefix
        self._exclude_tools = exclude_tools
        # Set the first time _list_tools_uncached finds an exclude_tools name
        # missing from the backend's own listing (likely a typo) -- so that
        # warning fires once per service for the life of this provider
        # instance, not on every uncached tools/list.
        self._warned_missing_exclude_tools = False
        # Per-(kind, subject) listing cache (issue #320, generalized to every
        # listing kind -- tools/resources/resource templates/prompts -- see
        # _cached_list's docstring). Pruned opportunistically on every write
        # (_prune_subject_list_cache), never on a timer, so memory stays
        # bounded by recently active (kind, subject) pairs without a separate
        # cleanup task.
        self._subject_list_cache: dict[tuple[str, str], _SubjectListCacheEntry] = {}
        # One asyncio.Lock per (kind, subject), created on first use and
        # never removed -- cheap (naturally bounded by the number of distinct
        # kinds x subjects this service has ever listed for), and lets N
        # concurrent cache-miss callers for the SAME kind+subject share one
        # upstream listing instead of each triggering their own
        # (single-flight). Different kinds, different subjects, and
        # different services (each provider has its own lock dict), never
        # block each other.
        self._subject_list_locks: dict[tuple[str, str], asyncio.Lock] = {}

    async def _get_tool(
        self, name: str, version: VersionSpec | None = None
    ) -> Tool | None:
        # A name that doesn't start with this un-namespaced service's own
        # prefix can never be one of its tools -- return None without the
        # cold-cache tools/list round trip (and the per-user credential mint
        # inside client_factory) that asking anyway would otherwise cost.
        if self._route_prefix is not None and not name.startswith(
            f"{self._route_prefix}_"
        ):
            return None
        # Configured off (issue #173): return None BEFORE delegating, so a
        # direct tools/call resolves this name exactly like one that was
        # never advertised at all -- see this class's docstring on why
        # filtering _list_tools()'s return value alone isn't enough.
        if name in self._exclude_tools:
            return None
        try:
            return await super()._get_tool(name, version)
        except NotLinkedForListingError:
            # An unlinked caller's listing is skipped, so there is no schema
            # to resolve this name against. For an authorized tools/call of
            # this service, resolve it to a schema-less stand-in instead:
            # AggregateProvider swallows a resolution failure into a bare
            # "Unknown tool", whereas running the stand-in reaches
            # client_factory's authorized branch and its friendly not-linked
            # error (issue #311).
            ctx = get_context()
            if await ctx.get_state("authorized_call_target") != self._service_name:
                raise
            return ProxyTool.from_mcp_tool(
                self.client_factory, McpTool(name=name, input_schema={"type": "object"})
            )

    def invalidate_subject(self, subject: str) -> None:
        """Drop *subject*'s cached listing entries (success or failure), for every kind (tools, resources, resource templates, prompts), for this service, and the caller-specific failure reason recorded for *subject* against it.

        Called when *subject*'s linked identity changes -- see
        ``invalidate_subject_cache`` (module-level, below) for the wiring
        across every provider on a link/unlink/credential-revocation event.
        The caller-specific reason (``ServiceRegistry.clear_caller_list_failure``)
        goes with the cached entries because both describe the credential state
        being replaced; the next listing records whatever is true afterwards.
        A service-wide reason is left alone: a credential change says nothing
        about whether the backend is up. A
        subject with nothing cached is a silent no-op. Leaves
        ``_subject_list_locks`` alone: an in-flight refresh for *subject* (if
        any) is unaffected, and the next cache miss just creates a fresh lock.
        """
        stale = [key for key in self._subject_list_cache if key[1] == subject]
        for key in stale:
            del self._subject_list_cache[key]
        self._registry.clear_caller_list_failure(self._service_name, subject)

    def invalidate_all_subjects(self) -> None:
        """Drop every subject's cached listing entries for this service, and each of those subjects' caller-specific failure reasons.

        For a replica that may have missed invalidation messages (see
        ``cache_invalidation.ListCacheInvalidator``): it cannot tell which
        subjects changed, so it forgets all of them. Like
        ``invalidate_subject``, leaves the service-wide failure reason and
        ``_subject_list_locks`` alone.
        """
        for subject in {subject for _, subject in self._subject_list_cache}:
            self.invalidate_subject(subject)

    def _prune_subject_list_cache(self) -> None:
        """Drop every expired entry, so the cache dict never grows past recently active (kind, subject) pairs."""
        expired = [
            key
            for key, entry in self._subject_list_cache.items()
            if not entry.is_fresh(
                self._cache_ttl
                if entry.error is None
                else _NEGATIVE_LIST_CACHE_TTL_SECONDS
            )
        ]
        for key in expired:
            del self._subject_list_cache[key]

    async def _caller_subject(self, kind: str) -> str | None:
        """Best-effort ``Principal.subject`` from the current fastmcp request context, or ``None``.

        ``None`` covers both "no active context at all" (``get_context()``
        raises ``RuntimeError`` outside a request -- exercised directly by
        several existing tests that call ``_list_tools()`` without patching
        it) and "context exists but carries no principal" -- both mean
        "bypass the per-subject cache" to ``_cached_list``. Either bypass
        reason is logged at debug level (``aggregator.list_cache_bypass``,
        with this service and the listing *kind* involved) since it would
        otherwise be invisible -- a caller silently falling through this path
        loses the caching this class exists to provide, and that was exactly
        the kind of thing that made issue #320's production investigation
        hard.
        """
        try:
            ctx = get_context()
        except RuntimeError:
            logger.debug(
                "aggregator.list_cache_bypass",
                service=self._service_name,
                kind=kind,
                reason="no_context",
            )
            return None
        principal = await ctx.get_state("principal")
        if principal is None:
            logger.debug(
                "aggregator.list_cache_bypass",
                service=self._service_name,
                kind=kind,
                reason="no_principal",
            )
            return None
        return principal.subject

    def _fresh_subject_entry(
        self, key: tuple[str, str]
    ) -> _SubjectListCacheEntry | None:
        """Return the *(kind, subject)* cache entry if it's still fresh under its own TTL (success: ``_cache_ttl``; failure: the negative TTL), else ``None``."""
        entry = self._subject_list_cache.get(key)
        if entry is None:
            return None
        ttl = (
            self._cache_ttl if entry.error is None else _NEGATIVE_LIST_CACHE_TTL_SECONDS
        )
        return entry if entry.is_fresh(ttl) else None

    @staticmethod
    def _serve_or_raise(entry: _SubjectListCacheEntry) -> Sequence[Any]:
        """Return a cached success's items, or re-raise a cached failure -- without repeating any side effects the original fetch already ran once, when the failure was first cached."""
        if entry.error is not None:
            raise entry.error
        return require(entry.items, "exactly one of items/error is set")

    async def _cached_list(
        self, kind: str, fetch: Callable[[], Awaitable[Sequence[Any]]]
    ) -> Sequence[Any]:
        """Serve *fetch*'s result from the per-(subject, kind) cache for this service, single-flighted per (kind, subject) -- issue #320, generalized beyond tools.

        Shared mechanics for all four listing kinds this provider caches
        (tools, resources, resource templates, prompts): no active request
        context, no principal on it, or ``ServiceSpec.tools_cache_ttl: 0``
        (``self._cache_ttl <= 0``) bypass the cache entirely, calling *fetch*
        straight through every time, exactly fastmcp's own uncached
        behavior. Otherwise, a fresh cached entry (success or failure) is
        served directly by ``_serve_or_raise``. A cache miss or expired entry
        takes an ``asyncio.Lock`` keyed by *(kind, subject)* before
        refreshing, so concurrent callers for the same kind+subject share
        one upstream listing (single-flight) rather than each triggering
        their own; the entry is re-checked after acquiring the lock in case
        another task already refreshed it while this one was waiting.

        *fetch* is the only thing that differs across kinds -- for tools
        it's ``_list_tools_uncached`` (classify/log/record_list_failure on
        top of the upstream call); for the other three it's simply fastmcp's
        own ``super()._list_resources``/etc, since those have no equivalent
        failure-classification hook to preserve.
        """
        subject = await self._caller_subject(kind)
        if subject is None or self._cache_ttl <= 0:
            return await fetch()

        key = (kind, subject)
        entry = self._fresh_subject_entry(key)
        if entry is not None:
            return self._serve_or_raise(entry)

        lock = self._subject_list_locks.setdefault(key, asyncio.Lock())
        async with lock:
            entry = self._fresh_subject_entry(key)
            if entry is not None:
                return self._serve_or_raise(entry)

            try:
                items = await fetch()
            except Exception as exc:
                # A 401 for an injected credential has just made its
                # provider refresh or reject it (issue #344, report_401), so
                # the next listing must try again rather than replay this
                # failure; every other failure is negative-cached. A caller
                # turned away before any request (NotLinkedForListingError, even
                # for a rejected credential) is cached too: _get_tool relies
                # on replaying it to resolve a direct call to the stand-in
                # instead of re-running the client factory's authorized
                # branch, whose friendly error AggregateProvider swallows.
                # An unentitled caller is never cached: the check costs no
                # request, and a permission granted since must apply at once.
                reason, _ = await _classify_list_failure(exc, self._service_name)
                if reason != "not_entitled" and (
                    reason != "unauthorized"
                    or isinstance(exc, NotLinkedForListingError)
                ):
                    self._subject_list_cache[key] = _SubjectListCacheEntry(
                        error=exc, timestamp=time.monotonic()
                    )
                    self._prune_subject_list_cache()
                raise
            else:
                self._subject_list_cache[key] = _SubjectListCacheEntry(
                    items=items, timestamp=time.monotonic()
                )
                self._prune_subject_list_cache()
                return items

    # The public list_* methods are what AggregateProvider calls, and it logs a
    # WARNING for any exception they raise. A caller who has not linked the
    # credential is an expected skip, already on record as an INFO
    # ``aggregator.service_list_failed`` event, so these report an empty
    # listing for it instead. Only the public methods catch: ``_get_tool``
    # and the per-subject cache go through ``_list_*`` and still see the
    # exception, which they rely on.

    async def list_tools(self) -> Sequence[Tool]:
        """List this service's tools, or none for a caller who has not linked the credential or holds none of its permissions."""
        try:
            return await super().list_tools()
        except (NotLinkedForListingError, NotEntitledForListingError):
            return []

    async def list_resources(self) -> Sequence[Resource]:
        """List this service's resources, or none for a caller who has not linked the credential or holds none of its permissions."""
        try:
            return await super().list_resources()
        except (NotLinkedForListingError, NotEntitledForListingError):
            return []

    async def list_resource_templates(self) -> Sequence[ResourceTemplate]:
        """List this service's resource templates, or none for a caller who has not linked the credential or holds none of its permissions."""
        try:
            return await super().list_resource_templates()
        except (NotLinkedForListingError, NotEntitledForListingError):
            return []

    async def list_prompts(self) -> Sequence[Prompt]:
        """List this service's prompts, or none for a caller who has not linked the credential or holds none of its permissions."""
        try:
            return await super().list_prompts()
        except (NotLinkedForListingError, NotEntitledForListingError):
            return []

    async def _list_tools(self) -> Sequence[Tool]:
        """List this service's tools, cached per (caller subject, this service) -- issue #320. See ``_cached_list`` for the caching mechanics; ``_list_tools_uncached`` is the tools-specific fetch (classify/log/record_list_failure)."""
        return await self._cached_list("tools", self._list_tools_uncached)

    async def _list_resources(self) -> Sequence[Resource]:
        """List this service's resources, cached the same way as ``_list_tools`` (see ``_cached_list``) -- no classify/log/record_list_failure side effects (tools-only)."""
        return await self._cached_list("resources", super()._list_resources)

    async def _list_resource_templates(self) -> Sequence[ResourceTemplate]:
        """List this service's resource templates, cached the same way as ``_list_tools`` (see ``_cached_list``) -- no classify/log/record_list_failure side effects (tools-only)."""
        return await self._cached_list(
            "resource_templates", super()._list_resource_templates
        )

    async def _list_prompts(self) -> Sequence[Prompt]:
        """List this service's prompts, cached the same way as ``_list_tools`` (see ``_cached_list``) -- no classify/log/record_list_failure side effects (tools-only)."""
        return await self._cached_list("prompts", super()._list_prompts)

    async def _list_tools_uncached(self) -> Sequence[Tool]:
        """Do the actual upstream ``tools/list`` -- classify/log/record on failure, clear/warn-on-mismatch on success.

        The pre-issue-#320 body of ``_list_tools()``, unchanged, now called
        only on a per-subject cache miss (or when that cache is bypassed
        entirely) rather than on every ``tools/list``.
        """
        try:
            tools = await self._list_tools_within_deadline()
        except Exception as exc:
            reason, detail = await _classify_list_failure(exc, self._service_name)
            subject = await self._caller_subject("tools")
            # An unentitled caller is not a failure of the service, so it
            # leaves no record for the catalog to surface.
            if reason != "not_entitled":
                self._registry.record_list_failure(self._service_name, reason, subject)
            # An unlinked or unentitled caller is an expected state, not a fault.
            log = (
                logger.info
                if reason in ("not_linked", "not_entitled")
                else logger.warning
            )
            log(
                "aggregator.service_list_failed",
                service=self._service_name,
                reason=reason,
                error=detail,
            )
            raise
        else:
            # A successful listing means the service has recovered from any
            # recorded service-wide failure, and this caller from their own
            # -- clear both so /v1/catalog and af_list_mcp_servers stop
            # reporting them.
            self._registry.clear_list_failure(
                self._service_name, await self._caller_subject("tools")
            )
            if self._exclude_tools:
                self._warn_on_missing_exclude_tools(tools)
                tools = [t for t in tools if t.name not in self._exclude_tools]
            self._record_tool_routing(tools)
            return tools

    async def _list_tools_within_deadline(self) -> Sequence[Tool]:
        """Run fastmcp's upstream ``tools/list`` under this provider's listing deadline.

        The deadline wraps the whole attempt -- ``client_factory`` (list-time
        credential setup) as well as the backend round trip -- so a stalled
        Vault read counts the same as a stalled backend. Expiry cancels the
        attempt, which closes the backend client and its connection through
        the ``async with client`` inside ``ProxyProvider._list_tools``.
        ``Timeout.expired()`` distinguishes this deadline from a
        ``TimeoutError`` the attempt raised on its own.
        """
        deadline = asyncio.timeout(self._list_timeout_seconds)
        try:
            async with deadline:
                return await super()._list_tools()
        except TimeoutError as exc:
            if not deadline.expired():
                raise
            raise ListDeadlineExceededError(
                f"Service '{self._service_name}' did not list its tools within "
                f"{self._list_timeout_seconds:g}s."
            ) from exc

    def _record_tool_routing(self, tools: Sequence[Tool]) -> None:
        """Record how many of *tools* (one upstream listing, after ``exclude_tools``) this service's prefix can route -- onto the registry (ToolRouting) and the per-service advertised/routable gauges -- and warn once for the whole listing if any can't."""
        unroutable: tuple[str, ...] = ()
        if self._route_prefix is not None:
            # A listed tool that doesn't match the route prefix is
            # unreachable via _get_tool's short-circuit above, and
            # EntitlementMiddleware hides it from tools/list unless its name
            # happens to match another service's prefix -- warn rather than
            # filter, so the mismatch is on record instead of silently dead
            # on arrival.
            prefix = f"{self._route_prefix}_"
            unroutable = tuple(
                sorted(tool.name for tool in tools if not tool.name.startswith(prefix))
            )
            if unroutable:
                # One summary per upstream listing rather than one event per
                # tool: a backend rename makes every tool mismatch at once.
                logger.warning(
                    "aggregator.tool_prefix_mismatch",
                    service=self._service_name,
                    prefix=self._route_prefix,
                    count=len(unroutable),
                    sample=list(unroutable[:_PREFIX_MISMATCH_LOG_SAMPLE]),
                )
        routing = ToolRouting(
            service=self._service_name, advertised=len(tools), unroutable=unroutable
        )
        self._registry.record_tool_routing(routing)
        metrics.service_tools_advertised.labels(service=self._service_name).set(
            routing.advertised
        )
        metrics.service_tools_routable.labels(service=self._service_name).set(
            routing.routable
        )

    def _warn_on_missing_exclude_tools(self, tools: Sequence[Tool]) -> None:
        """Warn once per service (per process, for this provider instance) if a configured ``exclude_tools`` name never appears in *tools* -- the raw upstream listing, before filtering. Likely a typo (issue #173): an excluded name that never existed excludes nothing, silently. Only called from a genuine upstream fetch (``_list_tools_uncached``), never from a per-subject cache hit, so a persistently mistyped name doesn't spam a warning on every cached ``tools/list``."""
        if self._warned_missing_exclude_tools:
            return
        missing = self._exclude_tools - {t.name for t in tools}
        if missing:
            logger.warning(
                "aggregator.exclude_tools_not_found",
                service=self._service_name,
                tools=sorted(missing),
            )
            self._warned_missing_exclude_tools = True


class BackendProviders:
    """The ``_ObservableProxyProvider`` of every proxied backend, by service name.

    fastmcp wraps a namespaced provider in a private ``_WrappedProvider`` when
    it is added, so ``mcp.providers`` never holds our providers directly.
    ``_register_services`` records them here instead, and the invalidation
    helpers below reach the real objects through this holder.
    """

    def __init__(self) -> None:
        self._by_service: dict[str, _ObservableProxyProvider] = {}

    def replace(self, providers: dict[str, _ObservableProxyProvider]) -> None:
        """Make *providers* (keyed by ``ServiceSpec.name``) the recorded set."""
        self._by_service = providers

    def get(self, service_name: str) -> _ObservableProxyProvider:
        """Return the provider for *service_name*; ``KeyError`` if none is registered."""
        return self._by_service[service_name]

    def items(self) -> list[tuple[str, _ObservableProxyProvider]]:
        """Return every ``(service name, provider)`` pair."""
        return list(self._by_service.items())

    def values(self) -> list[_ObservableProxyProvider]:
        """Return every recorded provider."""
        return list(self._by_service.values())


class Aggregator(FastMCP):
    """The aggregator FastMCP instance, owning the ``BackendProviders`` its backends are recorded in.

    Owning the holder makes one holder per aggregator structural:
    ``_register_services`` records into it and callers read it from here. A
    caller that must hand the holder to something built before the aggregator
    (the cache invalidator, which the credential providers the aggregator
    needs depend on) creates it first and passes it in.
    """

    def __init__(
        self,
        *args: Any,
        backend_providers: BackendProviders | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(*args, **kwargs)
        self.backend_providers = backend_providers or BackendProviders()


def invalidate_subject_cache(
    backend_providers: BackendProviders, subject: str, target: str | None = None
) -> None:
    """Drop *subject*'s cached listing entries (every kind: tools, resources, resource templates, prompts) across *backend_providers* -- one service (*target*) or every service.

    Called wherever a subject's linked identity changes (unlink, credential
    revocation, or a completed link -- see app.py's ``CredentialCache``
    construction)
    so a stale per-subject listing (``_ObservableProxyProvider.invalidate_subject``)
    is never served past that change. *target* narrows to the one
    ``ServiceSpec.name`` affected; omitted, every service's cache entry for
    *subject* is dropped.
    """
    for service_name, provider in backend_providers.items():
        if target is None or service_name == target:
            provider.invalidate_subject(subject)


def invalidate_all_subject_caches(backend_providers: BackendProviders) -> None:
    """Drop every subject's cached listing entries across all of *backend_providers* (see ``_ObservableProxyProvider.invalidate_all_subjects``)."""
    for provider in backend_providers.values():
        provider.invalidate_all_subjects()


def build_aggregator(
    registry: ServiceRegistry,
    settings: Settings,
    policy: EntitlementPolicy,
    credential_registry: CredentialRegistry,
    *,
    shared_state: SharedState,
    usage_store: UsageStore,
    lint_observations: LintObservationStore,
    identity_providers: dict[str, CredentialProvider] | None = None,
    identity_provider_configs: dict[str, IdentityProviderConfig] | None = None,
    target_to_alias: dict[str, str] | None = None,
    broker_token_issuer: BrokerTokenIssuer | None = None,
    job_credentials: JobCredentialGuide | None = None,
    backend_providers: BackendProviders | None = None,
) -> Aggregator:
    """Construct a fully-wired aggregator FastMCP instance.

    Registers IdentityMiddleware first (so it runs outermost among these
    three and extracts the Principal before anything else sees the request),
    EntitlementMiddleware second (filters tools/list to what the Principal
    is entitled to), and AuthorizationMiddleware third (checks entitlement
    again for tools/call, since a filtered list is not an access-control
    boundary by itself, and audits every invocation) -- then adds one
    ProxyProvider per service in ``registry`` plus the broker-native af_*
    diagnostic tools (issue #153, see mcp/diagnostics.py). Namespacing
    follows ``ServiceSpec.apply_namespace`` -- services whose tools already
    self-prefix (e.g. rucio-mcp) opt out.

    fastmcp v4's ``FastMCP.__init__`` auto-appends a ``DereferenceRefsMiddleware``
    to ``self.middleware`` (default ``dereference_schemas=True``, before any
    of the three ``add_middleware`` calls below run), which technically wraps
    IdentityMiddleware from the outside -- "outermost among these three" above
    is no longer "outermost, full stop". Confirmed benign: that middleware
    implements only ``on_list_tools``/``on_list_resource_templates``, purely
    inlining ``$ref`` in the already-built response schema after
    ``call_next`` returns (for client SDKs, e.g. VS Code Copilot, that don't
    handle `$ref` themselves) -- it never touches identity extraction,
    routing, or any other request-side behavior, and ``AsgiAuthMiddleware``
    gates at the ASGI layer before any FastMCP middleware (this one
    included) runs at all. Left enabled rather than set
    ``dereference_schemas=False``: that client-compat behavior is worth
    keeping given it's a no-op for everything this docstring's ordering
    invariant actually cares about.

    *shared_state* backs ``policy.rate_limits``; *usage_store* answers af_usage; *lint_observations* is where
    the tool-listing lint's findings are recorded. *identity_providers*/
    *identity_provider_configs*/*target_to_alias* default to empty:
    af_list_identities/af_list_mcp_servers then report nothing.
    *backend_providers* is the holder the proxied backends are recorded in;
    omitted, the aggregator creates its own.
    """
    # instructions is the model-facing "dual enforcement" layer (finding #6):
    # a platform preamble plus each service's agent_policy, surfaced to clients
    # in the MCP initialize response.
    mcp = Aggregator(
        name="af-mcp-aggregator",
        instructions=compose_agent_instructions(registry, job_credentials),
        backend_providers=backend_providers,
    )
    mcp.add_middleware(IdentityMiddleware())
    entitlement_mw = EntitlementMiddleware(registry, policy)
    entitlement_mw.use_lint_store(lint_observations)
    mcp.add_middleware(entitlement_mw)
    authorization_mw = AuthorizationMiddleware(registry, policy)
    authorization_mw.use_shared_state(shared_state)
    mcp.add_middleware(authorization_mw)
    _register_services(
        mcp,
        registry,
        credential_registry,
        settings,
        policy,
        broker_token_issuer=broker_token_issuer,
        target_to_alias=target_to_alias,
        identity_provider_configs=identity_provider_configs,
    )
    register_diagnostic_tools(
        mcp,
        registry,
        policy,
        credential_registry,
        identity_providers or {},
        identity_provider_configs or {},
        target_to_alias or {},
        settings,
        shared_state,
        usage_store,
        job_credentials,
    )
    return mcp


def build_asgi_middleware(
    settings: Settings,
    pat_backend: TokenRegistryBackend | None,
    principal_cache: PrincipalCache | None,
    maintenance_mode_store: MaintenanceModeStore,
) -> list[Middleware]:
    """Return the Starlette middleware specs that gate /mcp at the ASGI layer, outermost first.

    Enforces identity (issue #138/#144 step 1) and then maintenance mode for
    the aggregator's http_app -- pass this into ``FastMCP.http_app(middleware=...)``
    when mounting. The order is load-bearing: the maintenance gate reads the
    Principal the identity middleware stashes, so identity must wrap it.

    *pat_backend*/*principal_cache* being None means identity PATs are
    recognized by prefix on ``/mcp`` but always rejected (see
    ``mcp/middleware/identity_mw.py``'s ``AsgiAuthMiddleware``) -- a broker
    with no Keycloak admin service account configured (issue #144 step 2a).
    """
    return [
        Middleware(
            AsgiAuthMiddleware,
            settings=settings,
            pat_backend=pat_backend,
            principal_cache=principal_cache,
        ),
        Middleware(
            AsgiMaintenanceMiddleware,
            settings=settings,
            maintenance_mode_store=maintenance_mode_store,
        ),
    ]


def _register_services(
    mcp: Aggregator,
    registry: ServiceRegistry,
    credential_registry: CredentialRegistry,
    settings: Settings,
    policy: EntitlementPolicy,
    *,
    broker_token_issuer: BrokerTokenIssuer | None = None,
    target_to_alias: dict[str, str] | None = None,
    identity_provider_configs: dict[str, IdentityProviderConfig] | None = None,
) -> None:
    mcp.providers.clear()
    # mcp.providers.clear() above wipes every provider, including
    # mcp.local_provider (FastMCP.__init__ adds it there once, at
    # construction) -- re-add it immediately so the af_* diagnostic tools
    # (mcp/diagnostics.py's register_diagnostic_tools(), which registers
    # directly onto that same LocalProvider instance) stay reachable through
    # dispatch. Re-adding the same object never produces a duplicate entry:
    # the list was just cleared.
    mcp.add_provider(mcp.local_provider)
    providers: dict[str, _ObservableProxyProvider] = {}
    mcp.backend_providers.replace(providers)
    for spec in registry.all_services():
        if spec.builtin:
            # The builtin gateway service (issue #240) has no backend to
            # proxy: its af_* methods are the local tools
            # register_diagnostic_tools() puts on mcp.local_provider above,
            # so building a ProxyProvider (which would dial spec.url) is
            # both impossible and unnecessary.
            continue
        provider = _ObservableProxyProvider(
            spec.name,
            client_factory=_make_client_factory(
                spec,
                credential_registry,
                settings,
                policy,
                broker_token_issuer=broker_token_issuer,
                target_to_alias=target_to_alias,
                identity_provider_configs=identity_provider_configs,
            ),
            registry=registry,
            cache_ttl=spec.tools_cache_ttl,
            route_prefix=None if spec.apply_namespace else spec.prefix,
            exclude_tools=spec.exclude_tools,
            list_timeout_seconds=settings.mcp_list_timeout_seconds,
        )
        namespace = spec.prefix if spec.apply_namespace else ""
        mcp.add_provider(provider, namespace=namespace)
        providers[spec.name] = provider
