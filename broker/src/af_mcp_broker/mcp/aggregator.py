from __future__ import annotations

# Aggregator entry point — builds the FastMCP application that proxies tool
# calls to downstream MCP services after the broker has validated identity,
# applied entitlement filtering, checked authorization, and (for
# auth_type="bearer" services) minted and injected a per-user credential.
#
# app.py builds an aggregator eagerly (with an empty ServiceRegistry) so its
# ASGI app exists at FastAPI-construction time for mounting at /mcp and for
# combining lifespans; app.py's own lifespan then calls populate_aggregator()
# once SERVICES_FILE/POLICY_FILE/the credential subsystem have actually been
# loaded. The client_factory below deliberately never forwards the caller's
# inbound Authorization header to a service; see its docstring.
import asyncio
import time
from typing import TYPE_CHECKING, Any, NamedTuple

import httpx2
import structlog
from fastapi import HTTPException
from fastmcp import FastMCP
from fastmcp.client import Client
from fastmcp.client.transports import SSETransport, StreamableHttpTransport
from fastmcp.exceptions import ToolError
from fastmcp.server.dependencies import get_context
from fastmcp.server.elicitation import AcceptedElicitation
from fastmcp.server.providers.proxy import (
    ClientFactoryT,
    ProxyProvider,
    default_proxy_log_handler,
    default_proxy_progress_handler,
)
from mcp.types import ClientCapabilities, ElicitationCapability, ToolAnnotations
from starlette.middleware import Middleware

from af_mcp_broker.authorization import get_principal_permissions
from af_mcp_broker.credentials import CredentialKind, NeedsUnlock
from af_mcp_broker.mcp.diagnostics import register_diagnostic_tools
from af_mcp_broker.mcp.instructions import compose_agent_instructions
from af_mcp_broker.mcp.middleware.authorization_mw import AuthorizationMiddleware
from af_mcp_broker.mcp.middleware.entitlement_mw import EntitlementMiddleware
from af_mcp_broker.mcp.middleware.identity_mw import (
    AsgiAuthMiddleware,
    IdentityMiddleware,
)
from af_mcp_broker.mcp.registry import (
    LINK_IDENTITY_TOOL_NAME,
    LIST_IDENTITIES_TOOL_NAME,
    LIST_MCP_SERVERS_TOOL_NAME,
    identity_provider_url,
    namespaced_tool_name,
)

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Iterator, Sequence

    from fastmcp import Context
    from fastmcp.prompts import Prompt
    from fastmcp.resources import Resource, ResourceTemplate
    from fastmcp.tools.base import Tool
    from fastmcp.utilities.versions import VersionSpec

    from af_mcp_broker.authorization import EntitlementPolicy
    from af_mcp_broker.config import IdentityProviderConfig, Settings
    from af_mcp_broker.credentials import CredentialProvider, CredentialRegistry
    from af_mcp_broker.credentials.broker_issued import BrokerTokenIssuer
    from af_mcp_broker.identity import Principal
    from af_mcp_broker.maintenance import MaintenanceModeStore
    from af_mcp_broker.mcp.registry import ServiceRegistry, ServiceSpec
    from af_mcp_broker.principal_cache import PrincipalCache
    from af_mcp_broker.token_registry import RevokedJtiCache, TokenRegistryBackend

logger = structlog.get_logger(__name__)


# mcp SDK v2's streamable-HTTP client normalizes ANY non-2xx response whose
# body isn't already JSON-RPC-shaped into a generic MCPError(INTERNAL_ERROR),
# delivered as a JSON-RPC error reply on the read stream -- never raised as an
# httpx2-family exception (mcp/client/streamable_http.py's
# _handle_request_response, the `response.status_code >= 400` branch). The
# real HTTP status code is otherwise unrecoverable by the time _classify_failure
# sees the resulting exception, so a rejected stored credential (401) can no
# longer be told apart from any other backend failure -- see issue #314.
#
# A ContextVar set from a response event hook does NOT work around this: the
# POST that receives the response runs inside a *child* task the SDK spawns
# with `task_group.start_soon()` (mcp/client/streamable_http.py's
# streamable_http_client), which gets its own copy of the current context --
# a ContextVar.set() there is invisible once that task group's `async with`
# block returns control to the caller. Verified by direct repro before
# settling on the approach below.
#
# Instead, this hook raises httpx2.HTTPStatusError itself, for a 401 only --
# every other status is left to the SDK's own handling (its JSON-RPC-shaped-
# body parse, its dedicated 404 mapping, etc.), unchanged. Raising inside a
# response hook propagates like any exception from httpx2.AsyncClient.send()
# (httpx2/_client.py's _send_handling_redirects loop awaits each hook
# in-line, no special-casing); since it originates inside the SDK's spawned
# task, it surfaces wrapped in an anyio ExceptionGroup exactly like the
# proxy transport failures _iter_leaf_exceptions already exists to walk
# through -- so the existing, already-tested 401-leaf check below needs no
# further change to recognize it.
async def _raise_for_401(response: httpx2.Response) -> None:
    if response.status_code == 401:
        response.raise_for_status()


def _unauthorized_raising_httpx_client_factory(
    headers: dict[str, str] | None = None,
    timeout: httpx2.Timeout | None = None,
    auth: httpx2.Auth | None = None,
    **kwargs: Any,
) -> httpx2.AsyncClient:
    """``McpHttpClientFactory`` that adds ``_raise_for_401`` to the client's response hooks.

    Mirrors ``mcp.shared._httpx_utils.create_mcp_http_client``'s defaults
    (30s connect/write/pool, 300s read, for a backend that holds a response
    stream open) rather than importing that private module directly.
    ``**kwargs`` absorbs ``follow_redirects`` (passed by both
    ``StreamableHttpTransport`` and ``SSETransport``'s ``connect_session``,
    but not part of the documented factory signature -- see their
    ``httpx_client_factory`` docstrings recommending ``**kwargs`` for exactly
    this forward-compatibility reason).
    """
    if timeout is None:
        timeout = httpx2.Timeout(30.0, read=300.0)
    client_kwargs: dict[str, Any] = {"timeout": timeout, **kwargs}
    if headers is not None:
        client_kwargs["headers"] = headers
    if auth is not None:
        client_kwargs["auth"] = auth
    client = httpx2.AsyncClient(**client_kwargs)
    client.event_hooks.setdefault("response", []).append(_raise_for_401)
    return client


def _build_client(
    spec: ServiceSpec,
    transport_cls: type[SSETransport | StreamableHttpTransport],
    headers: dict[str, str] | None = None,
) -> Client:
    """Construct the plain (never ProxyClient) Client every branch of _make_client_factory returns.

    Applies the service's configured per-call read timeout (ServiceSpec.
    timeout_seconds) so a slow/unresponsive service fails that one call
    cleanly instead of hanging the aggregator, and installs the same
    progress/log *notification* forwarding handlers fastmcp's ProxyClient
    installs by default -- ProxyClient itself is still not used (see
    _make_client_factory's docstring: its unconditional
    forward_incoming_headers=True for HTTP/SSE clients is the one behavior
    deliberately avoided here), but that has nothing to do with
    these two handlers, which only relay already-decided-safe notification
    content from the service to the aggregator's own caller, never inbound
    credentials.
    """
    return Client(
        transport_cls(
            spec.url,
            headers=headers,
            httpx_client_factory=_unauthorized_raising_httpx_client_factory,
        ),
        timeout=spec.timeout_seconds,
        progress_handler=default_proxy_progress_handler,
        log_handler=default_proxy_log_handler,
    )


async def _resolve_list_time_headers(
    spec: ServiceSpec,
    credential_registry: CredentialRegistry,
    principal: Principal,
) -> tuple[dict[str, str] | None, str | None]:
    """Best-effort per-user credential mint for a tools/list-time connection.

    Returns ``(headers, skip_reason)``. Never raises: unlike the authorized
    tools/call path in ``_bearer_factory``, a failure here must not prevent
    the connection attempt outright -- doing so would mean this service's
    ``ProxyProvider`` never completes a single successful ``_list_tools()``
    call for an unlinked caller, which (a) would leave its component-list
    cache permanently unpopulated (fastmcp's ``ProxyProvider`` only writes
    that cache after a call that didn't raise), forcing every later
    ``_get_tool()`` cache-miss lookup -- including ones for a *different*,
    perfectly authorized caller -- to re-trigger a listing, and (b) a
    listing failure raised from there is swallowed by
    ``AggregateProvider._get_tool()``'s own warn-and-continue handling into
    a bare "Unknown tool", losing the friendly authorized-path ``ToolError``
    entirely. Connecting without a credential instead reproduces exactly
    what a "none" service does: a service that itself gates listing on auth
    (rucio-mcp) still ends up excluded via its own 401 -- classified and
    logged by ``_ObservableProxyProvider`` below -- while one that doesn't
    (e.g. a bearer service whose listing endpoint happens to be open) still
    lists successfully, deferring the real access decision to the
    authorized tools/call path exactly as before this fix.

    ``skip_reason`` (``"not_linked"`` | ``"unavailable"``) is set whenever
    ``headers`` is ``None``, letting the caller pre-record *why* no
    credential was attached (see the per-service request-scoped state in
    ``_bearer_factory``) for ``_classify_list_failure`` to use if the
    resulting uncredentialed connection does go on to fail.
    """
    try:
        provider = await credential_registry.resolve(spec.name)
    except KeyError:
        return None, "unavailable"

    # Same linkage gate as the authorized tools/call path, but non-fatal:
    # an unlinked caller simply doesn't get a credential attached.
    if not await provider.is_linked(principal):
        return None, "not_linked"

    try:
        cred = await provider.issue(principal, spec.name)
    except (NeedsUnlock, HTTPException):
        return None, "unavailable"

    headers: dict[str, str] = {}
    if cred.kind == CredentialKind.BEARER:
        token = cred.payload.get("access_token")
        if token:
            headers["Authorization"] = f"Bearer {token}"
    return headers, None


def _iter_leaf_exceptions(
    exc: BaseException, *, _seen: set[int] | None = None
) -> Iterator[BaseException]:
    """Yield *exc* itself, its ``ExceptionGroup`` leaves, and its ``__cause__``/``__context__`` chain.

    A transport failure inside fastmcp's client (which runs its I/O in anyio
    task groups) can surface wrapped in a ``BaseExceptionGroup`` rather than
    as the raw ``httpx`` exception -- classification below must look through
    that wrapping or an injected-credential 401 would misclassify as
    "unavailable". Separately, fastmcp v4 wraps a proxy transport failure as
    a plain chained exception (``raise _proxy_upstream_error(error) from
    error``), not a group, so the chain must be walked too or the same 401
    would stay unreachable when it arrives that way instead. ``_seen``
    guards against a pathological cause/context cycle; callers never pass it.
    """
    seen = _seen if _seen is not None else set()
    if id(exc) in seen:
        return
    seen.add(id(exc))
    if isinstance(exc, BaseExceptionGroup):
        for sub in exc.exceptions:
            yield from _iter_leaf_exceptions(sub, _seen=seen)
        return
    yield exc
    chained = exc.__cause__ or exc.__context__
    if chained is not None:
        yield from _iter_leaf_exceptions(chained, _seen=seen)


def _classify_failure(
    exc: Exception, *, injected: bool, skip_reason: str | None
) -> str:
    """Classify failure decision for api access.

    Decision core shared by ``_classify_list_failure`` (the /mcp listing
    path) and ``fetch_service_tool_listing`` (the /v1 per-service tool
    listing), so the two can never disagree on what a failure means.

    If a credential mint was deliberately skipped (``skip_reason`` set),
    that's the precise reason regardless of what the resulting
    uncredentialed connection raised. Otherwise, a raw upstream 401 is only
    "unauthorized" -- meaning the stored credential itself was rejected,
    bad/expired, the caller should re-link -- when a credential actually was
    injected for this attempt; a 401 with nothing injected (e.g. a
    "none"/"x509" service unexpectedly requiring auth) falls back to
    "unavailable", an operational/config problem rather than a "go re-link"
    prompt.

    A request that never got a correlated response within its deadline used
    to be distinguished as "timeout" (``McpError`` with ``code ==
    httpx.codes.REQUEST_TIMEOUT``) from "unavailable" (a connection-level
    refusal/reset before the request was even sent) -- see #280, which also
    explains why that distinction was never precise pre-mcp-v2: the same
    code covered both a genuinely slow backend and one whose malformed
    response orphaned the request. mcp SDK v2 fixed the latter (#292), but
    also stopped producing ``REQUEST_TIMEOUT`` at all -- fastmcp v4's
    ``server/providers/proxy.py._proxy_upstream_error`` normalizes
    every proxy transport failure, timeouts included, to a plain
    ``INTERNAL_ERROR``. That probe is dead code post-migration and has been
    removed rather than kept as an unreachable branch; "timeout" is no
    longer a ``_classify_failure`` outcome, which makes
    ``api/catalog_tools.py``'s dedicated "timeout" status message dead code
    too -- flagged for a follow-up decision (retire the status, or detect a
    real client-side timeout by chain-walking for ``TimeoutError`` instead,
    which fastmcp still preserves on ``__cause__``) rather than silently
    left as-is.

    Note: httpx2, not httpx (1.x) -- fastmcp v4 / mcp SDK v2 are httpx2-only,
    and httpx2.HTTPStatusError is not a subclass of httpx (1.x)'s.

    mcp SDK v2's streamable-HTTP client normally never raises this at all for
    a 401: a non-2xx response whose body isn't already JSON-RPC-shaped is
    normalized into a generic ``MCPError(INTERNAL_ERROR)`` delivered on the
    read stream, discarding the real status code. ``_build_client``'s
    ``_unauthorized_raising_httpx_client_factory`` forces a 401 specifically
    back into a raised ``httpx2.HTTPStatusError`` at the httpx layer so this
    check can still find it -- see issue #314.
    """
    if not injected and skip_reason is not None:
        return skip_reason
    if injected and any(
        isinstance(leaf, httpx2.HTTPStatusError) and leaf.response.status_code == 401
        for leaf in _iter_leaf_exceptions(exc)
    ):
        return "unauthorized"
    return "unavailable"


async def _classify_list_failure(exc: Exception, service_name: str) -> tuple[str, str]:
    """Classify a ``_list_tools()`` failure for structured logging.

    Consults the per-service request-scoped state ``_bearer_factory``'s
    list-time branch records (keyed per service since one ``tools/list``
    request fans out to every service concurrently), then applies
    ``_classify_failure``'s shared decision core.
    """
    ctx = get_context()
    status = await ctx.get_state(f"__list_credential_status__:{service_name}")
    injected, skip_reason = status if status is not None else (False, None)
    return _classify_failure(exc, injected=injected, skip_reason=skip_reason), str(exc)


async def resolve_list_time_credential(
    spec: ServiceSpec,
    credential_registry: CredentialRegistry,
    principal: Principal,
    broker_token_issuer: BrokerTokenIssuer | None = None,
) -> tuple[dict[str, str] | None, str | None]:
    """Best-effort list-time credential headers for *spec*, any auth_type.

    The /v1 per-service tool listing's (api/catalog_tools.py) entry point
    into the exact same list-time credential logic the aggregator's client
    factories use, so the portal's tool listing can never disagree with what
    a tools/list through /mcp would have injected:

    - "none": no per-user credential concept at all -> ``({}, None)``.
    - "x509"/"krb5"/"servicex": share one code path here -- a locally-signed
      AF Broker Identity Token, mirroring ``_x509_factory``'s/
      ``_krb5_factory``'s/``_servicex_factory``'s identical list-time
      branches; with no issuer configured the connection proceeds bare
      (``(None, None)``), same as the aggregator. The backend redeems the
      actual proxy/ticket/access-token itself via ``POST /v1/credentials/
      x509/redeem``, ``.../krb5/redeem``, or ``.../servicex/redeem``
      respectively; this function must never call ``provider.issue()`` for
      any of the three.
    - "bearer": ``_resolve_list_time_headers`` (the issue #121 best-effort
      mint), unchanged -- ``skip_reason`` ("not_linked" | "unavailable")
      is set whenever no credential could be attached.

    Callers must gate on holding at least one of the service's required
    permissions first (``_might_be_entitled`` here; ``api/permissions.py``'s
    ``_holds_any_required_permission`` for ``api/catalog_tools.py``) -- a
    caller who could never pass it shouldn't trigger a mint attempt at all.
    """
    if spec.auth_type == "none":
        return {}, None
    if spec.auth_type in ("x509", "krb5", "servicex"):
        if broker_token_issuer is None:
            return None, None
        token, _ = broker_token_issuer.mint(principal.subject, spec.effective_audience)
        return {"Authorization": f"Bearer {token}"}, None
    return await _resolve_list_time_headers(spec, credential_registry, principal)


def _might_be_entitled(
    principal: Principal, spec: ServiceSpec, policy: EntitlementPolicy
) -> bool:
    """Return whether a list-time credential mint for *spec* is worth attempting at all.

    Best-effort: this runs for a caller with no specific tool_name in hand
    yet (a tools/list request, or a stale-cache _get_tool() refresh) -- not a
    security boundary of its own (EntitlementMiddleware already hides a
    service's tools from a caller with no chance of using any of them; a
    caller who slips past this and calls one anyway is still stopped by
    AuthorizationMiddleware's real per-tool check). True if *spec* has no
    permission gate at all, or the caller holds at least one of the
    permissions it can require across any of its tools.
    """
    required = spec.all_required_permissions()
    return not required or bool(required & get_principal_permissions(principal, policy))


class ToolListingEntry(NamedTuple):
    """One tool as ``fetch_service_tool_listing`` and the builtin-service listing (``api/catalog_tools.py``) both see it (issue #238 B.7).

    A bare ``(name, description)`` pair used to be all either path kept, so
    ``/v1/catalog``'s per-service tool listing could never show a read/write
    badge even once a backend declared one, and a client comparing
    ``GET /v1/catalog/{service}/tools`` against a real ``tools/list`` saw
    less than the latter carries. ``annotations`` is forwarded verbatim (or
    ``None`` if the tool declared none); ``has_output_schema`` is a bare
    presence flag, not the schema itself -- the payload stays light, schemas
    belong to the MCP client.
    """

    name: str
    description: str
    annotations: ToolAnnotations | None
    has_output_schema: bool


async def fetch_service_tool_listing(
    spec: ServiceSpec,
    headers: dict[str, str] | None,
    skip_reason: str | None,
) -> tuple[str, list[ToolListingEntry]]:
    """Connect to *spec* once and list its tools.

    *headers*/*skip_reason* come from ``resolve_list_time_credential``.
    Returns ``(status, tools)``: status is "ok" or a ``_classify_failure``
    reason ("not_linked" | "unauthorized" | "unavailable"), and tools are
    ``ToolListingEntry``s with ``ServiceSpec.apply_namespace`` already
    applied to the name -- the names a caller actually sees through /mcp.
    ``spec.exclude_tools`` (native names, issue #173) is filtered out here
    too, so this listing can never show a tool a real ``tools/list`` through
    /mcp hides. Deliberately built on ``_build_client`` (same transport
    choice, per-call timeout, and notification handlers as the aggregator's
    own factories) rather than a second HTTP code path.
    """
    transport_cls = SSETransport if spec.transport == "sse" else StreamableHttpTransport
    client = _build_client(spec, transport_cls, headers=headers)
    try:
        async with client:
            tools = await client.list_tools()
    except Exception as exc:  # noqa: BLE001
        reason = _classify_failure(exc, injected=bool(headers), skip_reason=skip_reason)
        return reason, []
    return "ok", [
        ToolListingEntry(
            name=namespaced_tool_name(spec, tool.name),
            description=tool.description or "",
            annotations=tool.annotations,
            has_output_schema=tool.output_schema is not None,
        )
        for tool in tools
        if tool.name not in spec.exclude_tools
    ]


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
    provider: CredentialProvider, settings: Settings, alias: str | None
) -> ToolError:
    """Build the "identity not linked" ``ToolError``.

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
    """
    url = _identity_link_url(settings, alias)
    if alias is None:
        link_hint = f"`{LINK_IDENTITY_TOOL_NAME}`"
    else:
        link_hint = f'`{LINK_IDENTITY_TOOL_NAME}` (provider="{alias}")'
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
    not_linked = _not_linked_error(provider, settings, alias)

    ctx = get_context()
    if not _client_supports_elicitation(ctx):
        raise not_linked

    display_name = _identity_display_name(provider, alias, identity_provider_configs)
    url = _identity_link_url(settings, alias)
    try:
        result = await ctx.elicit(
            f"You need to link {display_name} before I can do this. Visit "
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
    wrapper unconditionally sets that flag to True for HTTP/SSE transports
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

    For "x509" (and "krb5", identically), the answer is still to do nothing
    extra: raising the not-yet-supported error during a listing would be
    both wasteful (every session's first list would eat it) and wrong (a
    listing shouldn't itself hard-fail), so absent the authorized-call
    signal the factory just connects without a credential, same as a "none"
    service -- unchanged.

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
    "wasteful" no longer applies. A failure to mint (no linked identity, no
    provider configured, a mint error) does NOT prevent the connection
    attempt, unlike the authorized tools/call path below -- see
    ``_resolve_list_time_headers``'s docstring for why raising there instead
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
    transport_cls = SSETransport if spec.transport == "sse" else StreamableHttpTransport

    if spec.auth_type == "none":

        def _none_factory() -> Client:
            return _build_client(spec, transport_cls)

        return _none_factory

    if spec.auth_type == "x509":

        async def _x509_factory() -> Client:
            ctx = get_context()
            if await ctx.get_state("authorized_call_target") != spec.name:
                # tools/list (or a stale-cache refresh): best-effort identity
                # header, mirroring the bearer branch -- but minting is a
                # local signature, so there is no network to fail and no
                # skip_reason machinery to thread through.
                principal = await ctx.get_state("principal")
                if principal is None or broker_token_issuer is None:
                    return _build_client(spec, transport_cls)
                if not _might_be_entitled(principal, spec, policy):
                    return _build_client(spec, transport_cls)
                token, _ = broker_token_issuer.mint(
                    principal.subject, spec.effective_audience
                )
                await ctx.set_state(
                    f"__list_credential_status__:{spec.name}",
                    (True, None),
                    serializable=False,
                )
                return _build_client(
                    spec, transport_cls, headers={"Authorization": f"Bearer {token}"}
                )

            principal = await ctx.get_state("principal")
            if principal is None:
                raise ToolError(
                    "No authenticated principal available for this tool call"
                )
            if broker_token_issuer is None:
                raise ToolError(
                    f"Service '{spec.name}' is an x509 service, which needs the "
                    "broker to sign AF Broker Identity Tokens, but no signing key "
                    "is configured (chart: broker.identityToken."
                    "existingSigningKeySecret)."
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
            token, _ = broker_token_issuer.mint(
                principal.subject, spec.effective_audience
            )
            return _build_client(
                spec, transport_cls, headers={"Authorization": f"Bearer {token}"}
            )

        return _x509_factory

    if spec.auth_type == "krb5":

        async def _krb5_factory() -> Client:
            ctx = get_context()
            if await ctx.get_state("authorized_call_target") != spec.name:
                # tools/list (or a stale-cache refresh): best-effort identity
                # header, mirroring the bearer branch -- but minting is a
                # local signature, so there is no network to fail and no
                # skip_reason machinery to thread through.
                principal = await ctx.get_state("principal")
                if principal is None or broker_token_issuer is None:
                    return _build_client(spec, transport_cls)
                if not _might_be_entitled(principal, spec, policy):
                    return _build_client(spec, transport_cls)
                token, _ = broker_token_issuer.mint(
                    principal.subject, spec.effective_audience
                )
                await ctx.set_state(
                    f"__list_credential_status__:{spec.name}",
                    (True, None),
                    serializable=False,
                )
                return _build_client(
                    spec, transport_cls, headers={"Authorization": f"Bearer {token}"}
                )

            principal = await ctx.get_state("principal")
            if principal is None:
                raise ToolError(
                    "No authenticated principal available for this tool call"
                )
            if broker_token_issuer is None:
                raise ToolError(
                    f"Service '{spec.name}' is a krb5 service, which needs the "
                    "broker to sign AF Broker Identity Tokens, but no signing key "
                    "is configured (chart: broker.identityToken."
                    "existingSigningKeySecret)."
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
            token, _ = broker_token_issuer.mint(
                principal.subject, spec.effective_audience
            )
            return _build_client(
                spec, transport_cls, headers={"Authorization": f"Bearer {token}"}
            )

        return _krb5_factory

    if spec.auth_type == "servicex":

        async def _servicex_factory() -> Client:
            ctx = get_context()
            if await ctx.get_state("authorized_call_target") != spec.name:
                # tools/list (or a stale-cache refresh): best-effort identity
                # header, mirroring the krb5/x509 branches -- but minting is
                # a local signature, so there is no network to fail and no
                # skip_reason machinery to thread through.
                principal = await ctx.get_state("principal")
                if principal is None or broker_token_issuer is None:
                    return _build_client(spec, transport_cls)
                if not _might_be_entitled(principal, spec, policy):
                    return _build_client(spec, transport_cls)
                token, _ = broker_token_issuer.mint(
                    principal.subject, spec.effective_audience
                )
                await ctx.set_state(
                    f"__list_credential_status__:{spec.name}",
                    (True, None),
                    serializable=False,
                )
                return _build_client(
                    spec, transport_cls, headers={"Authorization": f"Bearer {token}"}
                )

            principal = await ctx.get_state("principal")
            if principal is None:
                raise ToolError(
                    "No authenticated principal available for this tool call"
                )
            if broker_token_issuer is None:
                raise ToolError(
                    f"Service '{spec.name}' is a servicex service, which needs "
                    "the broker to sign AF Broker Identity Tokens, but no "
                    "signing key is configured (chart: broker.identityToken."
                    "existingSigningKeySecret)."
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
            token, _ = broker_token_issuer.mint(
                principal.subject, spec.effective_audience
            )
            return _build_client(
                spec, transport_cls, headers={"Authorization": f"Bearer {token}"}
            )

        return _servicex_factory

    async def _bearer_factory() -> Client:
        ctx = get_context()
        if await ctx.get_state("authorized_call_target") != spec.name:
            # Not an authorized tools/call for this service -- most commonly
            # a tools/list request (or a stale-cache _get_tool() refresh
            # triggered by one). See the docstring above for why a
            # best-effort mint is attempted here rather than skipped
            # outright, and _resolve_list_time_headers for the non-fatal
            # failure handling this requires.
            principal = await ctx.get_state("principal")
            if principal is None:
                # identity_mw should always have set this by now; there is
                # no principal to mint a credential for either way.
                return _build_client(spec, transport_cls)

            # Same permission gate AuthorizationMiddleware applies to an
            # actual call -- a caller who could never pass it shouldn't
            # trigger a mint attempt at all; EntitlementMiddleware already
            # hides this service's tools from such a caller's own tools/list
            # response, so this is just avoiding wasted work, not a security
            # boundary of its own.
            if not _might_be_entitled(principal, spec, policy):
                return _build_client(spec, transport_cls)

            headers, skip_reason = await _resolve_list_time_headers(
                spec, credential_registry, principal
            )
            # Keyed per service (not a single shared key) since one
            # tools/list request fans out to every service's factory
            # concurrently -- see _classify_list_failure's use of this.
            await ctx.set_state(
                f"__list_credential_status__:{spec.name}",
                (headers is not None, skip_reason),
                serializable=False,
            )
            return _build_client(spec, transport_cls, headers=headers or {})

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
        except NeedsUnlock as exc:
            portal = settings.portal_url.rstrip("/")
            raise ToolError(
                f"Credential unlock required. Visit the portal: "
                f"{portal}{exc.unlock_endpoint}"
            ) from exc
        except HTTPException as exc:
            # OIDCProvider.issue() raises HTTPException directly (401 session
            # expired, 404 no stored token) rather than NeedsUnlock -- surface
            # its detail the same way FastAPI's own handler would at /v1.
            raise ToolError(str(exc.detail)) from exc

        call_headers: dict[str, str] = {}
        if cred.kind == CredentialKind.BEARER:
            token = cred.payload.get("access_token")
            if token:
                call_headers["Authorization"] = f"Bearer {token}"
        return _build_client(spec, transport_cls, headers=call_headers)

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


class _ObservableProxyProvider(ProxyProvider):
    """ProxyProvider that structured-logs a classified reason when its ``tools/list`` fails, then re-raises so ``AggregateProvider``'s existing ``provider_error_strategy="warn"`` still drops this service's contribution and keeps every other service's listing unaffected -- exactly today's degrade-gracefully behavior, just with an ``aggregator.service_list_failed`` structlog event on record instead of only fastmcp's own unparseable stdlib WARNING (see issue #121).

    Overrides only the private ``_list_tools()`` extension hook that
    ``fastmcp.server.providers.proxy.ProxyProvider`` (pinned at 3.4.4, see
    pixi.lock) itself documents as a subclassing point -- but it's still
    third-party internals, not a public contract fastmcp guarantees stable.
    If ``_list_tools()``'s signature, its call sites (``_get_tool()``'s
    stale-cache refresh in particular -- see ``_resolve_list_time_headers``'s
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
    ) -> None:
        super().__init__(client_factory, cache_ttl=cache_ttl)
        self._service_name = service_name
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
        return await super()._get_tool(name, version)

    def invalidate_subject(self, subject: str) -> None:
        """Drop *subject*'s cached listing entries (success or failure), for every kind (tools, resources, resource templates, prompts), for this service.

        Called when *subject*'s linked identity changes -- see
        ``invalidate_subject_cache`` (module-level, below) for the wiring
        across every provider on a link/unlink/credential-revocation event. A
        subject with nothing cached is a silent no-op. Leaves
        ``_subject_list_locks`` alone: an in-flight refresh for *subject* (if
        any) is unaffected, and the next cache miss just creates a fresh lock.
        """
        stale = [key for key in self._subject_list_cache if key[1] == subject]
        for key in stale:
            del self._subject_list_cache[key]

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
        assert entry.items is not None  # invariant: exactly one of items/error is set
        return entry.items

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
            tools = await super()._list_tools()
        except Exception as exc:
            reason, detail = await _classify_list_failure(exc, self._service_name)
            self._registry.record_list_failure(self._service_name, reason)
            logger.warning(
                "aggregator.service_list_failed",
                service=self._service_name,
                reason=reason,
                error=detail,
            )
            raise
        else:
            # A successful listing means the service has recovered from any
            # previously recorded failure -- clear it so /v1/catalog and
            # af_list_mcp_servers stop reporting "unavailable" for a service
            # that's actually fine again.
            self._registry.clear_list_failure(self._service_name)
            if self._route_prefix is not None:
                # A listed tool that doesn't match the route prefix would be
                # visible in tools/list but unreachable via _get_tool's
                # short-circuit above -- warn rather than filter, so the
                # mismatch is on record instead of silently dead on arrival.
                prefix = f"{self._route_prefix}_"
                for tool in tools:
                    if not tool.name.startswith(prefix):
                        logger.warning(
                            "aggregator.tool_prefix_mismatch",
                            service=self._service_name,
                            tool=tool.name,
                            prefix=self._route_prefix,
                        )
            if self._exclude_tools:
                self._warn_on_missing_exclude_tools(tools)
                tools = [t for t in tools if t.name not in self._exclude_tools]
            return tools

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


def invalidate_subject_cache(
    mcp: FastMCP, subject: str, target: str | None = None
) -> None:
    """Drop *subject*'s cached listing entries (every kind: tools, resources, resource templates, prompts) across ``mcp``'s providers -- one service (*target*) or every service.

    Called wherever a subject's linked identity changes (unlink, or a
    credential revocation -- see app.py's ``CredentialCache`` construction)
    so a stale per-subject listing (``_ObservableProxyProvider.invalidate_subject``)
    is never served past that change. *target* narrows to the one
    ``ServiceSpec.name`` affected; omitted, every service's cache entry for
    *subject* is dropped.
    """
    for provider in mcp.providers:
        if isinstance(provider, _ObservableProxyProvider) and (
            target is None or provider._service_name == target
        ):
            provider.invalidate_subject(subject)


def build_aggregator(
    registry: ServiceRegistry,
    settings: Settings,
    policy: EntitlementPolicy,
    credential_registry: CredentialRegistry,
    revoked_jti_cache: RevokedJtiCache | None = None,
    pat_backend: TokenRegistryBackend | None = None,
    principal_cache: PrincipalCache | None = None,
    identity_providers: dict[str, CredentialProvider] | None = None,
    identity_provider_configs: dict[str, IdentityProviderConfig] | None = None,
    target_to_alias: dict[str, str] | None = None,
    broker_token_issuer: BrokerTokenIssuer | None = None,
    maintenance_mode_store: MaintenanceModeStore | None = None,
) -> FastMCP:
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

    *revoked_jti_cache*/*pat_backend*/*principal_cache* default to None here
    because app.py builds the aggregator eagerly, before the real token
    registry/principal cache exist (see the module-level comment above
    ``_mcp_aggregator``) -- ``populate_aggregator`` pushes the real ones in
    once the lifespan has them, same as settings/policy. *pat_backend*/
    *principal_cache* being None means identity PATs are recognized by prefix
    on ``/mcp`` but always rejected (see ``mcp/middleware/identity_mw.py``'s
    ``AsgiAuthMiddleware``) -- a broker with no Keycloak admin service
    account configured (issue #144 step 2a). *identity_providers*/
    *identity_provider_configs*/*target_to_alias* default to empty for the
    same eager-build reason -- af_list_identities/af_list_mcp_servers simply
    report nothing until ``populate_aggregator`` supplies the real ones.
    """
    # instructions is the model-facing "dual enforcement" layer (finding #6):
    # a platform preamble plus each service's agent_policy, surfaced to clients
    # in the MCP initialize response. Composed here from whatever registry is
    # available at construction -- the eager module-scope build starts with an
    # empty registry (see app.py), so populate_aggregator recomposes below once
    # the real registry is loaded, mirroring how settings/policy get pushed in.
    mcp = FastMCP(
        name="af-mcp-aggregator",
        instructions=compose_agent_instructions(registry),
    )
    mcp.add_middleware(
        IdentityMiddleware(
            settings,
            revoked_jti_cache,
            pat_backend,
            principal_cache,
            maintenance_mode_store,
        )
    )
    mcp.add_middleware(EntitlementMiddleware(registry, policy))
    mcp.add_middleware(AuthorizationMiddleware(registry, policy))
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
    )
    return mcp


def build_asgi_auth_middleware(mcp: FastMCP) -> Middleware:
    """Return the Starlette middleware spec that enforces identity at the ASGI layer.

    Enforces identity for ``mcp``'s http_app (issue #138/#144 step 1) -- pass
    this into ``FastMCP.http_app(middleware=[...])`` when mounting.

    Must be built from the same FastMCP instance ``build_aggregator()``
    constructed: it shares that instance's IdentityMiddleware (found via
    ``_find_middleware``), which is the single mutable settings/
    revoked_jti_cache handle ``populate_aggregator()`` keeps up to date --
    see ``identity_mw.AsgiAuthMiddleware``'s docstring for why sharing it
    rather than holding a second copy matters.
    """
    identity_mw, _, _ = _find_middleware(mcp)
    return Middleware(AsgiAuthMiddleware, identity_mw=identity_mw)


def populate_aggregator(
    mcp: FastMCP,
    registry: ServiceRegistry,
    settings: Settings,
    policy: EntitlementPolicy,
    credential_registry: CredentialRegistry,
    revoked_jti_cache: RevokedJtiCache | None = None,
    pat_backend: TokenRegistryBackend | None = None,
    principal_cache: PrincipalCache | None = None,
    identity_providers: dict[str, CredentialProvider] | None = None,
    identity_provider_configs: dict[str, IdentityProviderConfig] | None = None,
    target_to_alias: dict[str, str] | None = None,
    broker_token_issuer: BrokerTokenIssuer | None = None,
    maintenance_mode_store: MaintenanceModeStore | None = None,
) -> None:
    """Refresh an aggregator built by ``build_aggregator`` with a freshly loaded registry/settings/policy/credential_registry/revoked_jti_cache/pat_backend/principal_cache/identity_providers/identity_provider_configs/target_to_alias/maintenance_mode_store.

    app.py's mount-time constraint means the aggregator's FastMCP instance
    and ASGI app must exist before SERVICES_FILE/POLICY_FILE/the credential
    subsystem are loaded (they are only read inside the async lifespan);
    this function is how the lifespan pushes the real values into the
    already-mounted instance. Safe to call more than once per process (every
    lifespan entry, including repeated TestClient entries in tests): service
    providers are replaced wholesale rather than appended to, mirroring how
    ServiceRegistry and EntitlementPolicy are themselves rebuilt from scratch
    on every lifespan entry rather than merged -- the af_* diagnostic tools
    (register_diagnostic_tools) follow the same rebuild-from-scratch pattern.
    """
    identity_mw, entitlement_mw, authorization_mw = _find_middleware(mcp)
    # Recompose the model-facing instructions from the real registry: the eager
    # build (app.py) constructed mcp with an empty registry, so its instructions
    # omitted every operator service's agent_policy until now (finding #6).
    mcp.instructions = compose_agent_instructions(registry)
    identity_mw.settings = settings
    identity_mw.revoked_jti_cache = revoked_jti_cache
    identity_mw.pat_backend = pat_backend
    identity_mw.principal_cache = principal_cache
    identity_mw.maintenance_mode_store = maintenance_mode_store
    entitlement_mw.registry = registry
    entitlement_mw.policy = policy
    authorization_mw.registry = registry
    authorization_mw.policy = policy
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
    )


def _register_services(
    mcp: FastMCP,
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
    # dispatch after every build_aggregator()/populate_aggregator() call,
    # not just the first. Re-adding the same object is safe to repeat on
    # every call: it carries no per-call state of its own, and the list was
    # just cleared, so this never produces a duplicate entry.
    mcp.add_provider(mcp.local_provider)
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
        )
        namespace = spec.prefix if spec.apply_namespace else ""
        mcp.add_provider(provider, namespace=namespace)


def _find_middleware(
    mcp: FastMCP,
) -> tuple[IdentityMiddleware, EntitlementMiddleware, AuthorizationMiddleware]:
    identity_mw: IdentityMiddleware | None = None
    entitlement_mw: EntitlementMiddleware | None = None
    authorization_mw: AuthorizationMiddleware | None = None
    for mw in mcp.middleware:
        if isinstance(mw, IdentityMiddleware):
            identity_mw = mw
        elif isinstance(mw, EntitlementMiddleware):
            entitlement_mw = mw
        elif isinstance(mw, AuthorizationMiddleware):
            authorization_mw = mw
    if identity_mw is None or entitlement_mw is None or authorization_mw is None:
        raise RuntimeError(
            "aggregator is missing IdentityMiddleware/EntitlementMiddleware/"
            "AuthorizationMiddleware -- was it built by build_aggregator()?"
        )
    return identity_mw, entitlement_mw, authorization_mw
