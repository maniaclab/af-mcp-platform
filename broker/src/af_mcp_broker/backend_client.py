from __future__ import annotations

# Client-side access to a backend MCP service on behalf of a caller: building
# the fastmcp client (transport, timeouts, 401/invalid-response hooks),
# resolving the per-user credential a list-time connection carries, and
# listing one service's tools. Shared by the aggregator (mcp/aggregator.py,
# which lists and proxies every service for /mcp) and the /v1 per-service tool
# listing (api/catalog_tools.py), so both always see a backend the same way.
import json
import time
from typing import TYPE_CHECKING, Any, NamedTuple

import httpx2
import structlog
from fastmcp.client import Client
from fastmcp.client.transports import StreamableHttpTransport
from fastmcp.client.transports.base import TransportOptions
from fastmcp.server.providers.proxy import (
    default_proxy_log_handler,
    default_proxy_progress_handler,
)
from mcp.client.session import ClientSession

from af_mcp_broker.backend_errors import (
    BackendInvalidResponseError,
    NotLinkedForListingError,
)
from af_mcp_broker.credentials import CredentialKind
from af_mcp_broker.credentials.errors import CredentialError, NeedsUnlockError
from af_mcp_broker.logging import current_request_id, request_id_headers
from af_mcp_broker.service_registry import namespaced_tool_name

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Iterator

    from mcp.types import CallToolResult, ToolAnnotations

    from af_mcp_broker.credentials import (
        CredentialProvider,
        CredentialRegistry,
        IssuedCredential,
    )
    from af_mcp_broker.credentials.broker_issued import BrokerTokenIssuer
    from af_mcp_broker.principal import Principal
    from af_mcp_broker.service_registry import ServiceSpec

logger = structlog.get_logger(__name__)


# mcp SDK v2's streamable-HTTP client normalizes ANY non-2xx response whose
# body isn't already JSON-RPC-shaped into a generic MCPError(INTERNAL_ERROR),
# delivered as a JSON-RPC error reply on the read stream -- never raised as an
# httpx2-family exception (mcp/client/streamable_http.py's
# _handle_request_response, the `response.status_code >= 400` branch). The
# real HTTP status code is otherwise unrecoverable by the time classify_failure
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


def report_401(
    on_unauthorized: Callable[[], Awaitable[None]],
) -> Callable[[httpx2.Response], Awaitable[None]]:
    """Response hook that calls *on_unauthorized* when the backend answers 401 (issue #344).

    Installed only on a client carrying an injected per-user credential, so
    a 401 here means the backend rejected exactly that credential. It runs
    ahead of ``_raise_for_401`` and never raises itself: a failed report is
    logged, and the 401 still propagates unchanged.
    """

    async def _hook(response: httpx2.Response) -> None:
        if response.status_code != 401:
            return
        try:
            await on_unauthorized()
        except Exception as exc:  # noqa: BLE001
            logger.warning("aggregator.mark_rejected_failed", error=str(exc))

    return _hook


async def _stamp_request_id(request: httpx2.Request) -> None:
    """Send the broker's own ``request_id`` to the backend as ``X-Request-ID``.

    Read when the request is sent, from the contextvars of the call that
    sends it, so the id is the one the broker logged for that client request.
    Replaces any ``X-Request-ID`` already on the request: the broker's id is
    the only one a backend may log. A request sent outside any client
    request has no id to send.
    """
    request.headers.update(request_id_headers())


def unauthorized_raising_httpx_client_factory(
    headers: dict[str, str] | None = None,
    timeout: httpx2.Timeout | None = None,
    auth: httpx2.Auth | None = None,
    *,
    on_unauthorized: Callable[[], Awaitable[None]] | None = None,
    **kwargs: Any,
) -> httpx2.AsyncClient:
    """``McpHttpClientFactory`` that adds ``_raise_for_401`` to the client's response hooks.

    With *on_unauthorized*, also adds ``report_401`` ahead of it.

    Mirrors ``mcp.shared._httpx_utils.create_mcp_http_client``'s defaults
    (30s connect/write/pool, 300s read, for a backend that holds a response
    stream open) rather than importing that private module directly.
    ``**kwargs`` absorbs ``follow_redirects`` (passed by both
    ``StreamableHttpTransport``'s ``connect_session``, but not part of the
    documented factory signature -- see its ``httpx_client_factory``
    docstring recommending ``**kwargs`` for exactly this forward-compatibility
    reason).
    """
    if timeout is None:
        timeout = httpx2.Timeout(30.0, read=300.0)
    client_kwargs: dict[str, Any] = {"timeout": timeout, **kwargs}
    if headers is not None:
        client_kwargs["headers"] = headers
    if auth is not None:
        client_kwargs["auth"] = auth
    client = httpx2.AsyncClient(**client_kwargs)
    client.event_hooks.setdefault("request", []).append(_stamp_request_id)
    response_hooks = client.event_hooks.setdefault("response", [])
    if on_unauthorized is not None:
        response_hooks.append(report_401(on_unauthorized))
    response_hooks.append(_raise_for_401)
    return client


def _is_jsonrpc_request(request: httpx2.Request) -> bool:
    """Whether *request*'s body is a JSON-RPC request (it carries an ``id``), as opposed to a notification that a server may answer with an empty body."""
    try:
        body = json.loads(request.content)
    except (httpx2.RequestNotRead, ValueError):
        return False
    return isinstance(body, dict) and "id" in body


def _raise_for_invalid_response(
    service_name: str,
) -> Callable[[httpx2.Response], Awaitable[None]]:
    """Build a response hook raising ``BackendInvalidResponseError`` for a 200 reply to a JSON-RPC request that is neither an SSE stream nor a JSON document.

    Same layer and reasoning as ``_raise_for_401`` above: the mcp SDK turns
    such a reply into a generic parse-error ``MCPError`` whose text embeds a
    prefix of the backend's body, and the HTTP status and content type are
    gone by the time the broker sees it. Checking here keeps them, fails the
    request as soon as the response arrives, and lets the broker name the
    service. Only a syntactically valid JSON document is required of a
    ``application/json`` reply; the SDK still validates its JSON-RPC shape.
    A reply to a notification (no ``id``) is never inspected.
    """

    async def hook(response: httpx2.Response) -> None:
        request = response.request
        if (
            request.method != "POST"
            or response.status_code != 200
            or not _is_jsonrpc_request(request)
        ):
            return
        content_type = response.headers.get("content-type", "").lower()
        if content_type.startswith("text/event-stream"):
            return
        problem = "unexpected content type"
        if content_type.startswith("application/json"):
            await response.aread()
            try:
                json.loads(response.content)
            except ValueError:
                problem = "body is not valid JSON"
            else:
                return
        media_type = content_type.split(";")[0][:100]
        logger.warning(
            "aggregator.backend_invalid_response",
            service=service_name,
            status_code=response.status_code,
            content_type=media_type,
            problem=problem,
        )
        raise BackendInvalidResponseError(
            f"Service '{service_name}' returned an invalid response "
            f"(HTTP {response.status_code}, content-type "
            f"{media_type or 'missing'}): {problem}."
        )

    return hook


def _checked_httpx_client_factory(
    service_name: str,
    on_unauthorized: Callable[[], Awaitable[None]] | None = None,
) -> Callable[..., httpx2.AsyncClient]:
    """``McpHttpClientFactory`` for *service_name*: ``unauthorized_raising_httpx_client_factory`` (given *on_unauthorized*) plus the invalid-response check."""

    def factory(
        headers: dict[str, str] | None = None,
        timeout: httpx2.Timeout | None = None,
        auth: httpx2.Auth | None = None,
        **kwargs: Any,
    ) -> httpx2.AsyncClient:
        client = unauthorized_raising_httpx_client_factory(
            headers=headers,
            timeout=timeout,
            auth=auth,
            on_unauthorized=on_unauthorized,
            **kwargs,
        )
        client.event_hooks["response"].append(_raise_for_invalid_response(service_name))
        return client

    return factory


class RelayingClientSession(ClientSession):
    """A ``ClientSession`` that relays a tool result without validating it against the tool's output schema.

    ``ClientSession.call_tool`` learns the output schema by listing the
    backend's tools -- a full extra ``tools/list`` round trip on every call --
    and raises if the structured content disagrees with it. The aggregator
    skips that listing and validates against the schema it already holds
    instead (``OutputSchemaMiddleware`` in mcp/middleware/output_schema_mw.py).
    This is the same session fastmcp's own proxy uses for its backend
    connections (``fastmcp.server.providers.proxy._ForwardingClientSession``,
    private in fastmcp 4.0.4), re-declared here against the public
    ``ClientSession.validate_tool_result`` hook.
    """

    async def validate_tool_result(
        self,
        name: str,  # noqa: ARG002 -- signature fixed by the override
        result: CallToolResult,  # noqa: ARG002 -- signature fixed by the override
    ) -> None:
        return None


class BackendClient(Client):
    """The ``Client`` for one backend connection: relays results and never forwards the caller's headers.

    ``fastmcp.Client`` exposes no public way to choose its session class, so
    ``_transport_options`` (fastmcp 4.0.4; the attribute ``ProxyClient`` itself
    sets) is the single place it is set, to ``RelayingClientSession`` only.
    ``forward_incoming_headers`` stays at ``TransportOptions``'s default of
    False: ``ProxyClient`` turns it on, which is why it is not used here (see
    ``_make_client_factory`` in mcp/aggregator.py).
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._transport_options = TransportOptions(session_class=RelayingClientSession)


def build_client(
    spec: ServiceSpec,
    headers: dict[str, str] | None = None,
    on_unauthorized: Callable[[], Awaitable[None]] | None = None,
) -> Client:
    """Construct the plain (never ProxyClient) Client every branch of _make_client_factory returns.

    Applies the service's configured per-call read timeout (ServiceSpec.
    timeout_seconds) so a slow/unresponsive service fails that one call
    cleanly instead of hanging the aggregator, and installs the same
    progress/log *notification* forwarding handlers fastmcp's ProxyClient
    installs by default -- ProxyClient itself is still not used (see
    _make_client_factory's docstring: its unconditional
    forward_incoming_headers=True for HTTP clients is the one behavior
    deliberately avoided here), but that has nothing to do with
    these two handlers, which only relay already-decided-safe notification
    content from the service to the aggregator's own caller, never inbound
    credentials.

    *on_unauthorized* comes from ``bearer_injection`` alongside *headers*:
    it reports a backend 401 for the injected credential (issue #344).

    The same ``timeout_seconds`` also bounds the initialize handshake
    (``init_timeout``, otherwise unbounded), which is how long a backend that
    accepts the connection but never speaks would hold the caller (issue
    #386).
    """
    return BackendClient(
        StreamableHttpTransport(
            spec.url,
            headers=headers,
            httpx_client_factory=_checked_httpx_client_factory(
                spec.name, on_unauthorized
            ),
        ),
        timeout=spec.timeout_seconds,
        init_timeout=spec.timeout_seconds,
        progress_handler=default_proxy_progress_handler,
        log_handler=default_proxy_log_handler,
    )


class ListTimeCredential(NamedTuple):
    """What a list-time connection should carry, and why it carries nothing.

    ``headers``/``skip_reason`` as documented on ``resolve_list_time_headers``;
    ``on_unauthorized`` is set only when a per-user bearer credential was
    injected, and goes to ``build_client`` with ``headers``.
    """

    headers: dict[str, str] | None
    skip_reason: str | None
    on_unauthorized: Callable[[], Awaitable[None]] | None = None


def bearer_injection(
    provider: CredentialProvider, principal: Principal, cred: IssuedCredential
) -> tuple[dict[str, str], Callable[[], Awaitable[None]] | None]:
    """Headers injecting *cred* for a backend request, plus its 401 report (issue #344).

    The report is bound to this exact access token, so a 401 can only ever
    reject the token that was actually sent (see ``mark_rejected``). Both
    are empty when *cred* carries no bearer token.
    """
    token = (
        cred.payload.get("access_token") if cred.kind == CredentialKind.BEARER else None
    )
    if not token:
        return {}, None

    async def _mark_rejected() -> None:
        await provider.mark_rejected(principal, token)

    return {"Authorization": f"Bearer {token}"}, _mark_rejected


async def resolve_list_time_headers(
    spec: ServiceSpec,
    credential_registry: CredentialRegistry,
    principal: Principal,
) -> ListTimeCredential:
    """Best-effort per-user credential mint for a bearer service's tools/list-time connection.

    Returns a ``ListTimeCredential`` (``headers``, ``skip_reason``, and the
    injected credential's ``on_unauthorized`` report). A caller who has not
    linked the credential raises ``NotLinkedForListingError`` before anything is
    minted, so the backend is never contacted and the service contributes no
    tools to that caller's list, as for x509/krb5/servicex.

    Every other failure is non-fatal: unlike the authorized tools/call path
    in ``_bearer_factory``, a provider that does not resolve, or a mint that
    fails for an operational reason, must not prevent the connection attempt
    outright -- doing so would mean this service's ``ProxyProvider`` never
    completes a single successful ``_list_tools()`` call for a caller whose
    mint failed, which (a) would leave its component-list cache permanently
    unpopulated (fastmcp's ``ProxyProvider`` only writes that cache after a
    call that didn't raise), forcing every later ``_get_tool()`` cache-miss
    lookup -- including ones for a *different*, perfectly authorized caller
    -- to re-trigger a listing, and (b) a listing failure raised from there
    is swallowed by ``AggregateProvider._get_tool()``'s own warn-and-continue
    handling into a bare "Unknown tool", losing the friendly authorized-path
    ``ToolError`` entirely. Connecting without a credential instead
    reproduces exactly what a "none" service does: a service that itself
    gates listing on auth (rucio-mcp) still ends up excluded via its own 401
    -- classified and logged by ``_ObservableProxyProvider`` below.

    ``skip_reason`` (``"unavailable"``) is set whenever ``headers`` is
    ``None``, letting the caller pre-record *why* no credential was attached
    (see the per-service request-scoped state in ``_bearer_factory``) for
    ``_classify_list_failure`` to use if the resulting uncredentialed
    connection does go on to fail.
    """
    try:
        provider = await credential_registry.resolve(spec.name)
    except KeyError:
        return ListTimeCredential(None, "unavailable")

    await _raise_unless_linked_to_list(spec, provider, principal)

    try:
        cred = await provider.issue(principal, spec.name)
    except (NeedsUnlockError, CredentialError):
        return ListTimeCredential(None, "unavailable")

    headers, on_unauthorized = bearer_injection(provider, principal, cred)
    return ListTimeCredential(headers, None, on_unauthorized)


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


def classify_failure(exc: Exception, *, injected: bool, skip_reason: str | None) -> str:
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
    longer a ``classify_failure`` outcome, which makes
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
    read stream, discarding the real status code. ``build_client``'s
    ``unauthorized_raising_httpx_client_factory`` forces a 401 specifically
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


async def _raise_unless_linked_to_list(
    spec: ServiceSpec, provider: CredentialProvider, principal: Principal
) -> None:
    """Raise ``NotLinkedForListingError`` unless *principal* has linked the credential *provider* issues for *spec*."""
    if await provider.is_linked(principal):
        return
    rejected = await provider.is_rejected(principal)
    raise NotLinkedForListingError(
        f"Service '{spec.name}' lists its tools only for callers who have "
        "linked their credential"
        + (" (the linked credential was rejected)." if rejected else "."),
        rejected=rejected,
    )


async def require_linked_to_list(
    spec: ServiceSpec, credential_registry: CredentialRegistry, principal: Principal
) -> None:
    """Raise ``NotLinkedForListingError`` unless *principal* has linked the credential *spec* (x509/krb5/servicex) redeems.

    A provider that doesn't resolve is a platform misconfiguration reported
    elsewhere, so it does not block the listing here.
    """
    try:
        provider = await credential_registry.resolve(spec.name)
    except KeyError:
        return
    await _raise_unless_linked_to_list(spec, provider, principal)


def require_signing_issuer(
    spec: ServiceSpec, broker_token_issuer: BrokerTokenIssuer | None
) -> BrokerTokenIssuer:
    """Return the broker's signing issuer for an x509/krb5/servicex *spec*, which authenticates its backend with an AF Broker Identity Token.

    Boot validation guarantees the issuer for every such service: each is
    covered by an entry whose provider needs the signing key, and a
    deployment with such an entry and no key refuses to start. A missing
    issuer here is therefore a wiring bug in the caller, not a deployment
    state, and is reported as one.
    """
    if broker_token_issuer is None:
        msg = (
            f"Service '{spec.name}' (auth_type: {spec.auth_type}) needs the "
            "broker's signing key to mint AF Broker Identity Tokens, but no "
            "BrokerTokenIssuer was supplied."
        )
        raise RuntimeError(msg)
    return broker_token_issuer


async def resolve_list_time_credential(
    spec: ServiceSpec,
    credential_registry: CredentialRegistry,
    principal: Principal,
    broker_token_issuer: BrokerTokenIssuer | None = None,
) -> ListTimeCredential:
    """Best-effort list-time credential headers for *spec*, any auth_type.

    The /v1 per-service tool listing's (api/catalog_tools.py) entry point
    into the exact same list-time credential logic the aggregator's client
    factories use, so the portal's tool listing can never disagree with what
    a tools/list through /mcp would have injected:

    - "none": no per-user credential concept at all -> ``({}, None)``.
    - "x509"/"krb5"/"servicex": share one code path here -- a locally-signed
      AF Broker Identity Token, mirroring ``_identity_token_factory``'s
      identical list-time
      branches; boot validation guarantees the issuer for these services
      (see ``require_signing_issuer``). The backend redeems the
      actual proxy/ticket/access-token itself via ``POST /v1/credentials/
      x509/redeem``, ``.../krb5/redeem``, or ``.../servicex/redeem``
      respectively; this function must never call ``provider.issue()`` for
      any of the three. A caller who has not linked the credential raises
      ``NotLinkedForListingError`` before anything is minted.
    - "bearer": ``resolve_list_time_headers`` (the issue #121 best-effort
      mint). A caller who has not linked the credential raises
      ``NotLinkedForListingError`` before anything is minted, as for the three
      types above; ``skip_reason`` ("unavailable") is set when a resolved,
      linked caller's mint failed for an operational reason.

    Callers must gate on holding at least one of the service's required
    permissions first (``_might_be_entitled`` here; ``service_status.py``'s
    ``holds_any_required_permission`` for ``api/catalog_tools.py``) -- a
    caller who could never pass it shouldn't trigger a mint attempt at all.
    """
    if spec.auth_type == "none":
        return ListTimeCredential({}, None)
    if spec.auth_type in ("x509", "krb5", "servicex"):
        issuer = require_signing_issuer(spec, broker_token_issuer)
        await require_linked_to_list(spec, credential_registry, principal)
        token, _ = issuer.mint(
            principal.subject,
            spec.effective_audience,
            request_id=current_request_id(),
        )
        return ListTimeCredential({"Authorization": f"Bearer {token}"}, None)
    return await resolve_list_time_headers(spec, credential_registry, principal)


class ToolListingEntry(NamedTuple):
    """One tool as ``fetch_service_tool_listing`` and the builtin-service listing (``api/catalog_tools.py``) both see it (issue #238 B.7).

    A bare ``(name, description)`` pair would leave
    ``/v1/catalog``'s per-service tool listing unable to show a read/write
    badge even when a backend declares one, and a client comparing
    ``GET /v1/catalog/{service}/tools`` against a real ``tools/list`` would
    see less than the latter carries. ``annotations`` is forwarded verbatim (or
    ``None`` if the tool declared none); ``has_output_schema`` is a bare
    presence flag, not the schema itself -- the payload stays light, schemas
    belong to the MCP client.
    """

    name: str
    description: str
    annotations: ToolAnnotations | None
    has_output_schema: bool


class ToolListingCache:
    """In-process TTL cache of successful tool listings, keyed by service.

    Tool schemas aren't user-specific (the same cross-user assumption
    fastmcp's ProxyProvider component cache already relies on -- see
    aggregator.py's _make_client_factory docstring; that cache itself can't
    be reused here because its client factories require an in-flight MCP
    request context), so one process-wide entry per service is safe. The TTL
    is the service's own ``tools_cache_ttl`` -- the same operator knob that
    governs the ProxyProvider cache, and 0 disables caching here too.
    Per-caller decisions (entitlement, linkage) are re-evaluated on every
    request; only the network fan-out is skipped. Each broker replica keeps
    its own copy -- acceptable divergence for a tool *catalog* (worst case a
    just-redeployed service's new tool appears on one replica up to one TTL
    before another), unlike per-caller status data which is never cached.
    """

    def __init__(self) -> None:
        # service name -> (monotonic fetch time, [ToolListingEntry, ...])
        self._entries: dict[str, tuple[float, list[ToolListingEntry]]] = {}

    def get(self, service: str, ttl: float) -> list[ToolListingEntry] | None:
        if ttl <= 0:
            return None
        entry = self._entries.get(service)
        if entry is None:
            return None
        fetched_at, tools = entry
        if time.monotonic() - fetched_at > ttl:
            return None
        return tools

    def put(self, service: str, tools: list[ToolListingEntry]) -> None:
        self._entries[service] = (time.monotonic(), tools)


async def fetch_service_tool_listing(
    spec: ServiceSpec,
    credential: ListTimeCredential,
) -> tuple[str, list[ToolListingEntry]]:
    """Connect to *spec* once and list its tools.

    *credential* comes from ``resolve_list_time_credential``.
    Returns ``(status, tools)``: status is "ok" or a ``classify_failure``
    reason ("not_linked" | "unauthorized" | "unavailable"), and tools are
    ``ToolListingEntry``s with ``ServiceSpec.apply_namespace`` already
    applied to the name -- the names a caller actually sees through /mcp.
    ``spec.exclude_tools`` (native names, issue #173) is filtered out here
    too, so this listing can never show a tool a real ``tools/list`` through
    /mcp hides. Deliberately built on ``build_client`` (same transport,
    per-call timeout, and notification handlers as the aggregator's
    own factories) rather than a second HTTP code path.
    """
    client = build_client(
        spec,
        headers=credential.headers,
        on_unauthorized=credential.on_unauthorized,
    )
    try:
        async with client:
            tools = await client.list_tools()
    except Exception as exc:  # noqa: BLE001
        reason = classify_failure(
            exc,
            injected=bool(credential.headers),
            skip_reason=credential.skip_reason,
        )
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
