from __future__ import annotations

# Aggregator entry point — builds the FastMCP application that proxies tool
# calls to downstream MCP backends after the broker has validated identity,
# applied entitlement filtering, checked authorization, and (for
# auth_type="bearer" backends) minted and injected a per-user credential.
#
# app.py builds an aggregator eagerly (with an empty BackendRegistry) so its
# ASGI app exists at FastAPI-construction time for mounting at /mcp and for
# combining lifespans; app.py's own lifespan then calls populate_aggregator()
# once BACKENDS_FILE/POLICY_FILE/the credential subsystem have actually been
# loaded. The client_factory below deliberately never forwards the caller's
# inbound Authorization header to a backend; see its docstring.
from typing import TYPE_CHECKING

import httpx
import structlog
from fastapi import HTTPException
from fastmcp import FastMCP
from fastmcp.client import Client
from fastmcp.client.transports import SSETransport, StreamableHttpTransport
from fastmcp.exceptions import ToolError
from fastmcp.server.dependencies import get_context
from fastmcp.server.providers.proxy import (
    ClientFactoryT,
    ProxyProvider,
    default_proxy_log_handler,
    default_proxy_progress_handler,
)
from starlette.middleware import Middleware

from af_mcp_broker.authorization import check_entitlement
from af_mcp_broker.credentials import CredentialKind, NeedsUnlock
from af_mcp_broker.mcp.middleware.authorization_mw import AuthorizationMiddleware
from af_mcp_broker.mcp.middleware.entitlement_mw import EntitlementMiddleware
from af_mcp_broker.mcp.middleware.identity_mw import (
    AsgiAuthMiddleware,
    IdentityMiddleware,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

    from fastmcp.tools.base import Tool

    from af_mcp_broker.authorization import EntitlementPolicy
    from af_mcp_broker.config import Settings
    from af_mcp_broker.credentials import CredentialRegistry
    from af_mcp_broker.identity import Principal
    from af_mcp_broker.mcp.registry import BackendRegistry, BackendSpec
    from af_mcp_broker.token_registry import RevokedJtiCache

logger = structlog.get_logger(__name__)


def _build_client(
    spec: BackendSpec,
    transport_cls: type[SSETransport | StreamableHttpTransport],
    headers: dict[str, str] | None = None,
) -> Client:
    """Construct the plain (never ProxyClient) Client every branch of _make_client_factory returns.

    Applies the backend's configured per-call read timeout (BackendSpec.
    timeout_seconds) so a slow/unresponsive backend fails that one call
    cleanly instead of hanging the aggregator, and installs the same
    progress/log *notification* forwarding handlers fastmcp's ProxyClient
    installs by default -- ProxyClient itself is still not used (see
    _make_client_factory's docstring: its unconditional
    forward_incoming_headers=True for HTTP/SSE transports is the one
    behavior deliberately avoided here), but that has nothing to do with
    these two handlers, which only relay already-decided-safe notification
    content from the backend to the aggregator's own caller, never inbound
    credentials.
    """
    return Client(
        transport_cls(spec.url, headers=headers),
        timeout=spec.timeout_seconds,
        progress_handler=default_proxy_progress_handler,
        log_handler=default_proxy_log_handler,
    )


async def _resolve_list_time_headers(
    spec: BackendSpec,
    credential_registry: CredentialRegistry,
    principal: Principal,
) -> tuple[dict[str, str] | None, str | None]:
    """Best-effort per-user credential mint for a tools/list-time connection.

    Returns ``(headers, skip_reason)``. Never raises: unlike the authorized
    tools/call path in ``_bearer_factory``, a failure here must not prevent
    the connection attempt outright -- doing so would mean this backend's
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
    what a "none" backend does: a backend that itself gates listing on auth
    (rucio-mcp) still ends up excluded via its own 401 -- classified and
    logged by ``_ObservableProxyProvider`` below -- while one that doesn't
    (e.g. a bearer backend whose listing endpoint happens to be open) still
    lists successfully, deferring the real access decision to the
    authorized tools/call path exactly as before this fix.

    ``skip_reason`` (``"not_linked"`` | ``"unavailable"``) is set whenever
    ``headers`` is ``None``, letting the caller pre-record *why* no
    credential was attached (see the per-backend request-scoped state in
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


async def _classify_list_failure(exc: Exception, backend_name: str) -> tuple[str, str]:
    """Classify a ``_list_tools()`` failure for structured logging.

    Consults the per-backend request-scoped state ``_bearer_factory``'s
    list-time branch records (keyed per backend since one ``tools/list``
    request fans out to every backend concurrently): if a credential mint
    was deliberately skipped (``skip_reason`` set), that's the precise
    reason regardless of what the resulting uncredentialed connection
    raised. Otherwise, a raw upstream 401 is only "unauthorized" -- meaning
    the stored credential itself was rejected, bad/expired, the caller
    should re-link -- when a credential actually was injected for this
    attempt; a 401 with nothing injected (e.g. a "none"/"x509" backend
    unexpectedly requiring auth), a connection refusal, a timeout, or any
    other error all fall back to "unavailable", an operational/config
    problem rather than a "go re-link" prompt.
    """
    ctx = get_context()
    status = await ctx.get_state(f"__list_credential_status__:{backend_name}")
    injected, skip_reason = status if status is not None else (False, None)
    if not injected and skip_reason is not None:
        return skip_reason, str(exc)
    if (
        injected
        and isinstance(exc, httpx.HTTPStatusError)
        and exc.response.status_code == 401
    ):
        return "unauthorized", str(exc)
    return "unavailable", str(exc)


def _make_client_factory(
    spec: BackendSpec,
    credential_registry: CredentialRegistry,
    settings: Settings,
    policy: EntitlementPolicy,
) -> ClientFactoryT:
    """Build a ProxyProvider client_factory for one backend.

    Security property: constructing a plain ``Client`` around an explicit
    transport object never sets ``forward_incoming_headers`` -- it stays at
    the transport's default of False. fastmcp's ``ProxyClient`` convenience
    wrapper unconditionally sets that flag to True for HTTP/SSE transports
    (intended for proxies that should forward the caller's credentials), so
    it is deliberately not used here: the broker's own AF-internal bearer
    token must never reach a backend regardless. The ``headers`` passed to
    the transport below come exclusively from a credential this factory
    itself minted -- never copied from the inbound request -- so passing
    them does not reintroduce that forwarding behavior.

    ``auth_type`` selects the branch:
      - "none": no credential is resolved at all; the backend needs no
        per-user credential (e.g. it authorizes via a platform k8s SA).
      - "x509": no per-call delivery mechanism exists yet -- x509/VOMS
        proxies are consumed server-side from an NFS-mounted home
        directory (see docs/auth.md), not injected as a request header.
        TODO(#58): define one if/when an x509 backend needs /mcp access.
      - "bearer" (default): resolves the caller's Principal from the
        current request context, mints a credential in-process the same
        way ``POST /v1/credential`` does (api/credentials.py's
        ``issue_credential``), and injects it as ``Authorization: Bearer``.
        This branch is async because minting a credential requires
        awaiting the credential provider; ``ProxyTool._get_client()``
        already awaits the factory's return value when it is awaitable.

    The "x509" and "bearer" branches both key off ``authorized_call_target``
    (request-scoped state set by ``AuthorizationMiddleware`` right before it
    calls ``call_next``) to tell an authorized tools/call targeting this
    backend apart from any other invocation reaching this factory --
    ``ProxyTool.run()`` always hits the former; ``ProxyProvider._list_tools()``
    (which answers a ``tools/list`` request, and which ``_get_tool()`` also
    calls on a stale-cache lookup) hits the latter, and the two are otherwise
    indistinguishable from inside this factory.

    For "x509", the answer is still to do nothing extra: raising the
    not-yet-supported error during a listing would be both wasteful (every
    session's first list would eat it) and wrong (a listing shouldn't itself
    hard-fail), so absent the authorized-call signal the factory just
    connects without a credential, same as a "none" backend -- unchanged.

    For "bearer", that same "wasteful and wrong" framing used to justify
    skipping credential resolution entirely during a listing -- until issue
    #121: a backend whose MCP endpoint itself requires a bearer token to
    respond to ``tools/list`` (rucio-mcp) then 401s on every listing and
    becomes permanently invisible to every caller, with no user-facing
    error at all. Resolved by attempting a *best-effort* mint during a
    listing too, gated on the caller actually having the backend's
    ``required_capability`` (``check_entitlement``, the same check
    ``AuthorizationMiddleware`` uses) -- the in-process ``CredentialCache``
    already makes repeat mints for the same ``(uid, target)`` cheap, so
    "wasteful" no longer applies. A failure to mint (no linked identity, no
    provider configured, a mint error) does NOT prevent the connection
    attempt, unlike the authorized tools/call path below -- see
    ``_resolve_list_time_headers``'s docstring for why raising there instead
    would reintroduce a worse bug (a permanently unpopulated schema cache
    poisoning a *different* caller's later, genuinely authorized tools/call).
    ``_ObservableProxyProvider`` (below) classifies and structured-logs
    whatever the resulting connection attempt produces, then lets it
    propagate so the existing warn-and-skip behavior drops the backend from
    the list exactly like a dead backend would.

    This does mean a listing fetched with one user's credential can leave
    ``ProxyProvider``'s ``_tools_cache`` (used by ``_get_tool()`` for
    individual by-name lookups, e.g. during a tools/call's tool resolution
    -- NOT consulted by ``_list_tools()`` itself, which always makes a fresh
    call per ``tools/list`` request) holding a schema fetched under a
    different principal than the one who next triggers a stale-cache
    refresh. Harmless for tool *schemas* (name/description/parameters) that
    aren't user-specific -- true for rucio-mcp, one ``--read-only`` tool set
    per site -- since each ``ProxyTool`` only carries a reference back to
    this same ``client_factory`` (which mints fresh per call) rather than a
    baked-in credential. A backend whose tool list genuinely does personalize
    per caller should set ``BackendSpec.tools_cache_ttl: 0`` to disable that
    cache outright.
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
                return _build_client(spec, transport_cls)
            raise ToolError(
                f"Backend '{spec.name}' requires an x509/VOMS proxy credential. "
                "x509 proxies are consumed server-side from an NFS-mounted home "
                "directory and are not yet deliverable over /mcp tool calls. "
                "TODO(#58): define a per-call x509 delivery mechanism."
            )

        return _x509_factory

    async def _bearer_factory() -> Client:
        ctx = get_context()
        if await ctx.get_state("authorized_call_target") != spec.name:
            # Not an authorized tools/call for this backend -- most commonly
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

            # Same capability gate AuthorizationMiddleware applies to an
            # actual call -- a caller who could never pass it shouldn't
            # trigger a mint attempt at all; EntitlementMiddleware already
            # hides this backend's tools from such a caller's own tools/list
            # response, so this is just avoiding wasted work, not a security
            # boundary of its own.
            allowed, _reason = check_entitlement(
                principal, spec.required_capability, spec.name, policy
            )
            if not allowed:
                return _build_client(spec, transport_cls)

            headers, skip_reason = await _resolve_list_time_headers(
                spec, credential_registry, principal
            )
            # Keyed per backend (not a single shared key) since one
            # tools/list request fans out to every backend's factory
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
        if not await provider.is_linked(principal):
            portal = settings.portal_url.rstrip("/")
            raise ToolError(
                f"{type(provider).__name__} not linked. "
                f"Visit the portal Identities page ({portal}/identities) to "
                "connect it."
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


class _ObservableProxyProvider(ProxyProvider):
    """ProxyProvider that structured-logs a classified reason when its ``tools/list`` fails, then re-raises so ``AggregateProvider``'s existing ``provider_error_strategy="warn"`` still drops this backend's contribution and keeps every other backend's listing unaffected -- exactly today's degrade-gracefully behavior, just with an ``aggregator.backend_list_failed`` structlog event on record instead of only fastmcp's own unparseable stdlib WARNING (see issue #121).

    Overrides only the private ``_list_tools()`` extension hook that
    ``fastmcp.server.providers.proxy.ProxyProvider`` (pinned at 3.4.4, see
    pixi.lock) itself documents as a subclassing point -- but it's still
    third-party internals, not a public contract fastmcp guarantees stable.
    If ``_list_tools()``'s signature, its call sites (``_get_tool()``'s
    stale-cache refresh in particular -- see ``_resolve_list_time_headers``'s
    docstring for why that path matters here), or its cache-write-only-on-
    success behavior change on a future fastmcp bump, re-check this class.

    Also records the classified reason onto ``registry`` (BackendRegistry.
    record_list_failure) so /v1/catalog's per-backend status derivation
    (issue #123) can factor in a recent listing failure -- e.g. downgrading
    an otherwise "available" backend to "unavailable" -- without an extra
    live probe of its own.
    """

    def __init__(
        self,
        backend_name: str,
        client_factory: ClientFactoryT,
        registry: BackendRegistry,
        cache_ttl: float | None = None,
    ) -> None:
        super().__init__(client_factory, cache_ttl=cache_ttl)
        self._backend_name = backend_name
        self._registry = registry

    async def _list_tools(self) -> Sequence[Tool]:
        try:
            return await super()._list_tools()
        except Exception as exc:
            reason, detail = await _classify_list_failure(exc, self._backend_name)
            self._registry.record_list_failure(self._backend_name, reason)
            logger.warning(
                "aggregator.backend_list_failed",
                backend=self._backend_name,
                reason=reason,
                error=detail,
            )
            raise


def build_aggregator(
    registry: BackendRegistry,
    settings: Settings,
    policy: EntitlementPolicy,
    credential_registry: CredentialRegistry,
    revoked_jti_cache: RevokedJtiCache | None = None,
) -> FastMCP:
    """Construct a fully-wired aggregator FastMCP instance.

    Registers IdentityMiddleware first (so it runs outermost and extracts
    the Principal before anything else sees the request), EntitlementMiddleware
    second (filters tools/list to what the Principal is entitled to), and
    AuthorizationMiddleware third (checks entitlement again for tools/call,
    since a filtered list is not an access-control boundary by itself, and
    audits every invocation) -- then adds one ProxyProvider per backend in
    ``registry``. Namespacing follows ``BackendSpec.apply_namespace`` --
    backends whose tools already self-prefix (e.g. rucio-mcp) opt out.

    *revoked_jti_cache* defaults to None here because app.py builds the
    aggregator eagerly, before the real token registry exists (see the
    module-level comment above ``_mcp_aggregator``) -- ``populate_aggregator``
    pushes the real one in once the lifespan has it, same as settings/policy.
    """
    mcp = FastMCP(name="af-mcp-aggregator")
    mcp.add_middleware(IdentityMiddleware(settings, revoked_jti_cache))
    mcp.add_middleware(EntitlementMiddleware(registry, policy))
    mcp.add_middleware(AuthorizationMiddleware(registry, policy))
    _register_backends(mcp, registry, credential_registry, settings, policy)
    return mcp


def build_asgi_auth_middleware(mcp: FastMCP) -> Middleware:
    """Return the Starlette middleware spec that enforces identity at the
    ASGI layer for ``mcp``'s http_app (issue #138/#144 step 1) -- pass this
    into ``FastMCP.http_app(middleware=[...])`` when mounting.

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
    registry: BackendRegistry,
    settings: Settings,
    policy: EntitlementPolicy,
    credential_registry: CredentialRegistry,
    revoked_jti_cache: RevokedJtiCache | None = None,
) -> None:
    """Refresh an aggregator built by ``build_aggregator`` with a freshly loaded registry/settings/policy/credential_registry/revoked_jti_cache.

    app.py's mount-time constraint means the aggregator's FastMCP instance
    and ASGI app must exist before BACKENDS_FILE/POLICY_FILE/the credential
    subsystem are loaded (they are only read inside the async lifespan);
    this function is how the lifespan pushes the real values into the
    already-mounted instance. Safe to call more than once per process (every
    lifespan entry, including repeated TestClient entries in tests): backend
    providers are replaced wholesale rather than appended to, mirroring how
    BackendRegistry and EntitlementPolicy are themselves rebuilt from scratch
    on every lifespan entry rather than merged.
    """
    identity_mw, entitlement_mw, authorization_mw = _find_middleware(mcp)
    identity_mw.settings = settings
    identity_mw.revoked_jti_cache = revoked_jti_cache
    entitlement_mw.registry = registry
    entitlement_mw.policy = policy
    authorization_mw.registry = registry
    authorization_mw.policy = policy
    _register_backends(mcp, registry, credential_registry, settings, policy)


def _register_backends(
    mcp: FastMCP,
    registry: BackendRegistry,
    credential_registry: CredentialRegistry,
    settings: Settings,
    policy: EntitlementPolicy,
) -> None:
    mcp.providers.clear()
    for spec in registry.all_backends():
        provider = _ObservableProxyProvider(
            spec.name,
            client_factory=_make_client_factory(
                spec, credential_registry, settings, policy
            ),
            registry=registry,
            cache_ttl=spec.tools_cache_ttl,
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
