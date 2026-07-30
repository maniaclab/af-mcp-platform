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

from af_mcp_broker.credentials import CredentialKind, NeedsUnlock
from af_mcp_broker.mcp.middleware.authorization_mw import AuthorizationMiddleware
from af_mcp_broker.mcp.middleware.entitlement_mw import EntitlementMiddleware
from af_mcp_broker.mcp.middleware.identity_mw import IdentityMiddleware

if TYPE_CHECKING:
    from af_mcp_broker.authorization import EntitlementPolicy
    from af_mcp_broker.config import Settings
    from af_mcp_broker.credentials import CredentialRegistry
    from af_mcp_broker.mcp.registry import BackendRegistry, BackendSpec


def _build_client(
    spec: BackendSpec,
    transport_cls: type[SSETransport | StreamableHttpTransport],
    headers: dict[str, str] | None = None,
) -> Client:
    """Construct the plain (never ProxyClient) Client every branch of
    _make_client_factory returns.

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


def _make_client_factory(
    spec: BackendSpec, credential_registry: CredentialRegistry, settings: Settings
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

    Both the "x509" and "bearer" branches only act when
    ``authorized_call_target`` (request-scoped state set by
    ``AuthorizationMiddleware`` right before it calls ``call_next``) equals
    this backend's name -- see the check at the top of each. ProxyProvider
    reuses this same ``client_factory`` to populate its tools/list schema
    cache (process-wide, shared across all sessions, refreshed independently
    of any particular call), and that invocation is otherwise
    indistinguishable from a real tools/call reaching this factory via
    ``ProxyTool.run()``. Minting a credential -- or raising the x509
    not-yet-supported error -- during a shared schema listing would be both
    wasteful and wrong, so absent that signal the factory just connects
    without a credential, exactly like a "none" backend.
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
            return _build_client(spec, transport_cls)

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
            raise ToolError(
                f"{type(provider).__name__} not linked. "
                "Visit the portal Identities page to connect it."
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

        headers: dict[str, str] = {}
        if cred.kind == CredentialKind.BEARER:
            token = cred.payload.get("access_token")
            if token:
                headers["Authorization"] = f"Bearer {token}"
        return _build_client(spec, transport_cls, headers=headers)

    return _bearer_factory


def build_aggregator(
    registry: BackendRegistry,
    settings: Settings,
    policy: EntitlementPolicy,
    credential_registry: CredentialRegistry,
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
    """
    mcp = FastMCP(name="af-mcp-aggregator")
    mcp.add_middleware(IdentityMiddleware(settings))
    mcp.add_middleware(EntitlementMiddleware(registry, policy))
    mcp.add_middleware(AuthorizationMiddleware(registry, policy))
    _register_backends(mcp, registry, credential_registry, settings)
    return mcp


def populate_aggregator(
    mcp: FastMCP,
    registry: BackendRegistry,
    settings: Settings,
    policy: EntitlementPolicy,
    credential_registry: CredentialRegistry,
) -> None:
    """Refresh an aggregator built by ``build_aggregator`` with a freshly
    loaded registry/settings/policy/credential_registry.

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
    entitlement_mw.registry = registry
    entitlement_mw.policy = policy
    authorization_mw.registry = registry
    authorization_mw.policy = policy
    _register_backends(mcp, registry, credential_registry, settings)


def _register_backends(
    mcp: FastMCP,
    registry: BackendRegistry,
    credential_registry: CredentialRegistry,
    settings: Settings,
) -> None:
    mcp.providers.clear()
    for spec in registry.all_backends():
        provider = ProxyProvider(
            client_factory=_make_client_factory(spec, credential_registry, settings)
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
