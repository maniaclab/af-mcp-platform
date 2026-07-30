from __future__ import annotations

# Aggregator entry point — builds the FastMCP application that proxies tool
# calls to downstream MCP backends after the broker has validated identity
# and applied entitlement filtering.
#
# app.py builds an aggregator eagerly (with an empty BackendRegistry) so its
# ASGI app exists at FastAPI-construction time for mounting at /mcp and for
# combining lifespans; app.py's own lifespan then calls populate_aggregator()
# once BACKENDS_FILE/POLICY_FILE have actually been loaded. This module has
# no credential-injection or audit logic yet -- both land in a later PR. The
# client_factory below deliberately never forwards the caller's inbound
# Authorization header to a backend; see its docstring.
from collections.abc import Callable

from fastmcp import FastMCP
from fastmcp.client import Client
from fastmcp.client.transports import SSETransport, StreamableHttpTransport
from fastmcp.server.providers.proxy import ProxyProvider

from af_mcp_broker.authorization import EntitlementPolicy
from af_mcp_broker.config import Settings
from af_mcp_broker.mcp.middleware.entitlement_mw import EntitlementMiddleware
from af_mcp_broker.mcp.middleware.identity_mw import IdentityMiddleware
from af_mcp_broker.mcp.registry import BackendRegistry, BackendSpec


def _make_client_factory(spec: BackendSpec) -> Callable[[], Client]:
    """Build a ProxyProvider client_factory for one backend.

    Security property: constructing a plain ``Client`` around an explicit
    transport object never sets ``forward_incoming_headers`` -- it stays at
    the transport's default of False. fastmcp's ``ProxyClient`` convenience
    wrapper unconditionally sets that flag to True for HTTP/SSE transports
    (intended for proxies that should forward the caller's credentials), so
    it is deliberately not used here: this PR does no credential injection
    at all, and the broker's own AF-internal bearer token must never reach
    a backend regardless. A later PR adds real credential injection as an
    explicit, separate step.
    """
    if spec.transport == "sse":

        def _factory() -> Client:
            return Client(SSETransport(spec.url))

    else:

        def _factory() -> Client:
            return Client(StreamableHttpTransport(spec.url))

    return _factory


def build_aggregator(
    registry: BackendRegistry, settings: Settings, policy: EntitlementPolicy
) -> FastMCP:
    """Construct a fully-wired aggregator FastMCP instance.

    Registers IdentityMiddleware first (so it runs outermost and extracts
    the Principal before anything else sees the request) and
    EntitlementMiddleware second, then adds one ProxyProvider per backend in
    ``registry``. Namespacing follows ``BackendSpec.apply_namespace`` --
    backends whose tools already self-prefix (e.g. rucio-mcp) opt out.
    """
    mcp = FastMCP(name="af-mcp-aggregator")
    mcp.add_middleware(IdentityMiddleware(settings))
    mcp.add_middleware(EntitlementMiddleware(registry, policy))
    _register_backends(mcp, registry)
    return mcp


def populate_aggregator(
    mcp: FastMCP,
    registry: BackendRegistry,
    settings: Settings,
    policy: EntitlementPolicy,
) -> None:
    """Refresh an aggregator built by ``build_aggregator`` with a freshly
    loaded registry/settings/policy.

    app.py's mount-time constraint means the aggregator's FastMCP instance
    and ASGI app must exist before BACKENDS_FILE/POLICY_FILE are loaded (they
    are only read inside the async lifespan); this function is how the
    lifespan pushes the real values into the already-mounted instance. Safe
    to call more than once per process (every lifespan entry, including
    repeated TestClient entries in tests): backend providers are replaced
    wholesale rather than appended to, mirroring how BackendRegistry and
    EntitlementPolicy are themselves rebuilt from scratch on every lifespan
    entry rather than merged.
    """
    identity_mw, entitlement_mw = _find_middleware(mcp)
    identity_mw.settings = settings
    entitlement_mw.registry = registry
    entitlement_mw.policy = policy
    _register_backends(mcp, registry)


def _register_backends(mcp: FastMCP, registry: BackendRegistry) -> None:
    mcp.providers.clear()
    for spec in registry.all_backends():
        provider = ProxyProvider(client_factory=_make_client_factory(spec))
        namespace = spec.prefix if spec.apply_namespace else ""
        mcp.add_provider(provider, namespace=namespace)


def _find_middleware(
    mcp: FastMCP,
) -> tuple[IdentityMiddleware, EntitlementMiddleware]:
    identity_mw: IdentityMiddleware | None = None
    entitlement_mw: EntitlementMiddleware | None = None
    for mw in mcp.middleware:
        if isinstance(mw, IdentityMiddleware):
            identity_mw = mw
        elif isinstance(mw, EntitlementMiddleware):
            entitlement_mw = mw
    if identity_mw is None or entitlement_mw is None:
        raise RuntimeError(
            "aggregator is missing IdentityMiddleware/EntitlementMiddleware -- "
            "was it built by build_aggregator()?"
        )
    return identity_mw, entitlement_mw
