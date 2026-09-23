from __future__ import annotations

import asyncio
import inspect
import time
from typing import TYPE_CHECKING, Any, Self
from unittest.mock import AsyncMock

import httpx2
import pytest
import structlog
from fastapi import HTTPException
from fastmcp import FastMCP
from fastmcp.client import Client
from fastmcp.client.transports import SSETransport, StreamableHttpTransport
from fastmcp.exceptions import McpError, ToolError
from fastmcp.server.elicitation import (
    AcceptedElicitation,
    CancelledElicitation,
    DeclinedElicitation,
)
from fastmcp.server.providers.proxy import (
    ProxyTool,
    default_proxy_log_handler,
    default_proxy_progress_handler,
)
from mcp.types import METHOD_NOT_FOUND
from mcp.types import Prompt as McpPrompt
from mcp.types import Resource as McpResource
from mcp.types import ResourceTemplate as McpResourceTemplate
from mcp.types import Tool as McpTool

from af_mcp_broker.authorization import EntitlementPolicy
from af_mcp_broker.config import BrokerIssuedProviderConfig
from af_mcp_broker.credentials import (
    CredentialKind,
    CredentialProvider,
    CredentialRegistry,
    ExecutionModel,
    IssuedCredential,
    NeedsUnlock,
)
from af_mcp_broker.mcp import aggregator
from af_mcp_broker.mcp.aggregator import (
    _classify_failure,
    _make_client_factory,
    _require_linked,
    build_aggregator,
    populate_aggregator,
    resolve_list_time_credential,
)
from af_mcp_broker.mcp.middleware.authorization_mw import AuthorizationMiddleware
from af_mcp_broker.mcp.middleware.entitlement_mw import EntitlementMiddleware
from af_mcp_broker.mcp.middleware.identity_mw import IdentityMiddleware
from af_mcp_broker.mcp.registry import (
    LIST_IDENTITIES_TOOL_NAME,
    LIST_MCP_SERVERS_TOOL_NAME,
    WHOAMI_TOOL_NAME,
    ServiceRegistry,
    ServiceSpec,
)

if TYPE_CHECKING:
    from af_mcp_broker.identity import Principal


def _spec(**overrides: Any) -> ServiceSpec:
    defaults: dict[str, Any] = {
        "name": "example",
        "prefix": "example",
        "url": "http://example.invalid/mcp",
        "transport": "http",
        "required_permission": "__none__",
    }
    defaults.update(overrides)
    return ServiceSpec(**defaults)


def _mcp_error(code: int, message: str) -> McpError:
    """Build an ``McpError`` from a status code and message.

    mcp SDK v2's ``MCPError.__init__(self, code, message, data=None)``
    drops the v1 ``ErrorData`` wrapper. Isolating the construction here
    meant the SDK v2 migration only ever had to touch this one function,
    not every call site below.
    """
    return McpError(code, message)


# Every direct _make_client_factory() call below cares about credential
# resolution, not entitlement -- _bearer_factory's list-time branch (see
# aggregator.py) now also gates on check_entitlement(), but that check takes
# the required permission straight from the spec (ServiceSpec.
# required_permission, see issue #60) rather than looking it up in
# policy.yaml, and _spec()'s default of "__none__" already keeps the gate a
# no-op here -- so an empty policy is sufficient.
_OPEN_POLICY = EntitlementPolicy()


class _FakeProvider(CredentialProvider):
    """A CredentialProvider test double whose is_linked/issue outcomes are
    configured directly, rather than exercising a real provider's network
    calls."""

    cred_class = "fake"
    execution_model = ExecutionModel.DELEGATED

    def __init__(
        self,
        *,
        linked: bool = True,
        token: str | None = "minted-token",
        needs_unlock: NeedsUnlock | None = None,
        http_error: HTTPException | None = None,
    ) -> None:
        self.linked = linked
        self.token = token
        self.needs_unlock = needs_unlock
        self.http_error = http_error
        self.issue_calls: list[tuple[int, str]] = []

    async def is_linked(self, principal: Principal) -> bool:
        return self.linked

    async def issue(
        self,
        principal: Principal,
        target: str,
        min_remaining_seconds: int = 300,
        passphrase: Any = None,
    ) -> IssuedCredential:
        self.issue_calls.append((principal.uid, target))
        if self.needs_unlock is not None:
            raise self.needs_unlock
        if self.http_error is not None:
            raise self.http_error
        return IssuedCredential(
            cred_class=self.cred_class,
            target=target,
            kind=CredentialKind.BEARER,
            expires_at=time.time() + 3600,
            payload={"access_token": self.token, "token_type": "Bearer"},
            audit_id="test-audit",
            source="test",
            execution_model=self.execution_model,
        )


class _RelinkingProvider(_FakeProvider):
    """Reports not-linked on the first ``is_linked()`` call, then linked on
    every call after that -- simulates the caller completing the portal
    linking flow while ``_require_linked``'s elicitation round trip is in
    flight, so the re-check after an accepted "try again" response sees a
    different answer than the initial gate did."""

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(linked=False, **kwargs)
        self.is_linked_calls = 0

    async def is_linked(self, principal: Principal) -> bool:
        self.is_linked_calls += 1
        return self.is_linked_calls > 1


class _FakeSession:
    """Stand-in for the real ``Context.session``'s client-capability introspection.

    ``_client_supports_elicitation`` calls
    ``ctx.session.check_client_capability(...)`` -- this fake reports a
    fixed, test-configured answer rather than parsing a real
    ``ClientCapabilities``/``InitializeRequestParams`` round trip.
    """

    def __init__(self, *, supports_elicitation: bool) -> None:
        self._supports_elicitation = supports_elicitation

    def check_client_capability(self, capability: Any) -> bool:
        return self._supports_elicitation


class _FakeFastMCPContext:
    def __init__(
        self,
        principal: Principal | None,
        active_backend: str | None,
        *,
        supports_elicitation: bool = True,
        elicit_result: Any = None,
        elicit_error: BaseException | None = None,
    ) -> None:
        self._principal = principal
        self._active_backend = active_backend
        # Populated by set_state() -- the list-time branch records its
        # credential-status decision here (see aggregator.py's
        # _classify_list_failure), keyed the same way the real Context would.
        self.recorded_state: dict[str, Any] = {}
        self.session = _FakeSession(supports_elicitation=supports_elicitation)
        self._elicit_result = elicit_result
        self._elicit_error = elicit_error
        # Recorded (message, response_type) pairs -- lets a test assert
        # whether _require_linked ever attempted elicit() at all, and with
        # what message/options.
        self.elicit_calls: list[tuple[str, list[str]]] = []

    async def get_state(self, key: str) -> Any:
        if key == "principal":
            return self._principal
        if key == "authorized_call_target":
            return self._active_backend
        if key in self.recorded_state:
            return self.recorded_state[key]
        raise AssertionError(f"unexpected state key {key!r}")

    async def set_state(
        self, key: str, value: Any, *, serializable: bool = True
    ) -> None:
        self.recorded_state[key] = value

    async def elicit(self, message: str, response_type: list[str]) -> Any:
        self.elicit_calls.append((message, response_type))
        if self._elicit_error is not None:
            raise self._elicit_error
        return self._elicit_result


def _patch_context(
    monkeypatch: pytest.MonkeyPatch,
    principal: Principal | None,
    active_backend: str | None = "example",
    *,
    supports_elicitation: bool = True,
    elicit_result: Any = None,
    elicit_error: BaseException | None = None,
) -> _FakeFastMCPContext:
    """_make_client_factory's bearer/x509 branches read the caller's
    Principal, and whether AuthorizationMiddleware stamped this request as a
    genuine tools/call for this backend, via
    fastmcp.server.dependencies.get_context() -- the same contextvar-scoped
    call ProxyTool.run() itself uses -- since a client_factory has no other
    hook into the current request. Patch the name aggregator imports it
    under, mirroring identity_mw's test pattern for get_http_headers.
    ``active_backend`` defaults to "example" to match ``_spec()``'s default
    name, simulating a genuine call for that backend. Returns the single
    shared context instance every ``get_context()`` call resolves to, so a
    test can inspect what the list-time branch recorded via ``set_state()``
    after calling the factory.

    ``supports_elicitation``/``elicit_result``/``elicit_error`` configure
    the fake's elicitation behavior for ``_require_linked`` tests (stage 2a):
    the first controls what ``_client_supports_elicitation`` sees via
    ``ctx.session.check_client_capability(...)``; the latter two control
    what ``await ctx.elicit(...)`` returns or raises.
    """
    ctx = _FakeFastMCPContext(
        principal,
        active_backend,
        supports_elicitation=supports_elicitation,
        elicit_result=elicit_result,
        elicit_error=elicit_error,
    )
    monkeypatch.setattr(aggregator, "get_context", lambda: ctx)
    return ctx


def test_build_aggregator_returns_fastmcp(settings: Any) -> None:
    mcp = build_aggregator(
        ServiceRegistry(), settings, EntitlementPolicy(), CredentialRegistry()
    )
    assert isinstance(mcp, FastMCP)


def test_build_aggregator_wires_identity_before_entitlement_before_authorization(
    settings: Any,
) -> None:
    """First-registered middleware runs outermost -- identity must extract
    the Principal before entitlement filtering reads it, and authorization
    (which gates credential minting) must run after both. FastMCP itself
    prepends its own DereferenceRefsMiddleware, so assert relative order
    between ours rather than absolute list positions."""
    mcp = build_aggregator(
        ServiceRegistry(), settings, EntitlementPolicy(), CredentialRegistry()
    )
    identity_index = next(
        i for i, mw in enumerate(mcp.middleware) if isinstance(mw, IdentityMiddleware)
    )
    entitlement_index = next(
        i
        for i, mw in enumerate(mcp.middleware)
        if isinstance(mw, EntitlementMiddleware)
    )
    authorization_index = next(
        i
        for i, mw in enumerate(mcp.middleware)
        if isinstance(mw, AuthorizationMiddleware)
    )
    assert identity_index < entitlement_index < authorization_index


def test_build_aggregator_composes_model_facing_instructions(settings: Any) -> None:
    """Dual enforcement (re-review finding #6): the built FastMCP instance
    carries non-empty model-facing instructions -- the platform preamble plus
    each service's agent_policy."""
    registry = ServiceRegistry()
    registry.register(
        _spec(name="widgets", prefix="widgets", agent_policy="Widgets are read-only.")
    )
    mcp = build_aggregator(
        registry, settings, EntitlementPolicy(), CredentialRegistry()
    )
    assert mcp.instructions
    # deny-is-policy guidance from the preamble
    assert "retry" in mcp.instructions.lower()
    # the service's own model-facing policy
    assert "Widgets are read-only." in mcp.instructions


def test_populate_aggregator_refreshes_instructions(settings: Any) -> None:
    """build_aggregator is called eagerly with an empty registry (see app.py);
    populate_aggregator must recompose the instructions once the real registry
    is pushed in, or the eager build's instructions would omit every operator
    service's agent_policy."""
    mcp = build_aggregator(
        ServiceRegistry(), settings, EntitlementPolicy(), CredentialRegistry()
    )
    assert "Widgets are read-only." not in (mcp.instructions or "")

    real_registry = ServiceRegistry()
    real_registry.register(
        _spec(name="widgets", prefix="widgets", agent_policy="Widgets are read-only.")
    )
    populate_aggregator(
        mcp, real_registry, settings, EntitlementPolicy(), CredentialRegistry()
    )
    assert "Widgets are read-only." in (mcp.instructions or "")


# _register_services() re-adds mcp.local_provider (which the af_* diagnostic
# tools live on -- see mcp/diagnostics.py) right after clearing mcp.providers,
# so every count below is "one backend provider per registered backend" PLUS
# that one constant local-provider entry.
_LOCAL_PROVIDER_COUNT = 1


def test_build_aggregator_registers_one_provider_per_backend(settings: Any) -> None:
    registry = ServiceRegistry()
    registry.register(_spec(name="a", prefix="a"))
    registry.register(_spec(name="b", prefix="b"))

    mcp = build_aggregator(
        registry, settings, EntitlementPolicy(), CredentialRegistry()
    )

    assert len(mcp.providers) == 2 + _LOCAL_PROVIDER_COUNT


async def test_local_provider_tools_survive_populate_aggregator(settings: Any) -> None:
    """Regression test: _register_services() clears mcp.providers wholesale
    on every call (see its docstring), which would silently drop
    mcp.local_provider -- and with it every af_* diagnostic tool
    (mcp/diagnostics.py) -- from dispatch on the very next
    populate_aggregator() refresh if it weren't re-added. af_whoami is a
    stand-in for "any locally-registered tool stays reachable."""
    mcp = build_aggregator(
        ServiceRegistry(), settings, EntitlementPolicy(), CredentialRegistry()
    )
    populate_aggregator(
        mcp, ServiceRegistry(), settings, EntitlementPolicy(), CredentialRegistry()
    )

    tools = await mcp._list_tools()

    assert WHOAMI_TOOL_NAME in {t.name for t in tools}


def test_populate_aggregator_replaces_providers_not_appends(settings: Any) -> None:
    registry_a = ServiceRegistry()
    registry_a.register(_spec(name="a", prefix="a"))
    mcp = build_aggregator(
        registry_a, settings, EntitlementPolicy(), CredentialRegistry()
    )
    assert len(mcp.providers) == 1 + _LOCAL_PROVIDER_COUNT

    registry_b = ServiceRegistry()
    registry_b.register(_spec(name="b", prefix="b"))
    registry_b.register(_spec(name="c", prefix="c"))
    populate_aggregator(
        mcp, registry_b, settings, EntitlementPolicy(), CredentialRegistry()
    )

    assert len(mcp.providers) == 2 + _LOCAL_PROVIDER_COUNT


def test_populate_aggregator_refreshes_middleware_state(settings: Any) -> None:
    mcp = build_aggregator(
        ServiceRegistry(), settings, EntitlementPolicy(), CredentialRegistry()
    )
    identity_mw = next(
        mw for mw in mcp.middleware if isinstance(mw, IdentityMiddleware)
    )
    entitlement_mw = next(
        mw for mw in mcp.middleware if isinstance(mw, EntitlementMiddleware)
    )
    authorization_mw = next(
        mw for mw in mcp.middleware if isinstance(mw, AuthorizationMiddleware)
    )

    new_registry = ServiceRegistry()
    new_registry.register(_spec(name="a", prefix="a"))
    new_policy = EntitlementPolicy(group_permissions={"atlas": ["read_data"]})
    new_settings = settings.model_copy(update={"oidc_audience": "something-else"})

    populate_aggregator(
        mcp, new_registry, new_settings, new_policy, CredentialRegistry()
    )

    assert identity_mw.settings is new_settings
    assert entitlement_mw.registry is new_registry
    assert entitlement_mw.policy is new_policy
    assert authorization_mw.registry is new_registry
    assert authorization_mw.policy is new_policy


def test_populate_aggregator_raises_if_middleware_missing(settings: Any) -> None:
    mcp = FastMCP(name="bare")
    with pytest.raises(RuntimeError, match="build_aggregator"):
        populate_aggregator(
            mcp,
            ServiceRegistry(),
            settings,
            EntitlementPolicy(),
            CredentialRegistry(),
        )


def test_populate_aggregator_propagates_revoked_jti_cache(settings: Any) -> None:
    """issue #115: app.py's lifespan builds the real RevokedJtiCache only
    after the aggregator already exists (see build_aggregator's eager-build
    note), so populate_aggregator must be able to push it into
    IdentityMiddleware the same way it refreshes settings/registry/policy."""
    from af_mcp_broker.token_registry import (
        InMemoryTokenRegistryBackend,
        RevokedJtiCache,
    )

    mcp = build_aggregator(
        ServiceRegistry(), settings, EntitlementPolicy(), CredentialRegistry()
    )
    identity_mw = next(
        mw for mw in mcp.middleware if isinstance(mw, IdentityMiddleware)
    )
    assert identity_mw.revoked_jti_cache is None

    cache = RevokedJtiCache(InMemoryTokenRegistryBackend())
    populate_aggregator(
        mcp,
        ServiceRegistry(),
        settings,
        EntitlementPolicy(),
        CredentialRegistry(),
        revoked_jti_cache=cache,
    )

    assert identity_mw.revoked_jti_cache is cache


@pytest.mark.parametrize(
    ("transport", "expected_type"),
    [("http", StreamableHttpTransport), ("sse", SSETransport)],
)
def test_client_factory_selects_transport_by_spec(
    transport: str, expected_type: type, settings: Any
) -> None:
    # auth_type="none" keeps this test focused on transport selection alone.
    spec = _spec(
        transport=transport, url="http://example.invalid/mcp", auth_type="none"
    )
    factory = _make_client_factory(spec, CredentialRegistry(), settings, _OPEN_POLICY)
    client = factory()
    assert isinstance(client, Client)
    assert isinstance(client.transport, expected_type)
    # The security property this whole factory exists for: plain Client +
    # an explicit transport object never sets forward_incoming_headers,
    # unlike fastmcp's ProxyClient convenience wrapper (which this code
    # deliberately avoids using). fastmcp v4 moved forward_incoming_headers
    # off the transport instance and onto the client's TransportOptions
    # bundle (client/transports/base.py); a plain Client never populates
    # it, so it stays None here and TransportOptions()'s own default
    # (False) applies -- only ProxyClient sets it True.
    assert client._transport_options is None


def test_client_factory_none_auth_type_applies_backend_timeout(settings: Any) -> None:
    spec = _spec(auth_type="none", timeout_seconds=5.0)
    client = _make_client_factory(spec, CredentialRegistry(), settings, _OPEN_POLICY)()
    assert client._session_kwargs["read_timeout_seconds"] == 5.0


async def test_client_factory_x509_auth_type_applies_backend_timeout(
    settings: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    # active_backend=None takes the tools/list-refresh path (connect without
    # raising the not-yet-supported error), so the timeout can be inspected
    # on the returned Client the same way as the "none" branch above.
    _patch_context(monkeypatch, None, active_backend=None)
    spec = _spec(auth_type="x509", timeout_seconds=5.0)
    client = await _make_client_factory(
        spec, CredentialRegistry(), settings, _OPEN_POLICY
    )()
    assert client._session_kwargs["read_timeout_seconds"] == 5.0


async def test_client_factory_bearer_auth_type_applies_backend_timeout(
    settings: Any, make_principal, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_context(monkeypatch, make_principal(), active_backend=None)
    spec = _spec(auth_type="bearer", timeout_seconds=5.0)
    client = await _make_client_factory(
        spec, CredentialRegistry(), settings, _OPEN_POLICY
    )()
    assert client._session_kwargs["read_timeout_seconds"] == 5.0


def test_client_factory_installs_progress_and_log_forwarding_handlers(
    settings: Any,
) -> None:
    """PR A/B's client_factory deliberately builds a plain Client (never
    fastmcp's ProxyClient convenience wrapper) so the caller's inbound
    Authorization header is never forwarded -- see the security property
    documented on _make_client_factory. That convenience wrapper is also
    where fastmcp's progress/log *notification* forwarding defaults live, so
    a plain Client must opt into those explicitly (independently of header
    forwarding, which stays governed solely by the transport's default of
    False) or a backend's progress/log notifications would be swallowed
    (logged locally) instead of reaching the aggregator's own caller."""
    spec = _spec(auth_type="none")
    client = _make_client_factory(spec, CredentialRegistry(), settings, _OPEN_POLICY)()
    assert client._progress_handler is default_proxy_progress_handler
    # logging_callback is create_log_callback(handler)'s closure -- inspect
    # the closed-over handler directly rather than relying on identity of
    # the wrapper create_log_callback() returns.
    closure = inspect.getclosurevars(client._session_kwargs["logging_callback"])
    assert closure.nonlocals["handler"] is default_proxy_log_handler


def test_client_factory_none_auth_type_never_touches_credential_registry(
    settings: Any,
) -> None:
    spec = _spec(auth_type="none")
    # An empty registry would raise KeyError if resolve() were ever called
    # for this target -- proving auth_type="none" skips credential
    # resolution entirely rather than merely succeeding to find nothing.
    client = _make_client_factory(spec, CredentialRegistry(), settings, _OPEN_POLICY)()
    assert "Authorization" not in client.transport.headers


async def test_client_factory_x509_call_without_principal_raises(
    settings: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_context(monkeypatch, None)
    spec = _spec(auth_type="x509")
    factory = _make_client_factory(spec, CredentialRegistry(), settings, _OPEN_POLICY)
    with pytest.raises(ToolError, match="principal"):
        await factory()


async def test_client_factory_x509_auth_type_lists_without_raising(
    settings: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A tools/list schema-cache refresh must still be able to connect to an
    x509 backend to enumerate its tools -- only an actual tools/call (signalled
    by authorized_call_target matching this backend) hits the not-yet-supported
    error above."""
    _patch_context(monkeypatch, None, active_backend=None)
    spec = _spec(auth_type="x509")
    factory = _make_client_factory(spec, CredentialRegistry(), settings, _OPEN_POLICY)
    client = await factory()
    assert isinstance(client, Client)
    assert "Authorization" not in client.transport.headers


async def test_client_factory_bearer_injects_minted_token_not_inbound(
    settings: Any, make_principal, monkeypatch: pytest.MonkeyPatch
) -> None:
    principal = make_principal(uid=1001)
    _patch_context(monkeypatch, principal)
    spec = _spec(auth_type="bearer")
    provider = _FakeProvider(token="minted-abc")
    registry = CredentialRegistry()
    registry.register(spec.name, provider)

    factory = _make_client_factory(spec, registry, settings, _OPEN_POLICY)
    client = await factory()

    assert client.transport.headers["Authorization"] == "Bearer minted-abc"
    assert (
        client.transport.headers["Authorization"]
        != f"Bearer {principal.raw_token.get_secret_value()}"
    )
    # See test_client_factory_selects_transport_by_spec for why this is
    # _transport_options rather than a transport-level attribute in v4.
    assert client._transport_options is None


async def test_client_factory_bearer_per_user_isolation(
    settings: Any, make_principal, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Two different principals calling the same backend must each get
    their own minted token -- proven with a fake provider that returns a
    distinguishable token per uid."""
    spec = _spec(auth_type="bearer")

    class _PerUserProvider(_FakeProvider):
        async def issue(
            self, principal, target, min_remaining_seconds=300, passphrase=None
        ):
            self.issue_calls.append((principal.uid, target))
            return IssuedCredential(
                cred_class=self.cred_class,
                target=target,
                kind=CredentialKind.BEARER,
                expires_at=time.time() + 3600,
                payload={"access_token": f"token-for-{principal.uid}"},
                audit_id="test-audit",
                source="test",
                execution_model=self.execution_model,
            )

    provider = _PerUserProvider()
    registry = CredentialRegistry()
    registry.register(spec.name, provider)
    factory = _make_client_factory(spec, registry, settings, _OPEN_POLICY)

    alice = make_principal(uid=111, unixname="alice")
    _patch_context(monkeypatch, alice)
    alice_client = await factory()

    bob = make_principal(uid=222, unixname="bob")
    _patch_context(monkeypatch, bob)
    bob_client = await factory()

    assert alice_client.transport.headers["Authorization"] == "Bearer token-for-111"
    assert bob_client.transport.headers["Authorization"] == "Bearer token-for-222"


async def test_client_factory_bearer_unknown_target_raises_tool_error(
    settings: Any, make_principal, monkeypatch: pytest.MonkeyPatch
) -> None:
    spec = _spec(auth_type="bearer", name="no-such-target")
    _patch_context(monkeypatch, make_principal(), active_backend=spec.name)
    factory = _make_client_factory(spec, CredentialRegistry(), settings, _OPEN_POLICY)

    with pytest.raises(ToolError):
        await factory()


async def test_client_factory_bearer_not_linked_raises_friendly_error(
    settings: Any, make_principal, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_context(monkeypatch, make_principal())
    spec = _spec(auth_type="bearer")
    provider = _FakeProvider(linked=False)
    registry = CredentialRegistry()
    registry.register(spec.name, provider)

    with pytest.raises(ToolError, match="not linked") as excinfo:
        await _make_client_factory(spec, registry, settings, _OPEN_POLICY)()

    # Close the loop (issue #153): a model hitting this error is told which
    # diagnostic tools to call next rather than having to guess they exist.
    assert LIST_IDENTITIES_TOOL_NAME in str(excinfo.value)
    assert LIST_MCP_SERVERS_TOOL_NAME in str(excinfo.value)


async def test_client_factory_bearer_needs_unlock_raises_friendly_error(
    settings: Any, make_principal, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_context(monkeypatch, make_principal())
    spec = _spec(auth_type="bearer")
    provider = _FakeProvider(
        needs_unlock=NeedsUnlock(
            spec.name, "no cached proxy", unlock_endpoint="/v1/x509/proxy"
        )
    )
    registry = CredentialRegistry()
    registry.register(spec.name, provider)

    with pytest.raises(ToolError, match="portal") as excinfo:
        await _make_client_factory(spec, registry, settings, _OPEN_POLICY)()
    assert "/v1/x509/proxy" in str(excinfo.value)


async def test_client_factory_bearer_provider_http_exception_surfaces_detail(
    settings: Any, make_principal, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_context(monkeypatch, make_principal())
    spec = _spec(auth_type="bearer")
    provider = _FakeProvider(
        http_error=HTTPException(status_code=404, detail="No ATLAS IAM token stored")
    )
    registry = CredentialRegistry()
    registry.register(spec.name, provider)

    with pytest.raises(ToolError, match="No ATLAS IAM token stored"):
        await _make_client_factory(spec, registry, settings, _OPEN_POLICY)()


async def test_client_factory_bearer_missing_principal_raises(
    settings: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_context(monkeypatch, None)
    spec = _spec(auth_type="bearer")
    factory = _make_client_factory(spec, CredentialRegistry(), settings, _OPEN_POLICY)

    with pytest.raises(ToolError):
        await factory()


async def test_client_factory_bearer_list_time_falls_back_when_no_provider_registered(
    settings: Any, make_principal, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A tools/list schema-cache refresh reuses the same client_factory as a
    real call, and now attempts a best-effort mint too (issue #121) -- but an
    empty registry (no provider configured for this target at all) must
    still fall back to an uncredentialed connection rather than raising,
    exactly like a "none" backend would."""
    ctx = _patch_context(monkeypatch, make_principal(), active_backend=None)
    spec = _spec(auth_type="bearer")
    factory = _make_client_factory(spec, CredentialRegistry(), settings, _OPEN_POLICY)

    client = await factory()

    assert "Authorization" not in client.transport.headers
    assert ctx.recorded_state[f"__list_credential_status__:{spec.name}"] == (
        False,
        "unavailable",
    )


async def test_client_factory_bearer_list_time_falls_back_when_not_linked(
    settings: Any, make_principal, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Same non-fatal fallback as the no-provider case above, but for a
    registered provider that says the caller isn't linked -- classified
    distinctly ("not_linked" vs "unavailable") so _ObservableProxyProvider
    can log the precise reason if the resulting uncredentialed connection
    goes on to fail (e.g. the backend itself gates listing on auth)."""
    ctx = _patch_context(monkeypatch, make_principal(), active_backend=None)
    spec = _spec(auth_type="bearer")
    provider = _FakeProvider(linked=False)
    registry = CredentialRegistry()
    registry.register(spec.name, provider)
    factory = _make_client_factory(spec, registry, settings, _OPEN_POLICY)

    client = await factory()

    assert "Authorization" not in client.transport.headers
    assert provider.issue_calls == []
    assert ctx.recorded_state[f"__list_credential_status__:{spec.name}"] == (
        False,
        "not_linked",
    )


async def test_client_factory_bearer_list_time_mints_when_entitled_and_linked(
    settings: Any, make_principal, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The actual fix for issue #121: a tools/list-time connection for a
    linked, entitled caller now carries a minted credential, not just an
    authorized tools/call."""
    policy = EntitlementPolicy(group_permissions={"atlas": ["read_data"]})
    principal = make_principal(groups=["atlas"])
    ctx = _patch_context(monkeypatch, principal, active_backend=None)
    spec = _spec(auth_type="bearer", required_permission="read_data")
    provider = _FakeProvider(token="minted-for-list")
    registry = CredentialRegistry()
    registry.register(spec.name, provider)
    factory = _make_client_factory(spec, registry, settings, policy)

    client = await factory()

    assert client.transport.headers["Authorization"] == "Bearer minted-for-list"
    assert ctx.recorded_state[f"__list_credential_status__:{spec.name}"] == (True, None)


async def test_client_factory_bearer_list_time_skips_mint_when_not_entitled(
    settings: Any, make_principal, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A caller who lacks the backend's required_permission shouldn't trigger
    a mint attempt during a listing at all -- EntitlementMiddleware already
    hides this backend's tools from such a caller's own tools/list response,
    so minting would just be wasted work (proven with an empty issue_calls
    list on a provider that WOULD otherwise happily mint)."""
    policy = EntitlementPolicy(group_permissions={"atlas": ["read_data"]})
    principal = make_principal(groups=[])  # lacks read_data
    _patch_context(monkeypatch, principal, active_backend=None)
    spec = _spec(auth_type="bearer", required_permission="read_data")
    provider = _FakeProvider()
    registry = CredentialRegistry()
    registry.register(spec.name, provider)
    factory = _make_client_factory(spec, registry, settings, policy)

    client = await factory()

    assert "Authorization" not in client.transport.headers
    assert provider.issue_calls == []


async def test_observable_proxy_provider_records_list_failure_on_registry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """_ObservableProxyProvider now also records the classified tools/list
    failure reason onto the ServiceRegistry (ServiceRegistry.
    record_list_failure), alongside the existing structured
    'aggregator.service_list_failed' log -- so /v1/catalog's per-backend
    status derivation (issue #123) can factor in a recent listing failure
    without an extra live probe of its own."""
    ctx = _patch_context(monkeypatch, None, active_backend=None)
    ctx.recorded_state["__list_credential_status__:example"] = (False, "unavailable")

    async def _raising_factory() -> Client:
        raise ConnectionError("connection refused")

    registry = ServiceRegistry()
    registry.register(_spec())
    provider = aggregator._ObservableProxyProvider(
        "example", _raising_factory, registry=registry
    )

    with pytest.raises(ConnectionError):
        await provider._list_tools()

    assert registry.recent_list_failure("example") == "unavailable"


async def test_observable_proxy_provider_clears_list_failure_on_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A backend that previously failed tools/list and has since recovered
    must not stay reported "unavailable" forever -- record_list_failure() had
    no counterpart to un-record a stale reason, so /v1/catalog and
    af_list_mcp_servers kept surfacing a backend as unavailable for the rest
    of the broker pod's uptime even once its /mcp endpoint was answering
    fine again. A successful _list_tools() must clear any reason previously
    recorded for this backend."""
    monkeypatch.setattr(
        aggregator.ProxyProvider, "_list_tools", AsyncMock(return_value=[])
    )

    registry = ServiceRegistry()
    registry.register(_spec())
    registry.record_list_failure("example", "unavailable")

    async def _factory() -> Client:
        raise AssertionError(
            "ProxyProvider._list_tools is stubbed; should never call the client factory"
        )

    provider = aggregator._ObservableProxyProvider(
        "example", _factory, registry=registry
    )

    await provider._list_tools()

    assert registry.recent_list_failure("example") is None


async def test_observable_proxy_provider_get_tool_short_circuits_on_prefix_mismatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A ``route_prefix``-carrying provider (apply_namespace: false) is asked
    about every tool name in an aggregate tools/call, since fastmcp only
    pre-filters by prefix for namespaced mounts. A name that doesn't start
    with this backend's own prefix can never be one of its tools, so
    ``_get_tool`` must return None immediately -- without a cold-cache
    ``_list_tools()`` round trip (and the credential mint inside
    client_factory that a real one would trigger)."""
    list_tools = AsyncMock(return_value=[])
    monkeypatch.setattr(aggregator._ObservableProxyProvider, "_list_tools", list_tools)

    async def _factory() -> Client:
        raise AssertionError("client_factory must not be called for a prefix mismatch")

    registry = ServiceRegistry()
    registry.register(_spec())
    provider = aggregator._ObservableProxyProvider(
        "example", _factory, registry=registry, route_prefix="ami"
    )

    tool = await provider._get_tool("servicex_get_dataset")

    assert tool is None
    list_tools.assert_not_awaited()


async def test_observable_proxy_provider_get_tool_delegates_on_prefix_match() -> None:
    """A name that DOES start with the un-namespaced provider's own prefix
    must still resolve normally -- the short-circuit only rules out names
    that can't belong to this backend. Exercised through a fake client
    (rather than mocking ``_list_tools``) so the real cache-population path
    in fastmcp's base ``_get_tool``/``_list_tools`` runs unmodified."""
    mcp_tool = McpTool(name="ami_get_dataset_info", input_schema={"type": "object"})

    class _FakeClient:
        async def __aenter__(self) -> Self:
            return self

        async def __aexit__(self, *exc_info: object) -> None:
            return None

        async def list_tools(self) -> list[McpTool]:
            return [mcp_tool]

    registry = ServiceRegistry()
    registry.register(_spec())
    provider = aggregator._ObservableProxyProvider(
        "example", _FakeClient, registry=registry, route_prefix="ami"
    )

    tool = await provider._get_tool("ami_get_dataset_info")

    assert tool is not None
    assert tool.name == "ami_get_dataset_info"


async def test_observable_proxy_provider_get_tool_namespaced_unaffected() -> None:
    """A namespaced provider (``route_prefix=None``, the default -- fastmcp
    itself already restricts which names it's ever asked about) must keep
    delegating to the base ``_get_tool`` for any name, exactly as before this
    change."""
    mcp_tool = McpTool(name="anything_at_all", input_schema={"type": "object"})

    class _FakeClient:
        async def __aenter__(self) -> Self:
            return self

        async def __aexit__(self, *exc_info: object) -> None:
            return None

        async def list_tools(self) -> list[McpTool]:
            return [mcp_tool]

    registry = ServiceRegistry()
    registry.register(_spec())
    provider = aggregator._ObservableProxyProvider(
        "example", _FakeClient, registry=registry
    )

    tool = await provider._get_tool("anything_at_all")

    assert tool is not None
    assert tool.name == "anything_at_all"


async def test_observable_proxy_provider_warns_on_tool_prefix_mismatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """route_prefix set means a tool this backend advertises without that
    prefix is listable (it survives entitlement filtering in tools/list) but
    can never be reached through _get_tool's short-circuit above -- warn so
    the mismatch is visible in logs instead of leaving the tool silently
    dead on arrival."""
    matching_tool = ProxyTool.from_mcp_tool(
        lambda: None,
        McpTool(name="ami_get_dataset_info", input_schema={"type": "object"}),
    )
    mismatched_tool = ProxyTool.from_mcp_tool(
        lambda: None,
        McpTool(name="servicex_list_datasets", input_schema={"type": "object"}),
    )
    monkeypatch.setattr(
        aggregator.ProxyProvider,
        "_list_tools",
        AsyncMock(return_value=[matching_tool, mismatched_tool]),
    )

    registry = ServiceRegistry()
    registry.register(_spec())

    async def _factory() -> Client:
        raise AssertionError("ProxyProvider._list_tools is stubbed above")

    provider = aggregator._ObservableProxyProvider(
        "example", _factory, registry=registry, route_prefix="ami"
    )

    with structlog.testing.capture_logs() as logs:
        tools = await provider._list_tools()

    assert tools == [matching_tool, mismatched_tool]
    mismatch_events = [
        entry for entry in logs if entry["event"] == "aggregator.tool_prefix_mismatch"
    ]
    assert len(mismatch_events) == 1
    assert mismatch_events[0]["service"] == "example"
    assert mismatch_events[0]["tool"] == "servicex_list_datasets"
    assert mismatch_events[0]["prefix"] == "ami"


# ---------------------------------------------------------------------------
# exclude_tools (issue #173): a service's ProxyProvider must omit configured
# native tool names from tools/list AND refuse them on tools/call exactly
# like a name the backend never advertised -- e.g. condor-mcp's
# infrastructure-facing advertise_to_collector.
# ---------------------------------------------------------------------------


async def test_observable_proxy_provider_get_tool_returns_none_for_excluded_tool_before_delegating(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A tools/call resolving an excluded name must fail exactly like one for
    a name the backend never advertised at all. fastmcp's base _get_tool()
    reads self._tools_cache directly -- populated unfiltered by the base
    _list_tools() -- so filtering only the tools/list response is not
    enough; a direct _get_tool() lookup would still resolve it. The
    exclusion must short-circuit _get_tool() itself, before any cold-cache
    tools/list round trip (and the credential mint inside client_factory a
    real one would trigger)."""
    list_tools = AsyncMock(return_value=[])
    monkeypatch.setattr(aggregator._ObservableProxyProvider, "_list_tools", list_tools)

    async def _factory() -> Client:
        raise AssertionError("client_factory must not be called for an excluded tool")

    registry = ServiceRegistry()
    registry.register(_spec())
    provider = aggregator._ObservableProxyProvider(
        "example",
        _factory,
        registry=registry,
        exclude_tools=frozenset({"advertise_to_collector"}),
    )

    tool = await provider._get_tool("advertise_to_collector")

    assert tool is None
    list_tools.assert_not_awaited()


async def test_observable_proxy_provider_get_tool_still_resolves_non_excluded_tool() -> (
    None
):
    """exclude_tools only rules out its own names -- exercised through a fake
    client (not a mocked _list_tools) so the real cache-population path in
    fastmcp's base _get_tool()/_list_tools() runs unmodified."""
    mcp_tool = McpTool(name="query_jobs", input_schema={"type": "object"})

    class _FakeClient:
        async def __aenter__(self) -> Self:
            return self

        async def __aexit__(self, *exc_info: object) -> None:
            return None

        async def list_tools(self) -> list[McpTool]:
            return [mcp_tool]

    registry = ServiceRegistry()
    registry.register(_spec())
    provider = aggregator._ObservableProxyProvider(
        "example",
        _FakeClient,
        registry=registry,
        exclude_tools=frozenset({"advertise_to_collector"}),
    )

    tool = await provider._get_tool("query_jobs")

    assert tool is not None
    assert tool.name == "query_jobs"


async def test_observable_proxy_provider_list_tools_omits_excluded_tool_namespaced(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """tools/list must omit an excluded native name for a namespaced service
    (apply_namespace defaults true, route_prefix=None) -- the provider always
    sees native (pre-namespace) names regardless of namespacing, since
    fastmcp's Namespace transform adds the "<prefix>_" prefix from outside,
    after the provider (see registry.py's namespaced_tool_name docstring)."""
    kept = ProxyTool.from_mcp_tool(
        lambda: None, McpTool(name="query_jobs", input_schema={"type": "object"})
    )
    excluded = ProxyTool.from_mcp_tool(
        lambda: None,
        McpTool(name="advertise_to_collector", input_schema={"type": "object"}),
    )
    monkeypatch.setattr(
        aggregator.ProxyProvider,
        "_list_tools",
        AsyncMock(return_value=[kept, excluded]),
    )

    registry = ServiceRegistry()
    registry.register(_spec())

    async def _factory() -> Client:
        raise AssertionError("ProxyProvider._list_tools is stubbed above")

    provider = aggregator._ObservableProxyProvider(
        "example",
        _factory,
        registry=registry,
        exclude_tools=frozenset({"advertise_to_collector"}),
    )

    tools = await provider._list_tools()

    assert [t.name for t in tools] == ["query_jobs"]


async def test_observable_proxy_provider_list_tools_omits_excluded_tool_unnamespaced(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Same omission for an apply_namespace: false service, where native
    names already carry the backend's own self-declared prefix -- an
    exclude_tools entry must match the exact name the provider sees, prefix
    included."""
    kept = ProxyTool.from_mcp_tool(
        lambda: None,
        McpTool(name="condor_query_jobs", input_schema={"type": "object"}),
    )
    excluded = ProxyTool.from_mcp_tool(
        lambda: None,
        McpTool(name="condor_advertise_to_collector", input_schema={"type": "object"}),
    )
    monkeypatch.setattr(
        aggregator.ProxyProvider,
        "_list_tools",
        AsyncMock(return_value=[kept, excluded]),
    )

    registry = ServiceRegistry()
    registry.register(_spec())

    async def _factory() -> Client:
        raise AssertionError("ProxyProvider._list_tools is stubbed above")

    provider = aggregator._ObservableProxyProvider(
        "example",
        _factory,
        registry=registry,
        route_prefix="condor",
        exclude_tools=frozenset({"condor_advertise_to_collector"}),
    )

    tools = await provider._list_tools()

    assert [t.name for t in tools] == ["condor_query_jobs"]


async def test_observable_proxy_provider_warns_once_on_exclude_tools_typo(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A configured exclude_tools name that never appears in the backend's
    listing is likely a typo -- warn so it's visible in logs, but only once
    per service per process, not on every uncached tools/list."""
    tool = ProxyTool.from_mcp_tool(
        lambda: None, McpTool(name="query_jobs", input_schema={"type": "object"})
    )
    monkeypatch.setattr(
        aggregator.ProxyProvider, "_list_tools", AsyncMock(return_value=[tool])
    )

    registry = ServiceRegistry()
    registry.register(_spec())

    async def _factory() -> Client:
        raise AssertionError("ProxyProvider._list_tools is stubbed above")

    provider = aggregator._ObservableProxyProvider(
        "example",
        _factory,
        registry=registry,
        exclude_tools=frozenset({"advertsie_to_collector"}),  # deliberate typo
    )

    with structlog.testing.capture_logs() as logs:
        await provider._list_tools()
        await provider._list_tools()

    typo_events = [
        entry
        for entry in logs
        if entry["event"] == "aggregator.exclude_tools_not_found"
    ]
    assert len(typo_events) == 1
    assert typo_events[0]["service"] == "example"
    assert typo_events[0]["tools"] == ["advertsie_to_collector"]


async def test_observable_proxy_provider_no_typo_warning_when_exclude_tools_all_present(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tool = ProxyTool.from_mcp_tool(
        lambda: None,
        McpTool(name="advertise_to_collector", input_schema={"type": "object"}),
    )
    monkeypatch.setattr(
        aggregator.ProxyProvider, "_list_tools", AsyncMock(return_value=[tool])
    )

    registry = ServiceRegistry()
    registry.register(_spec())

    async def _factory() -> Client:
        raise AssertionError("ProxyProvider._list_tools is stubbed above")

    provider = aggregator._ObservableProxyProvider(
        "example",
        _factory,
        registry=registry,
        exclude_tools=frozenset({"advertise_to_collector"}),
    )

    with structlog.testing.capture_logs() as logs:
        await provider._list_tools()

    assert not [
        entry
        for entry in logs
        if entry["event"] == "aggregator.exclude_tools_not_found"
    ]


# ---------------------------------------------------------------------------
# Per-(subject, service) tools/list cache (issue #320)
# ---------------------------------------------------------------------------


class _FakeClock:
    """Stand-in for the ``time`` module's ``monotonic()``, patched in as
    ``aggregator.time`` -- mirrors ``_patch_context``'s "patch the name
    aggregator imports it under" pattern, so only aggregator.py's own
    ``time.monotonic()`` calls are affected, not asyncio's internals or any
    other module's. Lets TTL/negative-cache tests advance the clock
    deterministically instead of sleeping real seconds."""

    def __init__(self) -> None:
        self._now = 0.0

    def monotonic(self) -> float:
        return self._now

    def advance(self, seconds: float) -> None:
        self._now += seconds


class _CountingListClient:
    """Client double for ``_ObservableProxyProvider``'s ``client_factory``: records every list call (tools/resources/resource templates/prompts), returning a fixed list or raising a fixed error.

    ``wait_for``, when set, is awaited before returning/raising -- lets a
    test hold multiple concurrent list calls open at once to prove
    single-flight collapses them into one upstream call. One shared
    ``call_count`` across all four ``list_*`` methods is enough for every
    test using this double: each test only ever exercises one kind at a
    time, and the per-(subject, kind) cache under test (``_cached_list``)
    keeps each kind's misses independent regardless of this double sharing a
    single counter.
    """

    def __init__(
        self,
        *,
        tools: list[McpTool] | None = None,
        resources: list[Any] | None = None,
        resource_templates: list[Any] | None = None,
        prompts: list[Any] | None = None,
        error: Exception | None = None,
        wait_for: asyncio.Event | None = None,
    ) -> None:
        self.tools = tools if tools is not None else []
        self.resources = resources if resources is not None else []
        self.resource_templates = (
            resource_templates if resource_templates is not None else []
        )
        self.prompts = prompts if prompts is not None else []
        self.error = error
        self.wait_for = wait_for
        self.call_count = 0

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        return None

    async def _respond(self, items: list[Any]) -> list[Any]:
        self.call_count += 1
        if self.wait_for is not None:
            await self.wait_for.wait()
        if self.error is not None:
            raise self.error
        return items

    async def list_tools(self) -> list[McpTool]:
        return await self._respond(self.tools)

    async def list_resources(self) -> list[Any]:
        return await self._respond(self.resources)

    async def list_resource_templates(self) -> list[Any]:
        return await self._respond(self.resource_templates)

    async def list_prompts(self) -> list[Any]:
        return await self._respond(self.prompts)


def _tool(name: str) -> McpTool:
    return McpTool(name=name, input_schema={"type": "object"})


def _resource(name: str) -> McpResource:
    return McpResource(uri=f"mem://{name}", name=name)


def _resource_template(name: str) -> McpResourceTemplate:
    return McpResourceTemplate(uri_template=f"mem://{name}/{{id}}", name=name)


def _prompt(name: str) -> McpPrompt:
    return McpPrompt(name=name)


# Builds a raw item of the right shape for each ``_LIST_KIND_CASES``
# ``client_attr`` -- fastmcp's own ``ProxyResource``/``ProxyTemplate``/
# ``ProxyPrompt.from_mcp_*`` factories expect real mcp_types objects, not
# plain strings, so the generic every-kind tests below build one per kind.
_ITEM_BUILDERS: dict[str, Any] = {
    "tools": _tool,
    "resources": _resource,
    "resource_templates": _resource_template,
    "prompts": _prompt,
}


async def test_list_tools_cache_hit_within_ttl_skips_second_upstream_call(
    monkeypatch: pytest.MonkeyPatch, make_principal
) -> None:
    client = _CountingListClient(tools=[_tool("widget_a")])
    registry = ServiceRegistry()
    registry.register(_spec())
    provider = aggregator._ObservableProxyProvider(
        "example", lambda: client, registry=registry, cache_ttl=300.0
    )
    _patch_context(monkeypatch, make_principal(subject="alice"), active_backend=None)

    first = await provider._list_tools()
    second = await provider._list_tools()

    assert [t.name for t in first] == ["widget_a"]
    assert [t.name for t in second] == ["widget_a"]
    assert client.call_count == 1


async def test_list_tools_per_subject_isolation_one_401_one_success(
    monkeypatch: pytest.MonkeyPatch, make_principal
) -> None:
    """Two principals against the same service: alice's upstream listing
    401s, bob's succeeds -- neither may be served the other's cached
    outcome."""
    request = httpx2.Request("GET", "http://example.invalid")
    response = httpx2.Response(401, request=request)
    unauthorized = httpx2.HTTPStatusError(
        "unauthorized", request=request, response=response
    )
    alice_client = _CountingListClient(error=unauthorized)
    bob_client = _CountingListClient(tools=[_tool("widget_a")])

    registry = ServiceRegistry()
    registry.register(_spec())
    clients = {"alice": alice_client, "bob": bob_client}

    def _factory() -> Any:
        raise AssertionError("unused -- clients selected per call below")

    provider = aggregator._ObservableProxyProvider(
        "example", _factory, registry=registry, cache_ttl=300.0
    )

    for subject, client in clients.items():
        ctx = _patch_context(
            monkeypatch, make_principal(subject=subject), active_backend=None
        )
        ctx.recorded_state["__list_credential_status__:example"] = (True, None)
        monkeypatch.setattr(provider, "client_factory", lambda c=client: c)
        if subject == "alice":
            with pytest.raises(McpError):
                await provider._list_tools()
        else:
            tools = await provider._list_tools()
            assert [t.name for t in tools] == ["widget_a"]

    # Re-querying each subject again must still reflect their own outcome --
    # bob's success must never leak into alice's still-cached failure, and
    # vice versa.
    _patch_context(monkeypatch, make_principal(subject="alice"), active_backend=None)
    with pytest.raises(McpError):
        await provider._list_tools()
    assert alice_client.call_count == 1  # still cached, no retry yet

    _patch_context(monkeypatch, make_principal(subject="bob"), active_backend=None)
    tools = await provider._list_tools()
    assert [t.name for t in tools] == ["widget_a"]
    assert bob_client.call_count == 1  # still cached


async def test_list_tools_per_service_independent(
    monkeypatch: pytest.MonkeyPatch, make_principal
) -> None:
    """Two providers (two services) for the same subject cache independently
    -- one backend's listing never counts against another's cache."""
    registry = ServiceRegistry()
    registry.register(_spec(name="svc-a", prefix="a"))
    registry.register(_spec(name="svc-b", prefix="b"))
    client_a = _CountingListClient(tools=[_tool("a_widget")])
    client_b = _CountingListClient(tools=[_tool("b_widget")])
    provider_a = aggregator._ObservableProxyProvider(
        "svc-a", lambda: client_a, registry=registry, cache_ttl=300.0
    )
    provider_b = aggregator._ObservableProxyProvider(
        "svc-b", lambda: client_b, registry=registry, cache_ttl=300.0
    )
    _patch_context(monkeypatch, make_principal(subject="alice"), active_backend=None)

    await provider_a._list_tools()
    await provider_b._list_tools()
    await provider_a._list_tools()
    await provider_b._list_tools()

    assert client_a.call_count == 1
    assert client_b.call_count == 1


async def test_list_tools_ttl_expiry_refetches(
    monkeypatch: pytest.MonkeyPatch, make_principal
) -> None:
    clock = _FakeClock()
    monkeypatch.setattr(aggregator, "time", clock)
    client = _CountingListClient(tools=[_tool("widget_a")])
    registry = ServiceRegistry()
    registry.register(_spec())
    provider = aggregator._ObservableProxyProvider(
        "example", lambda: client, registry=registry, cache_ttl=100.0
    )
    _patch_context(monkeypatch, make_principal(subject="alice"), active_backend=None)

    await provider._list_tools()
    clock.advance(50.0)
    await provider._list_tools()
    assert client.call_count == 1  # still within TTL

    clock.advance(51.0)  # total 101s elapsed since the first fetch
    await provider._list_tools()
    assert client.call_count == 2


async def test_list_tools_cache_ttl_zero_disables_cache(
    monkeypatch: pytest.MonkeyPatch, make_principal
) -> None:
    client = _CountingListClient(tools=[_tool("widget_a")])
    registry = ServiceRegistry()
    registry.register(_spec())
    provider = aggregator._ObservableProxyProvider(
        "example", lambda: client, registry=registry, cache_ttl=0.0
    )
    _patch_context(monkeypatch, make_principal(subject="alice"), active_backend=None)

    await provider._list_tools()
    await provider._list_tools()

    assert client.call_count == 2


async def test_list_tools_negative_cache_reraises_without_relogging_then_retries_after_expiry(
    monkeypatch: pytest.MonkeyPatch, make_principal
) -> None:
    clock = _FakeClock()
    monkeypatch.setattr(aggregator, "time", clock)
    error = ConnectionError("connection refused")
    client = _CountingListClient(error=error)
    registry = ServiceRegistry()
    registry.register(_spec())
    provider = aggregator._ObservableProxyProvider(
        "example", lambda: client, registry=registry, cache_ttl=300.0
    )
    ctx = _patch_context(
        monkeypatch, make_principal(subject="alice"), active_backend=None
    )
    ctx.recorded_state["__list_credential_status__:example"] = (False, "unavailable")

    with structlog.testing.capture_logs() as logs:
        with pytest.raises(ConnectionError):
            await provider._list_tools()
        with pytest.raises(ConnectionError):
            await provider._list_tools()

    assert client.call_count == 1  # second call served from the negative cache
    failure_logs = [
        entry for entry in logs if entry["event"] == "aggregator.service_list_failed"
    ]
    assert len(failure_logs) == 1  # not re-logged on the cached re-raise
    assert registry.recent_list_failure("example") == "unavailable"

    # Past the negative TTL (30s): retried, not served stale.
    clock.advance(31.0)
    with pytest.raises(ConnectionError):
        await provider._list_tools()
    assert client.call_count == 2


async def test_list_tools_single_flight_concurrent_calls_one_upstream_listing(
    monkeypatch: pytest.MonkeyPatch, make_principal
) -> None:
    release = asyncio.Event()
    client = _CountingListClient(tools=[_tool("widget_a")], wait_for=release)
    registry = ServiceRegistry()
    registry.register(_spec())
    provider = aggregator._ObservableProxyProvider(
        "example", lambda: client, registry=registry, cache_ttl=300.0
    )
    _patch_context(monkeypatch, make_principal(subject="alice"), active_backend=None)

    tasks = [asyncio.create_task(provider._list_tools()) for _ in range(5)]
    await asyncio.sleep(0)  # let every task reach the (shared) upstream call
    assert client.call_count == 1  # single-flight: one in-flight listing
    release.set()
    results = await asyncio.gather(*tasks)

    assert client.call_count == 1
    for tools in results:
        assert [t.name for t in tools] == ["widget_a"]


async def test_list_tools_bypasses_cache_without_principal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _CountingListClient(tools=[_tool("widget_a")])
    registry = ServiceRegistry()
    registry.register(_spec())
    provider = aggregator._ObservableProxyProvider(
        "example", lambda: client, registry=registry, cache_ttl=300.0
    )
    _patch_context(monkeypatch, None, active_backend=None)

    await provider._list_tools()
    await provider._list_tools()

    assert client.call_count == 2


async def test_invalidate_subject_drops_only_that_subject(
    monkeypatch: pytest.MonkeyPatch, make_principal
) -> None:
    client = _CountingListClient(tools=[_tool("widget_a")])
    registry = ServiceRegistry()
    registry.register(_spec())
    provider = aggregator._ObservableProxyProvider(
        "example", lambda: client, registry=registry, cache_ttl=300.0
    )
    _patch_context(monkeypatch, make_principal(subject="alice"), active_backend=None)
    await provider._list_tools()
    _patch_context(monkeypatch, make_principal(subject="bob"), active_backend=None)
    await provider._list_tools()
    assert client.call_count == 2

    provider.invalidate_subject("alice")

    _patch_context(monkeypatch, make_principal(subject="bob"), active_backend=None)
    await provider._list_tools()
    assert client.call_count == 2  # bob still cached

    _patch_context(monkeypatch, make_principal(subject="alice"), active_backend=None)
    await provider._list_tools()
    assert client.call_count == 3  # alice's entry was dropped, refetched


async def test_invalidate_subject_cache_helper_targets_one_service(
    monkeypatch: pytest.MonkeyPatch, make_principal
) -> None:
    registry = ServiceRegistry()
    registry.register(_spec(name="svc-a", prefix="a"))
    registry.register(_spec(name="svc-b", prefix="b"))
    client_a = _CountingListClient(tools=[_tool("a_widget")])
    client_b = _CountingListClient(tools=[_tool("b_widget")])
    provider_a = aggregator._ObservableProxyProvider(
        "svc-a", lambda: client_a, registry=registry, cache_ttl=300.0
    )
    provider_b = aggregator._ObservableProxyProvider(
        "svc-b", lambda: client_b, registry=registry, cache_ttl=300.0
    )
    mcp = FastMCP(name="test")
    mcp.add_provider(provider_a)
    mcp.add_provider(provider_b)
    _patch_context(monkeypatch, make_principal(subject="alice"), active_backend=None)
    await provider_a._list_tools()
    await provider_b._list_tools()

    aggregator.invalidate_subject_cache(mcp, "alice", target="svc-a")

    await provider_a._list_tools()
    await provider_b._list_tools()

    assert client_a.call_count == 2  # svc-a's cache was dropped
    assert client_b.call_count == 1  # svc-b untouched


async def test_invalidate_subject_cache_helper_targets_all_services_when_none(
    monkeypatch: pytest.MonkeyPatch, make_principal
) -> None:
    registry = ServiceRegistry()
    registry.register(_spec(name="svc-a", prefix="a"))
    registry.register(_spec(name="svc-b", prefix="b"))
    client_a = _CountingListClient(tools=[_tool("a_widget")])
    client_b = _CountingListClient(tools=[_tool("b_widget")])
    provider_a = aggregator._ObservableProxyProvider(
        "svc-a", lambda: client_a, registry=registry, cache_ttl=300.0
    )
    provider_b = aggregator._ObservableProxyProvider(
        "svc-b", lambda: client_b, registry=registry, cache_ttl=300.0
    )
    mcp = FastMCP(name="test")
    mcp.add_provider(provider_a)
    mcp.add_provider(provider_b)
    _patch_context(monkeypatch, make_principal(subject="alice"), active_backend=None)
    await provider_a._list_tools()
    await provider_b._list_tools()

    aggregator.invalidate_subject_cache(mcp, "alice")

    await provider_a._list_tools()
    await provider_b._list_tools()

    assert client_a.call_count == 2
    assert client_b.call_count == 2


# ---------------------------------------------------------------------------
# Per-(subject, service) listing cache generalized to every kind
# (tools/resources/resource templates/prompts) -- production symptom:
# resources/prompts fanned out to every backend uncached on every reconnect,
# exactly like tools/list before issue #320's cache. All four kinds now share
# one mechanism (_ObservableProxyProvider._cached_list); these tests pin that
# resources/resource-templates/prompts get identical semantics to tools
# without re-testing every tools-specific edge case four times over -- the
# classify/log/record_list_failure behavior stays tools-only (see
# _list_tools_uncached), so it is not exercised here.
# ---------------------------------------------------------------------------

_LIST_KIND_CASES = [
    ("_list_tools", "tools"),
    ("_list_resources", "resources"),
    ("_list_resource_templates", "resource_templates"),
    ("_list_prompts", "prompts"),
]


@pytest.mark.parametrize(("method_name", "client_attr"), _LIST_KIND_CASES)
async def test_list_cache_hit_within_ttl_skips_second_upstream_call_every_kind(
    monkeypatch: pytest.MonkeyPatch,
    make_principal,
    method_name: str,
    client_attr: str,
) -> None:
    items = [_ITEM_BUILDERS[client_attr]("widget_a")]
    client = _CountingListClient(**{client_attr: items})
    registry = ServiceRegistry()
    registry.register(_spec())
    provider = aggregator._ObservableProxyProvider(
        "example", lambda: client, registry=registry, cache_ttl=300.0
    )
    _patch_context(monkeypatch, make_principal(subject="alice"), active_backend=None)

    first = await getattr(provider, method_name)()
    second = await getattr(provider, method_name)()

    # fastmcp's fetch wraps each raw mcp_types item into its Proxy* domain
    # object (ProxyTool/ProxyResource/etc), so compare by name rather than
    # full equality against the raw items passed into the client double.
    assert [item.name for item in first] == ["widget_a"]
    assert [item.name for item in second] == ["widget_a"]
    assert client.call_count == 1


@pytest.mark.parametrize(("method_name", "client_attr"), _LIST_KIND_CASES)
async def test_list_ttl_expiry_refetches_every_kind(
    monkeypatch: pytest.MonkeyPatch,
    make_principal,
    method_name: str,
    client_attr: str,
) -> None:
    clock = _FakeClock()
    monkeypatch.setattr(aggregator, "time", clock)
    items = [_ITEM_BUILDERS[client_attr]("widget_a")]
    client = _CountingListClient(**{client_attr: items})
    registry = ServiceRegistry()
    registry.register(_spec())
    provider = aggregator._ObservableProxyProvider(
        "example", lambda: client, registry=registry, cache_ttl=100.0
    )
    _patch_context(monkeypatch, make_principal(subject="alice"), active_backend=None)

    await getattr(provider, method_name)()
    clock.advance(50.0)
    await getattr(provider, method_name)()
    assert client.call_count == 1  # still within TTL

    clock.advance(51.0)  # total 101s elapsed since the first fetch
    await getattr(provider, method_name)()
    assert client.call_count == 2


@pytest.mark.parametrize(("method_name", "client_attr"), _LIST_KIND_CASES)
async def test_list_single_flight_concurrent_calls_one_upstream_listing_every_kind(
    monkeypatch: pytest.MonkeyPatch,
    make_principal,
    method_name: str,
    client_attr: str,
) -> None:
    release = asyncio.Event()
    items = [_ITEM_BUILDERS[client_attr]("widget_a")]
    client = _CountingListClient(wait_for=release, **{client_attr: items})
    registry = ServiceRegistry()
    registry.register(_spec())
    provider = aggregator._ObservableProxyProvider(
        "example", lambda: client, registry=registry, cache_ttl=300.0
    )
    _patch_context(monkeypatch, make_principal(subject="alice"), active_backend=None)

    tasks = [asyncio.create_task(getattr(provider, method_name)()) for _ in range(5)]
    await asyncio.sleep(0)  # let every task reach the (shared) upstream call
    assert client.call_count == 1  # single-flight: one in-flight listing
    release.set()
    results = await asyncio.gather(*tasks)

    assert client.call_count == 1
    for result in results:
        assert [item.name for item in result] == ["widget_a"]


async def test_invalidate_subject_drops_every_kind_not_just_tools(
    monkeypatch: pytest.MonkeyPatch, make_principal
) -> None:
    client = _CountingListClient(
        tools=[_tool("widget_a")],
        resources=[_resource("r1")],
        prompts=[_prompt("p1")],
    )
    registry = ServiceRegistry()
    registry.register(_spec())
    provider = aggregator._ObservableProxyProvider(
        "example", lambda: client, registry=registry, cache_ttl=300.0
    )
    _patch_context(monkeypatch, make_principal(subject="alice"), active_backend=None)
    await provider._list_tools()
    await provider._list_resources()
    await provider._list_prompts()
    assert client.call_count == 3

    provider.invalidate_subject("alice")

    await provider._list_tools()
    await provider._list_resources()
    await provider._list_prompts()

    assert client.call_count == 6  # every kind was dropped, all refetched


async def test_list_cache_bypass_logs_debug_event_when_no_principal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _CountingListClient(resources=[_resource("r1")])
    registry = ServiceRegistry()
    registry.register(_spec())
    provider = aggregator._ObservableProxyProvider(
        "example", lambda: client, registry=registry, cache_ttl=300.0
    )
    _patch_context(monkeypatch, None, active_backend=None)

    with structlog.testing.capture_logs() as logs:
        await provider._list_resources()

    bypass_logs = [
        entry for entry in logs if entry["event"] == "aggregator.list_cache_bypass"
    ]
    assert len(bypass_logs) == 1
    assert bypass_logs[0]["service"] == "example"
    assert bypass_logs[0]["kind"] == "resources"
    assert bypass_logs[0]["reason"] == "no_principal"


async def test_list_cache_bypass_logs_debug_event_when_no_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No ``_patch_context`` here at all -- ``get_context()`` runs for real
    outside of any active fastmcp request and raises ``RuntimeError``,
    exercising the other bypass reason."""
    client = _CountingListClient(prompts=[_prompt("p1")])
    registry = ServiceRegistry()
    registry.register(_spec())
    provider = aggregator._ObservableProxyProvider(
        "example", lambda: client, registry=registry, cache_ttl=300.0
    )

    with structlog.testing.capture_logs() as logs:
        await provider._list_prompts()

    bypass_logs = [
        entry for entry in logs if entry["event"] == "aggregator.list_cache_bypass"
    ]
    assert len(bypass_logs) == 1
    assert bypass_logs[0]["service"] == "example"
    assert bypass_logs[0]["kind"] == "prompts"
    assert bypass_logs[0]["reason"] == "no_context"


# ---------------------------------------------------------------------------
# x509 branch: broker-issued identity JWT injection (issue #112)
# ---------------------------------------------------------------------------


def _make_issuer():
    from test_broker_issued import _make_rsa_key, _private_pem

    from af_mcp_broker.credentials.broker_issued import BrokerTokenIssuer

    return BrokerTokenIssuer(
        private_key_pem=_private_pem(_make_rsa_key()),
        issuer="https://mcp.example.com",
        ttl_seconds=600,
    )


async def test_client_factory_x509_injects_broker_identity_jwt(
    settings: Any, make_principal, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_context(monkeypatch, make_principal(subject="sub-abc"))
    issuer = _make_issuer()
    spec = _spec(auth_type="x509")
    # A linked provider registered for this target -- the not-linked gate
    # added below (mirroring _bearer_factory's) now runs before minting, so
    # an authorized-call test that only cares about JWT injection needs a
    # linked provider on record for the resolve()/is_linked() check to pass.
    registry = CredentialRegistry()
    registry.register(spec.name, _FakeProvider(linked=True))

    client = await _make_client_factory(
        spec, registry, settings, _OPEN_POLICY, broker_token_issuer=issuer
    )()

    auth = client.transport.headers["Authorization"]
    assert auth.startswith("Bearer ")
    claims = issuer.verify(auth.removeprefix("Bearer "))
    assert claims is not None
    assert claims["sub"] == "sub-abc"
    assert claims["aud"] == "example"


async def test_client_factory_x509_call_time_aud_uses_effective_audience(
    settings: Any, make_principal, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When a service's name and audience diverge (issue #257), the call-time
    x509 mint stamps the backend's `audience`, NOT the (renamed) `name` -- so a
    service can be renamed without moving the aud every backend validates."""
    _patch_context(monkeypatch, make_principal(subject="sub-abc"))
    issuer = _make_issuer()
    spec = _spec(name="ami_service", auth_type="x509", audience="ami-mcp")
    registry = CredentialRegistry()
    registry.register(spec.name, _FakeProvider(linked=True))

    client = await _make_client_factory(
        spec, registry, settings, _OPEN_POLICY, broker_token_issuer=issuer
    )()

    claims = issuer.verify(
        client.transport.headers["Authorization"].removeprefix("Bearer ")
    )
    assert claims is not None
    assert claims["aud"] == "ami-mcp"


async def test_client_factory_x509_without_issuer_is_toolerror(
    settings: Any, make_principal, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_context(monkeypatch, make_principal(subject="sub-abc"))
    spec = _spec(auth_type="x509")

    with pytest.raises(ToolError, match="signing key"):
        await _make_client_factory(spec, CredentialRegistry(), settings, _OPEN_POLICY)()


async def test_client_factory_x509_not_linked_raises_friendly_error(
    settings: Any, make_principal, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The x509 branch gets the same not-linked gate _bearer_factory already
    has (before this fix it minted a broker identity token unconditionally
    and let the backend's own redeem call 404 instead) -- an unlinked x509
    caller must be told to link, at the broker, before any token is minted."""
    _patch_context(monkeypatch, make_principal(subject="sub-abc"))
    issuer = _make_issuer()
    spec = _spec(auth_type="x509")
    provider = _FakeProvider(linked=False)
    registry = CredentialRegistry()
    registry.register(spec.name, provider)

    with pytest.raises(ToolError, match="not linked") as excinfo:
        await _make_client_factory(
            spec, registry, settings, _OPEN_POLICY, broker_token_issuer=issuer
        )()

    # Same close-the-loop requirement as the bearer branch's not-linked
    # error (issue #153) -- and now also names af_link_identity so the
    # caller doesn't have to guess it exists.
    assert LIST_IDENTITIES_TOOL_NAME in str(excinfo.value)
    assert LIST_MCP_SERVERS_TOOL_NAME in str(excinfo.value)
    assert "af_link_identity" in str(excinfo.value)


async def test_client_factory_x509_not_linked_names_portal_deep_link(
    settings: Any, make_principal, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The not-linked error's portal URL deep-links straight to this
    provider's card (point 4 of the design), using target_to_alias's
    backend-name -> identity-provider-alias join -- the same URL format
    af_link_identity itself returns."""
    _patch_context(monkeypatch, make_principal(subject="sub-abc"))
    issuer = _make_issuer()
    spec = _spec(auth_type="x509")
    registry = CredentialRegistry()
    registry.register(spec.name, _FakeProvider(linked=False))

    with pytest.raises(ToolError) as excinfo:
        await _make_client_factory(
            spec,
            registry,
            settings,
            _OPEN_POLICY,
            broker_token_issuer=issuer,
            target_to_alias={spec.name: "x509"},
        )()

    portal = settings.portal_url.rstrip("/")
    assert f"{portal}/identities#identity-card-x509" in str(excinfo.value)


async def test_client_factory_x509_list_time_injects_header_best_effort(
    settings: Any, make_principal, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_context(monkeypatch, make_principal(subject="sub-abc"), active_backend=None)
    issuer = _make_issuer()
    spec = _spec(auth_type="x509")

    client = await _make_client_factory(
        spec, CredentialRegistry(), settings, _OPEN_POLICY, broker_token_issuer=issuer
    )()

    assert client.transport.headers["Authorization"].startswith("Bearer ")


async def test_client_factory_x509_list_time_aud_uses_effective_audience(
    settings: Any, make_principal, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The list-time x509 factory mint honors the audience/name split too
    (issue #257), so a portal/tools-list connection presents the same aud the
    call-time mint does."""
    _patch_context(monkeypatch, make_principal(subject="sub-abc"), active_backend=None)
    issuer = _make_issuer()
    spec = _spec(name="ami_service", auth_type="x509", audience="ami-mcp")

    client = await _make_client_factory(
        spec, CredentialRegistry(), settings, _OPEN_POLICY, broker_token_issuer=issuer
    )()

    claims = issuer.verify(
        client.transport.headers["Authorization"].removeprefix("Bearer ")
    )
    assert claims is not None
    assert claims["aud"] == "ami-mcp"


async def test_resolve_list_time_credential_x509_aud_uses_effective_audience(
    settings: Any, make_principal
) -> None:
    """The /v1 catalog list path (resolve_list_time_credential) mints the same
    audience-split aud as the aggregator's own factories (issue #257) -- the two
    list-time code paths must never disagree on the token they present."""
    issuer = _make_issuer()
    spec = _spec(name="ami_service", auth_type="x509", audience="ami-mcp")

    headers, skip_reason = await resolve_list_time_credential(
        spec,
        CredentialRegistry(),
        make_principal(subject="sub-abc"),
        broker_token_issuer=issuer,
    )

    assert skip_reason is None
    assert headers is not None
    claims = issuer.verify(headers["Authorization"].removeprefix("Bearer "))
    assert claims is not None
    assert claims["aud"] == "ami-mcp"


async def test_client_factory_x509_list_time_without_issuer_connects_bare(
    settings: Any, make_principal, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_context(monkeypatch, make_principal(subject="sub-abc"), active_backend=None)
    spec = _spec(auth_type="x509")

    client = await _make_client_factory(
        spec, CredentialRegistry(), settings, _OPEN_POLICY
    )()

    assert "Authorization" not in client.transport.headers


async def test_resolve_list_time_credential_krb5_mints_not_provider_issue(
    settings: Any, make_principal
) -> None:
    """resolve_list_time_credential's krb5 handling must mirror x509's --
    mint-and-inject an AF Broker Identity Token, never call provider.issue()
    -- the same invariant _make_client_factory's _krb5_factory list-time
    branch enforces (see
    test_client_factory_krb5_injects_broker_identity_jwt_not_provider_issue).
    Without a dedicated krb5 branch here, this falls through to
    _resolve_list_time_headers, which calls provider.issue() directly --
    exactly what the auth_type=krb5 design (backend redeems the ticket
    itself via POST /v1/credentials/krb5/redeem) exists to prevent."""
    issuer = _make_issuer()
    spec = _spec(name="krb5_service", auth_type="krb5", audience="krb5-mcp")
    provider = _FakeProvider(linked=True)
    registry = CredentialRegistry()
    registry.register(spec.name, provider)

    headers, skip_reason = await resolve_list_time_credential(
        spec,
        registry,
        make_principal(subject="sub-abc"),
        broker_token_issuer=issuer,
    )

    assert skip_reason is None
    assert headers is not None
    claims = issuer.verify(headers["Authorization"].removeprefix("Bearer "))
    assert claims is not None
    assert claims["sub"] == "sub-abc"
    assert claims["aud"] == "krb5-mcp"
    assert provider.issue_calls == []


# ---------------------------------------------------------------------------
# krb5 branch: broker-issued identity JWT injection, mirroring x509's
# "mint and inject, let the backend redeem separately" behavior (this plan's
# Task 2 adds POST /v1/credentials/krb5/redeem as that separate redeem call) --
# NOT the bearer branch's "mint via provider.issue() and inject that
# credential directly".
# ---------------------------------------------------------------------------


async def test_client_factory_krb5_auth_type_applies_backend_timeout(
    settings: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    # active_backend=None takes the tools/list-refresh path (connect without
    # raising the not-yet-supported error), so the timeout can be inspected
    # on the returned Client the same way as the "none"/"x509" branches above.
    _patch_context(monkeypatch, None, active_backend=None)
    spec = _spec(auth_type="krb5", timeout_seconds=5.0)
    client = await _make_client_factory(
        spec, CredentialRegistry(), settings, _OPEN_POLICY
    )()
    assert client._session_kwargs["read_timeout_seconds"] == 5.0


async def test_client_factory_krb5_call_without_principal_raises(
    settings: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_context(monkeypatch, None)
    spec = _spec(auth_type="krb5")
    factory = _make_client_factory(spec, CredentialRegistry(), settings, _OPEN_POLICY)
    with pytest.raises(ToolError, match="principal"):
        await factory()


async def test_client_factory_krb5_auth_type_lists_without_raising(
    settings: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A tools/list schema-cache refresh must still be able to connect to a
    krb5 backend to enumerate its tools -- only an actual tools/call (signalled
    by authorized_call_target matching this backend) hits the not-yet-supported
    error above."""
    _patch_context(monkeypatch, None, active_backend=None)
    spec = _spec(auth_type="krb5")
    factory = _make_client_factory(spec, CredentialRegistry(), settings, _OPEN_POLICY)
    client = await factory()
    assert isinstance(client, Client)
    assert "Authorization" not in client.transport.headers


async def test_client_factory_krb5_injects_broker_identity_jwt_not_provider_issue(
    settings: Any, make_principal, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The krb5 branch mints and injects an AF Broker Identity Token the same
    way x509 does -- it must NEVER call provider.issue() itself, since Task 2's
    POST /v1/credentials/krb5/redeem is what the *backend* calls to fetch the
    actual ticket (unlike the generic bearer branch, which mints a credential
    directly via provider.issue() and injects that)."""
    _patch_context(monkeypatch, make_principal(subject="sub-abc"))
    issuer = _make_issuer()
    spec = _spec(auth_type="krb5")
    provider = _FakeProvider(linked=True)
    registry = CredentialRegistry()
    registry.register(spec.name, provider)

    client = await _make_client_factory(
        spec, registry, settings, _OPEN_POLICY, broker_token_issuer=issuer
    )()

    auth = client.transport.headers["Authorization"]
    assert auth.startswith("Bearer ")
    claims = issuer.verify(auth.removeprefix("Bearer "))
    assert claims is not None
    assert claims["sub"] == "sub-abc"
    assert claims["aud"] == "example"
    assert provider.issue_calls == []


async def test_client_factory_krb5_call_time_aud_uses_effective_audience(
    settings: Any, make_principal, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Mirrors x509's audience/name split (issue #257) -- the call-time krb5
    mint stamps the backend's `audience`, NOT the (renamed) `name`."""
    _patch_context(monkeypatch, make_principal(subject="sub-abc"))
    issuer = _make_issuer()
    spec = _spec(name="krb5_service", auth_type="krb5", audience="krb5-mcp")
    registry = CredentialRegistry()
    registry.register(spec.name, _FakeProvider(linked=True))

    client = await _make_client_factory(
        spec, registry, settings, _OPEN_POLICY, broker_token_issuer=issuer
    )()

    claims = issuer.verify(
        client.transport.headers["Authorization"].removeprefix("Bearer ")
    )
    assert claims is not None
    assert claims["aud"] == "krb5-mcp"


async def test_client_factory_krb5_without_issuer_is_toolerror(
    settings: Any, make_principal, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_context(monkeypatch, make_principal(subject="sub-abc"))
    spec = _spec(auth_type="krb5")

    with pytest.raises(ToolError, match="signing key") as excinfo:
        await _make_client_factory(spec, CredentialRegistry(), settings, _OPEN_POLICY)()

    assert "krb5 service" in str(excinfo.value)


async def test_client_factory_krb5_not_linked_raises_friendly_error(
    settings: Any, make_principal, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Same not-linked gate x509/_bearer_factory already have -- an unlinked
    krb5 caller must be told to link, at the broker, before any token is
    minted."""
    _patch_context(monkeypatch, make_principal(subject="sub-abc"))
    issuer = _make_issuer()
    spec = _spec(auth_type="krb5")
    provider = _FakeProvider(linked=False)
    registry = CredentialRegistry()
    registry.register(spec.name, provider)

    with pytest.raises(ToolError, match="not linked") as excinfo:
        await _make_client_factory(
            spec, registry, settings, _OPEN_POLICY, broker_token_issuer=issuer
        )()

    assert LIST_IDENTITIES_TOOL_NAME in str(excinfo.value)
    assert LIST_MCP_SERVERS_TOOL_NAME in str(excinfo.value)
    assert "af_link_identity" in str(excinfo.value)
    assert provider.issue_calls == []


async def test_client_factory_krb5_list_time_injects_header_best_effort(
    settings: Any, make_principal, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_context(monkeypatch, make_principal(subject="sub-abc"), active_backend=None)
    issuer = _make_issuer()
    spec = _spec(auth_type="krb5")

    client = await _make_client_factory(
        spec, CredentialRegistry(), settings, _OPEN_POLICY, broker_token_issuer=issuer
    )()

    assert client.transport.headers["Authorization"].startswith("Bearer ")


async def test_client_factory_krb5_list_time_without_issuer_connects_bare(
    settings: Any, make_principal, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_context(monkeypatch, make_principal(subject="sub-abc"), active_backend=None)
    spec = _spec(auth_type="krb5")

    client = await _make_client_factory(
        spec, CredentialRegistry(), settings, _OPEN_POLICY
    )()

    assert "Authorization" not in client.transport.headers


# ---------------------------------------------------------------------------
# Stage 2a: real interactive elicitation on the not-linked path, before
# falling back to stage 1's plain _not_linked_error ToolError.
# ---------------------------------------------------------------------------


async def test_require_linked_returns_without_context_when_already_linked(
    settings: Any, make_principal
) -> None:
    """The common case -- most calls never reach the elicitation machinery
    at all, and this path doesn't even need get_context() patched, since
    is_linked() short-circuits before _require_linked ever touches it."""
    provider = _FakeProvider(linked=True)
    spec = _spec()

    await _require_linked(provider, make_principal(), spec, settings, None)


async def test_require_linked_skips_elicit_when_client_lacks_permission(
    settings: Any, make_principal, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A client that never declared elicitation support in its
    ClientCapabilities is never asked -- _client_supports_elicitation's
    introspection short-circuits straight to stage 1's plain error rather
    than attempting a doomed round trip."""
    ctx = _patch_context(monkeypatch, make_principal(), supports_elicitation=False)
    provider = _FakeProvider(linked=False)
    spec = _spec()

    with pytest.raises(ToolError, match="not linked") as excinfo:
        await _require_linked(provider, make_principal(), spec, settings, None)

    assert "still" not in str(excinfo.value)
    assert ctx.elicit_calls == []


@pytest.mark.parametrize(
    "elicit_result",
    [DeclinedElicitation(), CancelledElicitation()],
    ids=["declined", "cancelled"],
)
async def test_require_linked_declined_or_cancelled_raises_stage1_error(
    settings: Any,
    make_principal,
    monkeypatch: pytest.MonkeyPatch,
    elicit_result: DeclinedElicitation | CancelledElicitation,
) -> None:
    ctx = _patch_context(monkeypatch, make_principal(), elicit_result=elicit_result)
    provider = _FakeProvider(linked=False)
    spec = _spec()

    with pytest.raises(ToolError, match="not linked") as excinfo:
        await _require_linked(provider, make_principal(), spec, settings, None)

    assert "still" not in str(excinfo.value)
    assert len(ctx.elicit_calls) == 1


async def test_require_linked_accepted_with_cancel_option_raises_stage1_error(
    settings: Any, make_principal, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Defensive case: an accepted response carrying the "Cancel" option's
    own text (rather than a decline/cancel action) is treated the same as
    a decline -- only the exact retry option's text proceeds."""
    _patch_context(
        monkeypatch,
        make_principal(),
        elicit_result=AcceptedElicitation(data=aggregator._ELICIT_CANCEL_OPTION),
    )
    provider = _FakeProvider(linked=False)
    spec = _spec()

    with pytest.raises(ToolError, match="not linked") as excinfo:
        await _require_linked(provider, make_principal(), spec, settings, None)

    assert "still" not in str(excinfo.value)


async def test_require_linked_elicit_raising_falls_back_to_stage1_error(
    settings: Any, make_principal, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A client that declared elicitation support but whose elicit() call
    fails anyway (protocol mismatch, transport error, anything) must fall
    back cleanly -- never a crash, never a worse or different error than
    stage 1's baseline."""
    _patch_context(
        monkeypatch, make_principal(), elicit_error=RuntimeError("client exploded")
    )
    provider = _FakeProvider(linked=False)
    spec = _spec()

    with pytest.raises(ToolError, match="not linked") as excinfo:
        await _require_linked(provider, make_principal(), spec, settings, None)

    assert "still" not in str(excinfo.value)


async def test_require_linked_accepted_retry_now_linked_proceeds(
    settings: Any, make_principal, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Accepting "I've linked it -- try again" and the provider now
    reporting linked (the caller actually completed the portal flow) must
    let the caller proceed -- _require_linked returns normally, no
    exception, so the surrounding factory continues exactly as the
    already-linked path already does."""
    _patch_context(
        monkeypatch,
        make_principal(),
        elicit_result=AcceptedElicitation(data=aggregator._ELICIT_RETRY_OPTION),
    )
    provider = _RelinkingProvider()
    spec = _spec()

    await _require_linked(provider, make_principal(), spec, settings, None)

    assert provider.is_linked_calls == 2


async def test_require_linked_accepted_retry_still_not_linked_raises_distinct_error(
    settings: Any, make_principal, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Accepting "try again" but still not linked afterward gets a distinct
    "still not linked" error -- and exactly one elicitation attempt, never a
    second round trip (no re-elicit loop)."""
    ctx = _patch_context(
        monkeypatch,
        make_principal(),
        elicit_result=AcceptedElicitation(data=aggregator._ELICIT_RETRY_OPTION),
    )
    provider = _FakeProvider(linked=False)
    spec = _spec()

    with pytest.raises(ToolError, match="still not linked"):
        await _require_linked(provider, make_principal(), spec, settings, None)

    assert len(ctx.elicit_calls) == 1


async def test_require_linked_elicit_message_names_display_name_and_portal_url(
    settings: Any, make_principal, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The elicitation message names the identity provider's configured
    display_name (the same text af_list_identities/af_link_identity show)
    and deep-links to that provider's portal card -- and offers exactly the
    two designed response options."""
    ctx = _patch_context(monkeypatch, make_principal())
    provider = _FakeProvider(linked=False)
    spec = _spec()
    configs = {
        "x509": BrokerIssuedProviderConfig(
            alias="x509", display_name="Grid Certificate"
        )
    }

    with pytest.raises(ToolError):
        await _require_linked(
            provider,
            make_principal(),
            spec,
            settings,
            {spec.name: "x509"},
            configs,
        )

    assert len(ctx.elicit_calls) == 1
    message, options = ctx.elicit_calls[0]
    assert "Grid Certificate" in message
    portal = settings.portal_url.rstrip("/")
    assert f"{portal}/identities#identity-card-x509" in message
    assert options == [
        aggregator._ELICIT_RETRY_OPTION,
        aggregator._ELICIT_CANCEL_OPTION,
    ]


async def test_client_factory_bearer_elicitation_accepted_now_linked_proceeds(
    settings: Any, make_principal, monkeypatch: pytest.MonkeyPatch
) -> None:
    """End-to-end through _bearer_factory (not just _require_linked
    directly): an accepted-and-now-linked elicitation lets the factory
    continue on to mint and inject a real credential, exactly like the
    already-linked path -- proving _bearer_factory is actually wired to the
    shared _require_linked helper, not just a copy of its logic."""
    _patch_context(
        monkeypatch,
        make_principal(),
        elicit_result=AcceptedElicitation(data=aggregator._ELICIT_RETRY_OPTION),
    )
    spec = _spec(auth_type="bearer")
    provider = _RelinkingProvider(token="minted-after-link")
    registry = CredentialRegistry()
    registry.register(spec.name, provider)

    client = await _make_client_factory(spec, registry, settings, _OPEN_POLICY)()

    assert client.transport.headers["Authorization"] == "Bearer minted-after-link"


async def test_client_factory_x509_elicitation_accepted_now_linked_proceeds(
    settings: Any, make_principal, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Same end-to-end proof as the bearer test above, but for
    _x509_factory -- both factories share _require_linked rather than
    duplicating the elicitation logic."""
    _patch_context(
        monkeypatch,
        make_principal(subject="sub-abc"),
        elicit_result=AcceptedElicitation(data=aggregator._ELICIT_RETRY_OPTION),
    )
    issuer = _make_issuer()
    spec = _spec(auth_type="x509")
    provider = _RelinkingProvider()
    registry = CredentialRegistry()
    registry.register(spec.name, provider)

    client = await _make_client_factory(
        spec, registry, settings, _OPEN_POLICY, broker_token_issuer=issuer
    )()

    auth = client.transport.headers["Authorization"]
    assert auth.startswith("Bearer ")
    claims = issuer.verify(auth.removeprefix("Bearer "))
    assert claims is not None
    assert claims["sub"] == "sub-abc"


class TestClassifyFailureUnavailable:
    """issue #280 / B.3: a request that never got a correlated response used
    to be distinguished as "timeout" from a connection-level "unavailable"
    via ``McpError.error.code == httpx.codes.REQUEST_TIMEOUT``. fastmcp v4 /
    mcp SDK v2 no longer produce that code at all -- every proxy transport
    failure, timeouts included, normalizes to a plain ``INTERNAL_ERROR``
    (``_proxy_upstream_error``) -- so that probe is gone and every case
    below (including what used to be the "timeout" cases) is "unavailable"
    now. See _classify_failure's docstring for the full removal rationale."""

    def test_mcp_error_is_unavailable(self) -> None:
        exc = _mcp_error(
            httpx2.codes.INTERNAL_SERVER_ERROR,
            "Timed out while waiting for response to CallToolRequest. Waited 30.0 seconds.",
        )
        assert _classify_failure(exc, injected=False, skip_reason=None) == "unavailable"

    def test_mcp_error_other_code_is_also_unavailable(self) -> None:
        exc = _mcp_error(httpx2.codes.INTERNAL_SERVER_ERROR, "boom")
        assert _classify_failure(exc, injected=False, skip_reason=None) == "unavailable"

    def test_connect_error_is_unavailable(self) -> None:
        exc = httpx2.ConnectError("connection refused")
        assert _classify_failure(exc, injected=False, skip_reason=None) == "unavailable"

    def test_mcp_error_wrapped_in_exception_group_is_still_unavailable(self) -> None:
        """Mirrors the existing 401-in-a-BaseExceptionGroup coverage this
        function already has -- fastmcp's client runs I/O in anyio task
        groups, so the McpError can arrive wrapped."""
        exc = BaseExceptionGroup(
            "unhandled",
            [_mcp_error(httpx2.codes.INTERNAL_SERVER_ERROR, "boom")],
        )
        assert _classify_failure(exc, injected=False, skip_reason=None) == "unavailable"

    def test_skip_reason_still_takes_priority(self) -> None:
        """A deliberately-skipped credential mint is the precise reason
        regardless of what the resulting uncredentialed connection raised --
        same rule the docstring already states for "unavailable"."""
        exc = _mcp_error(httpx2.codes.INTERNAL_SERVER_ERROR, "boom")
        assert (
            _classify_failure(exc, injected=False, skip_reason="not_linked")
            == "not_linked"
        )


class TestClassifyFailureChainedWrapping:
    """fastmcp v4 wraps a proxy transport failure as a plain chained
    exception (``raise _proxy_upstream_error(error) from error``), not a
    ``BaseExceptionGroup`` like fastmcp's client I/O failures today --
    ``_iter_leaf_exceptions`` must walk ``__cause__``/``__context__`` too, or
    a 401 (or any other leaf classification cares about) reachable only via
    a chain stays invisible to ``_classify_failure``. These tests build the
    chained shape directly rather than depending on a real v4 proxy call, so
    they already pass on fastmcp 3.4.7 today; after B.3/B.4 they are the
    regression guard for the real thing."""

    def test_401_reachable_only_via_cause_chain_is_detected(self) -> None:
        request = httpx2.Request("GET", "http://example.invalid")
        response = httpx2.Response(401, request=request)
        inner = httpx2.HTTPStatusError(
            "unauthorized", request=request, response=response
        )
        outer = RuntimeError("proxy upstream error")
        outer.__cause__ = inner
        assert (
            _classify_failure(outer, injected=True, skip_reason=None) == "unauthorized"
        )

    def test_401_reachable_only_via_context_chain_is_detected(self) -> None:
        """``__context__`` (an implicit "while handling this, another
        exception occurred"), not just ``__cause__`` (an explicit ``raise
        ... from err``) -- ``_iter_leaf_exceptions`` must walk whichever one
        is actually set."""
        request = httpx2.Request("GET", "http://example.invalid")
        response = httpx2.Response(401, request=request)
        inner = httpx2.HTTPStatusError(
            "unauthorized", request=request, response=response
        )
        outer = RuntimeError("proxy upstream error")
        outer.__context__ = inner
        assert (
            _classify_failure(outer, injected=True, skip_reason=None) == "unauthorized"
        )

    def test_uninjected_401_via_chain_stays_unavailable(self) -> None:
        """Same chain shape, but no credential was injected for this
        attempt -- must stay "unavailable", not "unauthorized" (a stored
        credential can't have been rejected if none was ever sent)."""
        request = httpx2.Request("GET", "http://example.invalid")
        response = httpx2.Response(401, request=request)
        inner = httpx2.HTTPStatusError(
            "unauthorized", request=request, response=response
        )
        outer = RuntimeError("proxy upstream error")
        outer.__cause__ = inner
        assert (
            _classify_failure(outer, injected=False, skip_reason=None) == "unavailable"
        )


async def test_observable_proxy_provider_method_not_found_is_empty_not_a_failure() -> (
    None
):
    """A backend whose tools/list itself raises ``McpError(METHOD_NOT_FOUND)``
    (e.g. it declares no tools at all) is treated as "zero tools", not a
    listing failure: fastmcp's ``ProxyProvider._list_tools()`` already
    catches exactly this code and returns an empty list rather than raising.

    Verified against the installed fastmcp 3.4.7 source this is already
    true today, not a new behavior mcp SDK v2/fastmcp v4 introduces (a
    correction to this plan step's original framing, which claimed it was
    new in v4). Pinning it regardless: no exception ever reaches
    ``_ObservableProxyProvider`` for this case, so ``record_list_failure``
    must never fire and any previously recorded failure must still clear,
    identically before and after the SDK bump."""
    registry = ServiceRegistry()
    registry.register(_spec())
    registry.record_list_failure("example", "unavailable")

    class _FakeClient:
        async def __aenter__(self) -> Self:
            return self

        async def __aexit__(self, *exc_info: object) -> None:
            return None

        async def list_tools(self) -> list[Any]:
            raise _mcp_error(METHOD_NOT_FOUND, "Method not found")

    provider = aggregator._ObservableProxyProvider(
        "example", _FakeClient, registry=registry
    )

    tools = await provider._list_tools()

    assert tools == []
    assert registry.recent_list_failure("example") is None
