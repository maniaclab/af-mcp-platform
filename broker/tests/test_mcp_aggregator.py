from __future__ import annotations

import inspect
import time
from datetime import timedelta
from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException
from fastmcp import FastMCP
from fastmcp.client import Client
from fastmcp.client.transports import SSETransport, StreamableHttpTransport
from fastmcp.exceptions import ToolError
from fastmcp.server.elicitation import (
    AcceptedElicitation,
    CancelledElicitation,
    DeclinedElicitation,
)
from fastmcp.server.providers.proxy import (
    default_proxy_log_handler,
    default_proxy_progress_handler,
)

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
    _make_client_factory,
    _require_linked,
    build_aggregator,
    populate_aggregator,
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
        "required_capability": "__none__",
    }
    defaults.update(overrides)
    return ServiceSpec(**defaults)


# Every direct _make_client_factory() call below cares about credential
# resolution, not entitlement -- _bearer_factory's list-time branch (see
# aggregator.py) now also gates on check_entitlement(), but that check takes
# the required capability straight from the spec (ServiceSpec.
# required_capability, see issue #60) rather than looking it up in
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
    new_policy = EntitlementPolicy(group_capabilities={"atlas": ["read_data"]})
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
    # deliberately avoids using).
    assert client.transport.forward_incoming_headers is False


def test_client_factory_none_auth_type_applies_backend_timeout(settings: Any) -> None:
    spec = _spec(auth_type="none", timeout_seconds=5.0)
    client = _make_client_factory(spec, CredentialRegistry(), settings, _OPEN_POLICY)()
    assert client._session_kwargs["read_timeout_seconds"] == timedelta(seconds=5.0)


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
    assert client._session_kwargs["read_timeout_seconds"] == timedelta(seconds=5.0)


async def test_client_factory_bearer_auth_type_applies_backend_timeout(
    settings: Any, make_principal, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_context(monkeypatch, make_principal(), active_backend=None)
    spec = _spec(auth_type="bearer", timeout_seconds=5.0)
    client = await _make_client_factory(
        spec, CredentialRegistry(), settings, _OPEN_POLICY
    )()
    assert client._session_kwargs["read_timeout_seconds"] == timedelta(seconds=5.0)


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
    assert client.transport.forward_incoming_headers is False


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
    policy = EntitlementPolicy(group_capabilities={"atlas": ["read_data"]})
    principal = make_principal(groups=["atlas"])
    ctx = _patch_context(monkeypatch, principal, active_backend=None)
    spec = _spec(auth_type="bearer", required_capability="read_data")
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
    """A caller who lacks the backend's required_capability shouldn't trigger
    a mint attempt during a listing at all -- EntitlementMiddleware already
    hides this backend's tools from such a caller's own tools/list response,
    so minting would just be wasted work (proven with an empty issue_calls
    list on a provider that WOULD otherwise happily mint)."""
    policy = EntitlementPolicy(group_capabilities={"atlas": ["read_data"]})
    principal = make_principal(groups=[])  # lacks read_data
    _patch_context(monkeypatch, principal, active_backend=None)
    spec = _spec(auth_type="bearer", required_capability="read_data")
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


async def test_client_factory_x509_list_time_without_issuer_connects_bare(
    settings: Any, make_principal, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_context(monkeypatch, make_principal(subject="sub-abc"), active_backend=None)
    spec = _spec(auth_type="x509")

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


async def test_require_linked_skips_elicit_when_client_lacks_capability(
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
