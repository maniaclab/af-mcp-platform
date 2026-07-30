from __future__ import annotations

import inspect
import time
from datetime import timedelta
from typing import TYPE_CHECKING, Any

import pytest
from fastapi import HTTPException
from fastmcp import FastMCP
from fastmcp.client import Client
from fastmcp.client.transports import SSETransport, StreamableHttpTransport
from fastmcp.exceptions import ToolError
from fastmcp.server.providers.proxy import (
    default_proxy_log_handler,
    default_proxy_progress_handler,
)

from af_mcp_broker.authorization import EntitlementPolicy
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
    build_aggregator,
    populate_aggregator,
)
from af_mcp_broker.mcp.middleware.authorization_mw import AuthorizationMiddleware
from af_mcp_broker.mcp.middleware.entitlement_mw import EntitlementMiddleware
from af_mcp_broker.mcp.middleware.identity_mw import IdentityMiddleware
from af_mcp_broker.mcp.registry import BackendRegistry, BackendSpec

if TYPE_CHECKING:
    from af_mcp_broker.identity import Principal


def _spec(**overrides: Any) -> BackendSpec:
    defaults: dict[str, Any] = {
        "name": "example",
        "prefix": "example",
        "url": "http://example.invalid/mcp",
        "transport": "http",
        "required_capability": "__none__",
    }
    defaults.update(overrides)
    return BackendSpec(**defaults)


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

    async def handles(self, target: str) -> bool:
        return True

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


class _FakeFastMCPContext:
    def __init__(self, principal: Principal | None, active_backend: str | None) -> None:
        self._principal = principal
        self._active_backend = active_backend

    async def get_state(self, key: str) -> Any:
        if key == "principal":
            return self._principal
        if key == "authorized_call_target":
            return self._active_backend
        raise AssertionError(f"unexpected state key {key!r}")


def _patch_context(
    monkeypatch: pytest.MonkeyPatch,
    principal: Principal | None,
    active_backend: str | None = "example",
) -> None:
    """_make_client_factory's bearer/x509 branches read the caller's
    Principal, and whether AuthorizationMiddleware stamped this request as a
    genuine tools/call for this backend, via
    fastmcp.server.dependencies.get_context() -- the same contextvar-scoped
    call ProxyTool.run() itself uses -- since a client_factory has no other
    hook into the current request. Patch the name aggregator imports it
    under, mirroring identity_mw's test pattern for get_http_headers.
    ``active_backend`` defaults to "example" to match ``_spec()``'s default
    name, simulating a genuine call for that backend."""
    monkeypatch.setattr(
        aggregator,
        "get_context",
        lambda: _FakeFastMCPContext(principal, active_backend),
    )


def test_build_aggregator_returns_fastmcp(settings: Any) -> None:
    mcp = build_aggregator(
        BackendRegistry(), settings, EntitlementPolicy(), CredentialRegistry([])
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
        BackendRegistry(), settings, EntitlementPolicy(), CredentialRegistry([])
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


def test_build_aggregator_registers_one_provider_per_backend(settings: Any) -> None:
    registry = BackendRegistry()
    registry.register(_spec(name="a", prefix="a"))
    registry.register(_spec(name="b", prefix="b"))

    mcp = build_aggregator(
        registry, settings, EntitlementPolicy(), CredentialRegistry([])
    )

    assert len(mcp.providers) == 2


def test_populate_aggregator_replaces_providers_not_appends(settings: Any) -> None:
    registry_a = BackendRegistry()
    registry_a.register(_spec(name="a", prefix="a"))
    mcp = build_aggregator(
        registry_a, settings, EntitlementPolicy(), CredentialRegistry([])
    )
    assert len(mcp.providers) == 1

    registry_b = BackendRegistry()
    registry_b.register(_spec(name="b", prefix="b"))
    registry_b.register(_spec(name="c", prefix="c"))
    populate_aggregator(
        mcp, registry_b, settings, EntitlementPolicy(), CredentialRegistry([])
    )

    assert len(mcp.providers) == 2


def test_populate_aggregator_refreshes_middleware_state(settings: Any) -> None:
    mcp = build_aggregator(
        BackendRegistry(), settings, EntitlementPolicy(), CredentialRegistry([])
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

    new_registry = BackendRegistry()
    new_registry.register(_spec(name="a", prefix="a"))
    new_policy = EntitlementPolicy(group_capabilities={"atlas": ["read_data"]})
    new_settings = settings.model_copy(update={"oidc_audience": "something-else"})

    populate_aggregator(
        mcp, new_registry, new_settings, new_policy, CredentialRegistry([])
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
            BackendRegistry(),
            settings,
            EntitlementPolicy(),
            CredentialRegistry([]),
        )


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
    factory = _make_client_factory(spec, CredentialRegistry([]), settings)
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
    client = _make_client_factory(spec, CredentialRegistry([]), settings)()
    assert client._session_kwargs["read_timeout_seconds"] == timedelta(seconds=5.0)


async def test_client_factory_x509_auth_type_applies_backend_timeout(
    settings: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    # active_backend=None takes the tools/list-refresh path (connect without
    # raising the not-yet-supported error), so the timeout can be inspected
    # on the returned Client the same way as the "none" branch above.
    _patch_context(monkeypatch, None, active_backend=None)
    spec = _spec(auth_type="x509", timeout_seconds=5.0)
    client = await _make_client_factory(spec, CredentialRegistry([]), settings)()
    assert client._session_kwargs["read_timeout_seconds"] == timedelta(seconds=5.0)


async def test_client_factory_bearer_auth_type_applies_backend_timeout(
    settings: Any, make_principal, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_context(monkeypatch, make_principal(), active_backend=None)
    spec = _spec(auth_type="bearer", timeout_seconds=5.0)
    client = await _make_client_factory(spec, CredentialRegistry([]), settings)()
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
    client = _make_client_factory(spec, CredentialRegistry([]), settings)()
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
    client = _make_client_factory(spec, CredentialRegistry([]), settings)()
    assert "Authorization" not in client.transport.headers


async def test_client_factory_x509_auth_type_raises_clear_tool_error(
    settings: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_context(monkeypatch, None)
    spec = _spec(auth_type="x509")
    factory = _make_client_factory(spec, CredentialRegistry([]), settings)
    with pytest.raises(ToolError, match="x509"):
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
    factory = _make_client_factory(spec, CredentialRegistry([]), settings)
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
    registry = CredentialRegistry([])
    registry.register(spec.name, provider)

    factory = _make_client_factory(spec, registry, settings)
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
    registry = CredentialRegistry([])
    registry.register(spec.name, provider)
    factory = _make_client_factory(spec, registry, settings)

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
    factory = _make_client_factory(spec, CredentialRegistry([]), settings)

    with pytest.raises(ToolError):
        await factory()


async def test_client_factory_bearer_not_linked_raises_friendly_error(
    settings: Any, make_principal, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_context(monkeypatch, make_principal())
    spec = _spec(auth_type="bearer")
    provider = _FakeProvider(linked=False)
    registry = CredentialRegistry([])
    registry.register(spec.name, provider)

    with pytest.raises(ToolError, match="not linked"):
        await _make_client_factory(spec, registry, settings)()


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
    registry = CredentialRegistry([])
    registry.register(spec.name, provider)

    with pytest.raises(ToolError, match="portal") as excinfo:
        await _make_client_factory(spec, registry, settings)()
    assert "/v1/x509/proxy" in str(excinfo.value)


async def test_client_factory_bearer_provider_http_exception_surfaces_detail(
    settings: Any, make_principal, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_context(monkeypatch, make_principal())
    spec = _spec(auth_type="bearer")
    provider = _FakeProvider(
        http_error=HTTPException(status_code=404, detail="No ATLAS IAM token stored")
    )
    registry = CredentialRegistry([])
    registry.register(spec.name, provider)

    with pytest.raises(ToolError, match="No ATLAS IAM token stored"):
        await _make_client_factory(spec, registry, settings)()


async def test_client_factory_bearer_missing_principal_raises(
    settings: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_context(monkeypatch, None)
    spec = _spec(auth_type="bearer")
    factory = _make_client_factory(spec, CredentialRegistry([]), settings)

    with pytest.raises(ToolError):
        await factory()


async def test_client_factory_bearer_lists_without_minting_when_not_an_active_call(
    settings: Any, make_principal, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A tools/list schema-cache refresh reuses the same client_factory as a
    real call, but must not mint a credential -- proven with an empty
    registry that would raise KeyError if resolve() were ever reached."""
    _patch_context(monkeypatch, make_principal(), active_backend=None)
    spec = _spec(auth_type="bearer")
    factory = _make_client_factory(spec, CredentialRegistry([]), settings)

    client = await factory()

    assert "Authorization" not in client.transport.headers
