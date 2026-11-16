"""Fakes and builders shared by the tests of ``test_mcp_aggregator``."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any, Self

from broker_state_helpers import aggregator_inputs
from mcp.types import Tool as McpTool
from signing_keys import private_pem, shared_rsa_key

from af_mcp_broker.authorization import EntitlementPolicy
from af_mcp_broker.credentials import (
    CredentialKind,
    CredentialProvider,
    CredentialRegistry,
    ExecutionModel,
    IssuedCredential,
)
from af_mcp_broker.credentials.broker_issued import BrokerTokenIssuer
from af_mcp_broker.mcp import aggregator
from af_mcp_broker.mcp.aggregator import (
    build_aggregator,
)
from af_mcp_broker.service_registry import (
    ServiceRegistry,
    ServiceSpec,
)

if TYPE_CHECKING:
    import asyncio

    import pytest
    from fastmcp import FastMCP

    from af_mcp_broker.credentials.errors import (
        CredentialError,
        NeedsUnlockError,
    )
    from af_mcp_broker.principal import Principal


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


# Every direct _make_client_factory() call below cares about credential
# resolution, not entitlement -- _bearer_factory's list-time branch (see
# aggregator.py) also gates on check_entitlement(), but that check takes
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
        needs_unlock: NeedsUnlockError | None = None,
        http_error: CredentialError | None = None,
        rejected: bool = False,
    ) -> None:
        self.linked = linked
        self.rejected_credential = rejected
        self.token = token
        self.needs_unlock = needs_unlock
        self.http_error = http_error
        self.issue_calls: list[tuple[int, str]] = []
        # (subject, access_token) per mark_rejected() call
        self.rejected: list[tuple[str, str]] = []

    async def is_linked(self, principal: Principal) -> bool:
        return self.linked

    async def is_rejected(self, principal: Principal) -> bool:
        return self.rejected_credential

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

    async def mark_rejected(self, principal: Principal, access_token: str) -> None:
        self.rejected.append((principal.subject, access_token))


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


def _build_namespaced_aggregator(
    monkeypatch: pytest.MonkeyPatch,
    settings: Any,
    clients: dict[str, _CountingListClient],
) -> tuple[FastMCP, aggregator.BackendProviders]:
    """Build an aggregator through ``build_aggregator`` so every backend is registered namespaced, exactly as in production.

    ``clients`` maps a service name to the double its backend connection
    resolves to; the service's prefix is derived from the name.
    """
    registry = ServiceRegistry()
    for name in clients:
        registry.register(_spec(name=name, prefix=name))
    monkeypatch.setattr(
        aggregator,
        "_make_client_factory",
        lambda spec, *_args, **_kwargs: lambda: clients[spec.name],
    )
    mcp = build_aggregator(
        registry,
        settings,
        EntitlementPolicy(),
        CredentialRegistry(),
        **aggregator_inputs(),
    )
    return mcp, mcp.backend_providers


def _make_issuer():

    return BrokerTokenIssuer(
        private_key_pem=private_pem(shared_rsa_key()),
        issuer="https://mcp.example.com",
        ttl_seconds=600,
    )
