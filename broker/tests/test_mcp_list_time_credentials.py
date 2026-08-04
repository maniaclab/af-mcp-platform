from __future__ import annotations

import asyncio
import re
import time
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, Any

import pytest
import uvicorn
from conftest import make_claims
from fastmcp import Client, FastMCP
from fastmcp.client.transports import StreamableHttpTransport
from fastmcp.server.dependencies import get_http_headers
from fastmcp.utilities.http import find_available_port
from fastmcp.utilities.tests import run_server_async
from starlette.middleware import Middleware
from starlette.responses import JSONResponse

from af_mcp_broker.authorization import EntitlementPolicy
from af_mcp_broker.credentials import (
    CredentialKind,
    CredentialProvider,
    CredentialRegistry,
    ExecutionModel,
    IssuedCredential,
)
from af_mcp_broker.mcp import aggregator as aggregator_module
from af_mcp_broker.mcp.aggregator import build_aggregator
from af_mcp_broker.mcp.registry import BackendRegistry, BackendSpec

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from af_mcp_broker.identity import Principal

# ---------------------------------------------------------------------------
# Regression coverage for issue #121: tools/list returned nothing for
# auth-requiring backends because credentials were only ever minted for an
# authorized tools/call. "secure" below mirrors rucio-mcp -- an ASGI
# middleware in front of the FastMCP http app rejects any request lacking a
# recognizable bearer credential with a raw HTTP 401, before any JSON-RPC
# dispatch even happens (fastmcp's own tool-level auth wouldn't reproduce the
# bug: only middleware wrapping the whole route recreates a listing that
# itself needs a token). "open" is a normal auth_type="none" backend (proves
# the rest of the list still works); "dead" points at a port nobody is
# listening on (proves a genuinely-down backend still degrades gracefully).
# ---------------------------------------------------------------------------

_TOKEN_RE = re.compile(r"Bearer token-for-(\d+)")


def _auth_gated_backend() -> Any:
    mcp = FastMCP(name="auth-gated-backend")

    @mcp.tool
    def whoami() -> str | None:
        """Returns the raw Authorization header this backend actually
        received (already proven valid by the middleware below), so tests
        can distinguish per-user minted credentials and prove the caller's
        inbound Keycloak token was never forwarded."""
        return get_http_headers(include={"authorization"}).get("authorization")

    class _RequireMintedBearer:
        """Mirrors rucio-mcp's RequireAuthMiddleware: rejects unauthenticated
        initialize/tools/list (and everything else) with a 401 at the ASGI
        layer, before fastmcp's own JSON-RPC dispatch ever sees the request."""

        def __init__(self, app: Any) -> None:
            self.app = app

        async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
            if scope["type"] == "http":
                headers = dict(scope["headers"])
                auth = headers.get(b"authorization", b"").decode()
                if not _TOKEN_RE.fullmatch(auth):
                    response = JSONResponse({"error": "unauthorized"}, status_code=401)
                    await response(scope, receive, send)
                    return
            await self.app(scope, receive, send)

    return mcp.http_app(path="/mcp", middleware=[Middleware(_RequireMintedBearer)])


def _open_backend() -> FastMCP:
    mcp = FastMCP(name="open-backend")

    @mcp.tool
    def ping() -> str:
        return "pong"

    return mcp


@asynccontextmanager
async def _run_asgi_app(app: Any) -> AsyncIterator[str]:
    """Run an arbitrary ASGI app (not necessarily a bare FastMCP server)
    behind a real uvicorn server on an ephemeral port -- fastmcp's own
    run_server_async only accepts a FastMCP instance directly, which can't
    carry the ASGI-level auth middleware _auth_gated_backend() needs to
    reproduce issue #121 faithfully. Mirrors the identical helper in
    test_mcp_aggregator_integration.py.
    """
    port = find_available_port()
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
    server = uvicorn.Server(config)
    task = asyncio.create_task(server.serve())
    while not server.started:
        await asyncio.sleep(0.01)
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        await task


@pytest.fixture
async def secure_backend_url() -> AsyncIterator[str]:
    async with _run_asgi_app(_auth_gated_backend()) as url:
        yield f"{url}/mcp"


@pytest.fixture
async def open_backend_url() -> AsyncIterator[str]:
    async with run_server_async(_open_backend(), path="/mcp") as url:
        yield url


@pytest.fixture
def dead_backend_url() -> str:
    """A URL nobody is listening on -- connections must fail fast, and that
    failure must not prevent other backends from listing."""
    port = find_available_port()
    return f"http://127.0.0.1:{port}/mcp"


class _FakeListProvider(CredentialProvider):
    """Mints a deterministic, per-uid token the auth-gated backend's
    middleware recognizes (``token-for-<uid>``), so tests can tell whose
    credential reached the backend. ``unlinked_uids`` lets a single fixture
    cover both the linked and not-linked scenarios without a second
    aggregator/provider instance -- important for the cache-poisoning
    regression test below, which specifically needs *one* shared
    ProxyProvider instance across two different principals.
    """

    cred_class = "fake"
    execution_model = ExecutionModel.DELEGATED

    def __init__(self, *, unlinked_uids: frozenset[int] = frozenset()) -> None:
        self.unlinked_uids = unlinked_uids
        self.issue_calls: list[int] = []

    async def handles(self, target: str) -> bool:
        return True

    async def is_linked(self, principal: Principal) -> bool:
        return principal.uid not in self.unlinked_uids

    async def issue(
        self,
        principal: Principal,
        target: str,
        min_remaining_seconds: int = 300,
        passphrase: Any = None,
    ) -> IssuedCredential:
        self.issue_calls.append(principal.uid)
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


@pytest.fixture
def policy() -> EntitlementPolicy:
    # Each backend's required capability comes straight from its own
    # BackendSpec.required_capability below (issue #60), not from a
    # policy.yaml lookup, so this only needs to grant "read_data" itself.
    return EntitlementPolicy(
        group_capabilities={"atlas": ["read_data"], "__authenticated__": []},
    )


@pytest.fixture
def fake_provider() -> _FakeListProvider:
    # uid 333 ("carol" below) is deliberately never linked -- exercises the
    # not_linked classification and the cache-poisoning regression without a
    # second aggregator/provider instance.
    return _FakeListProvider(unlinked_uids=frozenset({333}))


@pytest.fixture
async def aggregator_url(
    settings: Any,
    policy: EntitlementPolicy,
    fake_provider: _FakeListProvider,
    secure_backend_url: str,
    open_backend_url: str,
    dead_backend_url: str,
) -> AsyncIterator[str]:
    registry = BackendRegistry()
    registry.register(
        BackendSpec(
            name="secure",
            prefix="secure",
            url=secure_backend_url,
            transport="http",
            required_capability="read_data",
            auth_type="bearer",
        )
    )
    registry.register(
        BackendSpec(
            name="open",
            prefix="open",
            url=open_backend_url,
            transport="http",
            required_capability="__none__",
            auth_type="none",
        )
    )
    registry.register(
        BackendSpec(
            name="dead",
            prefix="dead",
            url=dead_backend_url,
            transport="http",
            required_capability="read_data",
            auth_type="bearer",
        )
    )

    credential_registry = CredentialRegistry([])
    credential_registry.register("secure", fake_provider)
    credential_registry.register(
        "dead", fake_provider
    )  # mints fine; connection still fails

    mcp = build_aggregator(registry, settings, policy, credential_registry)
    async with run_server_async(mcp, path="/mcp") as url:
        yield url


def _bearer_client(url: str, token: str) -> Client:
    return Client(
        StreamableHttpTransport(url, headers={"Authorization": f"Bearer {token}"})
    )


def _token_for(uid: int, gid: int, unixname: str) -> Any:
    return make_claims(
        groups=["atlas"], posix={"uid": uid, "gid": gid, "unixname": unixname}
    )


async def test_linked_entitled_principal_sees_auth_gated_tools(
    aggregator_url: str, sig_key: Any, prime_jwks: Any
) -> None:
    """(a) With a linked identity and the required capability, tools/list
    through /mcp returns the auth-gated backend's namespaced tools -- the
    core issue #121 fix."""
    prime_jwks([sig_key.jwk])
    token = sig_key.sign(_token_for(111, 111, "alice"))

    async with _bearer_client(aggregator_url, token) as client:
        names = {t.name for t in await client.list_tools()}

    assert "secure_whoami" in names
    assert "open_ping" in names
    # (c) the genuinely-down "dead" backend contributes nothing but doesn't
    # prevent the other two from listing (provider_error_strategy="warn").
    assert not any(n.startswith("dead_") for n in names)


async def test_unlinked_principal_missing_secure_tools_rest_of_list_works(
    aggregator_url: str, sig_key: Any, prime_jwks: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """(b) An unlinked principal doesn't see the auth-gated backend's tools,
    the rest of the list still works, and the structured failure log is
    emitted with the "not_linked" classification."""
    prime_jwks([sig_key.jwk])
    token = sig_key.sign(_token_for(333, 333, "carol"))

    events: list[tuple[str, dict[str, Any]]] = []
    original_warning = aggregator_module.logger.warning

    def _capture(event: str, **kwargs: Any) -> Any:
        events.append((event, kwargs))
        return original_warning(event, **kwargs)

    monkeypatch.setattr(aggregator_module.logger, "warning", _capture)

    async with _bearer_client(aggregator_url, token) as client:
        names = {t.name for t in await client.list_tools()}

    assert "secure_whoami" not in names
    assert "open_ping" in names

    matches = [
        kwargs
        for event, kwargs in events
        if event == "aggregator.backend_list_failed"
        and kwargs.get("backend") == "secure"
    ]
    assert matches, events
    assert matches[0]["reason"] == "not_linked"


async def test_dead_backend_does_not_break_other_backends_listing(
    aggregator_url: str, sig_key: Any, prime_jwks: Any
) -> None:
    """(c) A genuinely-down backend (connection refused) still doesn't break
    listing for the other backends, even though it required a capability
    this principal has (so a mint is attempted and does succeed -- the
    failure is purely the connection itself)."""
    prime_jwks([sig_key.jwk])
    token = sig_key.sign(_token_for(111, 111, "alice"))

    async with _bearer_client(aggregator_url, token) as client:
        names = {t.name for t in await client.list_tools()}

    assert not any(n.startswith("dead_") for n in names)
    assert "secure_whoami" in names
    assert "open_ping" in names


async def test_authorized_call_unchanged_and_inbound_token_never_forwarded(
    aggregator_url: str, sig_key: Any, prime_jwks: Any
) -> None:
    """(d) tools/call behavior is unchanged for the authorized path, and
    (e) the caller's inbound Keycloak token is never forwarded upstream --
    the backend only ever sees the minted credential."""
    prime_jwks([sig_key.jwk])
    inbound_token = sig_key.sign(_token_for(111, 111, "alice"))

    async with _bearer_client(aggregator_url, inbound_token) as client:
        result = await client.call_tool("secure_whoami", {})

    assert result.data == "Bearer token-for-111"
    assert result.data != f"Bearer {inbound_token}"


async def test_per_user_isolation_during_list(
    aggregator_url: str, sig_key: Any, prime_jwks: Any, fake_provider: _FakeListProvider
) -> None:
    """(f) Two principals each get their own minted credential -- exercised
    at list time (not just call time, which test_mcp_credential_injection_
    integration.py already covers): both must see the auth-gated backend's
    tools, each having minted their own token to pass its middleware."""
    prime_jwks([sig_key.jwk])
    alice_token = sig_key.sign(_token_for(111, 111, "alice"))
    bob_token = sig_key.sign(_token_for(222, 222, "bob"))

    async with _bearer_client(aggregator_url, alice_token) as client:
        alice_names = {t.name for t in await client.list_tools()}
    async with _bearer_client(aggregator_url, bob_token) as client:
        bob_names = {t.name for t in await client.list_tools()}

    assert "secure_whoami" in alice_names
    assert "secure_whoami" in bob_names
    assert {111, 222} <= set(fake_provider.issue_calls)


async def test_unlinked_listing_does_not_poison_a_linked_callers_authorized_call(
    aggregator_url: str, sig_key: Any, prime_jwks: Any
) -> None:
    """Regression found while building this fix: fastmcp's ProxyProvider
    only writes its shared, process-wide by-name lookup cache (used by
    _get_tool() to resolve a specific tool during a tools/call's dispatch)
    after a _list_tools() call that didn't raise. An early version of this
    fix let an unlinked principal's list-time mint failure raise before
    ever attempting a connection -- which meant that cache never got
    populated, so a *different*, properly linked principal's later
    authorized tools/call had to re-trigger a listing during dispatch, and
    that listing's resulting exception was swallowed by fastmcp's
    AggregateProvider.get_tool() warn-and-skip handling into a bare
    "Unknown tool" -- silently losing the friendly, actionable ToolError.
    Falling back to an uncredentialed connection on mint failure (see
    _resolve_list_time_headers's docstring in aggregator.py) fixes this:
    the auth-gated backend's own 401 still excludes it from the unlinked
    caller's list, but doesn't poison the shared cache for anyone else.
    """
    prime_jwks([sig_key.jwk])
    carol_token = sig_key.sign(_token_for(333, 333, "carol"))  # unlinked
    alice_token = sig_key.sign(_token_for(111, 111, "alice"))  # linked

    async with _bearer_client(aggregator_url, carol_token) as client:
        carol_names = {t.name for t in await client.list_tools()}
    assert "secure_whoami" not in carol_names

    async with _bearer_client(aggregator_url, alice_token) as client:
        result = await client.call_tool("secure_whoami", {})

    assert result.data == "Bearer token-for-111"
