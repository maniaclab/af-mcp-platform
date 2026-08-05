from __future__ import annotations

import asyncio
import re
import time
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, Any

import httpx
import pytest
import uvicorn
from conftest import make_claims, run_aggregator_async
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
from af_mcp_broker.mcp.aggregator import build_aggregator, build_asgi_auth_middleware
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
    # required_capability for each target ("secure"/"open"/"dead") is
    # declared on that target's BackendSpec in the aggregator_url fixture
    # below -- the registry is authoritative for that, not EntitlementPolicy
    # (see check_entitlement's docstring). This policy only needs to say
    # which capabilities the "atlas" group grants.
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
    static_principal_cache: Any,
) -> AsyncIterator[str]:
    # Each test persona minted via _token_for below now gets its own JWT
    # `sub` (issue #144 step 3b: POSIX identity comes from the directory,
    # keyed by subject, so two principals sharing a subject would be unable
    # to have distinct uids at all) -- give each of them "atlas" on the
    # directory here so this file's entitlement expectations are unaffected
    # by where that fact comes from (issue #144 step 3 did the same for a
    # single shared subject before POSIX needed one each).
    principal_cache, directory = static_principal_cache
    for uid, gid, unixname in _TEST_PERSONAS:
        sub = _subject_for(unixname)
        directory.groups_by_subject[sub] = ["atlas"]
        directory.posix_by_subject[sub] = {
            "uid": uid,
            "gid": gid,
            "unixname": unixname,
        }
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

    credential_registry = CredentialRegistry()
    credential_registry.register("secure", fake_provider)
    credential_registry.register(
        "dead", fake_provider
    )  # mints fine; connection still fails

    mcp = build_aggregator(
        registry, settings, policy, credential_registry, principal_cache=principal_cache
    )
    async with run_aggregator_async(mcp, path="/mcp") as url:
        yield url


def _bearer_client(url: str, token: str) -> Client:
    return Client(
        StreamableHttpTransport(url, headers={"Authorization": f"Bearer {token}"})
    )


# The fixed set of test personas this file's tests mint tokens for -- each
# needs its own JWT `sub` (issue #144 step 3b: POSIX identity, like groups,
# is a directory fact keyed by subject, so distinct principals can no longer
# share one), pre-registered on the test-controlled directory by the
# aggregator_url fixture above.
_TEST_PERSONAS: tuple[tuple[int, int, str], ...] = (
    (111, 111, "alice"),
    (222, 222, "bob"),
    (333, 333, "carol"),
)


def _subject_for(unixname: str) -> str:
    return f"user-{unixname}"


def _token_for(uid: int, gid: int, unixname: str) -> Any:
    # Neither groups nor POSIX identity travels via claims any more (issue
    # #144 steps 3/3b) -- the aggregator_url fixture above sets the matching
    # entitlement and uid/gid/unixname directly on the test-controlled
    # directory, keyed by this same subject. Asserting membership in
    # _TEST_PERSONAS here catches a typo'd/unregistered persona immediately,
    # rather than as a confusing downstream assertion failure.
    assert (uid, gid, unixname) in _TEST_PERSONAS
    return make_claims(sub=_subject_for(unixname))


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


async def test_list_then_call_on_healthy_backend_survives_a_sibling_401_during_list(
    aggregator_url: str, sig_key: Any, prime_jwks: Any
) -> None:
    """Attempted regression coverage for issue #58's "Session terminated"
    report: production showed a single MCP session doing tools/list (which
    succeeds -- some backends 401 during listing and are dropped per
    provider_error_strategy="warn", exactly like "secure" is for carol
    below) immediately followed by tools/call on an unrelated, healthy
    backend's tool -- with the server tearing the session down before the
    call was ever processed.

    This reproduces the same shape in-process (one client session, one
    backend 401ing during listing via a real ASGI 401 over a real HTTP
    connection -- same as the not_linked test above -- followed by
    tools/call on a different, healthy backend) and passes: the
    ProxyProvider/AggregateProvider exception-containment path already
    isolates "secure"'s listing failure from "open"'s tools/call in this
    exact scenario. It is kept as a regression guard for that isolation
    property, not as a confirmed repro of #58 -- see the issue for the
    investigation into what in-process reproduction could and couldn't
    establish.
    """
    prime_jwks([sig_key.jwk])
    token = sig_key.sign(_token_for(333, 333, "carol"))

    async with _bearer_client(aggregator_url, token) as client:
        names = {t.name for t in await client.list_tools()}
        assert "secure_whoami" not in names
        assert "open_ping" in names

        result = await client.call_tool("open_ping", {})

    assert result.data == "pong"


@pytest.mark.parametrize("stateless", [True, False])
async def test_replica_split_session_continuity(
    settings: Any,
    policy: EntitlementPolicy,
    open_backend_url: str,
    sig_key: Any,
    prime_jwks: Any,
    stateless: bool,
    static_principal_cache: Any,
) -> None:
    """Issue #128: a stateful aggregator (mcp_stateless_http=False, the
    fastmcp/mcp SDK default) pins a streamable-HTTP session to whichever pod
    created it. With more than one replica and no session-affinity ingress
    config, a load balancer routing a session's later requests to a
    different replica hits an unknown session there, which terminates it --
    surfacing as an intermittent "Session terminated" McpError to the
    client, invisible to any single-instance test.

    Simulates two replicas as two separate aggregator ASGI app instances
    built from the same registry/policy/credential config (mirrors two pods
    loading identical ConfigMap-sourced config), each with its own uvicorn
    server. Talks raw HTTP (rather than fastmcp's Client) so the exact same
    ``Mcp-Session-Id`` minted by replica 1's ``initialize`` can be replayed
    against replica 2's ``tools/call`` -- reproducing a load balancer
    routing one logical session's requests across replicas. Parametrized
    over both modes: stateless must succeed (no server-side session state is
    ever consulted), stateful must fail with 404 (replica 2 never minted
    that session id) -- proving this test would actually have caught #128
    before the fix, not just exercising a codepath that always passes.
    """
    principal_cache, _directory = static_principal_cache
    prime_jwks([sig_key.jwk])
    token = sig_key.sign(_token_for(111, 111, "alice"))

    registry = BackendRegistry()
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
    credential_registry = CredentialRegistry()

    def _replica() -> Any:
        mcp = build_aggregator(
            registry,
            settings,
            policy,
            credential_registry,
            principal_cache=principal_cache,
        )
        return mcp.http_app(
            path="/mcp",
            stateless_http=stateless,
            middleware=[build_asgi_auth_middleware(mcp)],
        )

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
    }

    async with (
        _run_asgi_app(_replica()) as replica_1_url,
        _run_asgi_app(_replica()) as replica_2_url,
        httpx.AsyncClient() as http_client,
    ):
        init_body = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "0"},
            },
        }
        init_resp = await http_client.post(
            f"{replica_1_url}/mcp", json=init_body, headers=headers
        )
        assert init_resp.status_code == 200
        session_id = init_resp.headers.get("mcp-session-id")
        assert stateless or session_id is not None

        call_headers = dict(headers)
        if session_id is not None:
            call_headers["Mcp-Session-Id"] = session_id
        call_body = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "open_ping", "arguments": {}},
        }
        call_resp = await http_client.post(
            f"{replica_2_url}/mcp", json=call_body, headers=call_headers
        )

    if stateless:
        assert call_resp.status_code == 200, call_resp.text
        assert '"result":"pong"' in call_resp.text.replace(" ", "")
    else:
        # Replica 2 never minted this session id -- exactly the production
        # failure: the client's request lands on a pod that terminates a
        # session it never created.
        assert call_resp.status_code == 404, call_resp.text
