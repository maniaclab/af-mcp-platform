from __future__ import annotations

# GET /v1/catalog/{backend}/tools -- the portal's per-backend tool listing.
# The endpoint reuses the aggregator's list-time credential logic
# (aggregator.resolve_list_time_credential / fetch_service_tool_listing, the
# issue #121 best-effort mint), so these tests mirror
# test_mcp_list_time_credentials.py's backend zoo: an open backend, an
# auth-gated backend that 401s any request without a recognized minted
# bearer (rucio-mcp's shape), and a dead URL. Real HTTP backends throughout,
# no transport mocks -- only the FastAPI route itself is driven in-process
# via httpx's ASGITransport.
import asyncio
import json
import re
import time
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, Any

import httpx
import pytest
import uvicorn
from fastapi import FastAPI
from fastmcp import FastMCP
from fastmcp.server.dependencies import get_http_headers
from fastmcp.utilities.http import find_available_port
from fastmcp.utilities.tests import run_server_async
from starlette.middleware import Middleware
from starlette.responses import JSONResponse

from af_mcp_broker.api import catalog_tools
from af_mcp_broker.authorization import EntitlementPolicy
from af_mcp_broker.credentials import (
    CredentialKind,
    CredentialProvider,
    CredentialRegistry,
    ExecutionModel,
    IssuedCredential,
)
from af_mcp_broker.identity import keycloak_dependency
from af_mcp_broker.mcp.registry import ServiceRegistry, ServiceSpec

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable

    from af_mcp_broker.identity import Principal

_TOKEN_RE = re.compile(r"Bearer token-for-(\w+)")


def _auth_gated_backend() -> Any:
    """Mirrors rucio-mcp (and test_mcp_list_time_credentials.py's "secure"
    backend): an ASGI middleware 401s any request lacking a recognizable
    minted bearer before JSON-RPC dispatch, so even tools/list needs a
    credential."""
    mcp = FastMCP(name="auth-gated-backend")

    @mcp.tool
    def whoami() -> str | None:
        """Echo the Authorization header this backend received."""
        return get_http_headers(include={"authorization"}).get("authorization")

    class _RequireMintedBearer:
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
        """Answer with pong."""
        return "pong"

    @mcp.tool
    def submit(payload: str) -> str:
        """Pretend to submit something."""
        return payload

    return mcp


@asynccontextmanager
async def _run_asgi_app(app: Any) -> AsyncIterator[str]:
    """Run an arbitrary ASGI app behind a real uvicorn server on an ephemeral
    port -- mirrors the identical helper in test_mcp_list_time_credentials.py
    (and test_mcp_aggregator_integration.py): fastmcp's run_server_async only
    accepts a bare FastMCP instance, which can't carry the ASGI-level auth
    middleware _auth_gated_backend() needs."""
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
async def open_backend_url() -> AsyncIterator[str]:
    async with run_server_async(_open_backend(), path="/mcp") as url:
        yield url


@pytest.fixture
async def secure_backend_url() -> AsyncIterator[str]:
    async with _run_asgi_app(_auth_gated_backend()) as url:
        yield f"{url}/mcp"


@pytest.fixture
def dead_backend_url() -> str:
    port = find_available_port()
    return f"http://127.0.0.1:{port}/mcp"


class _FakeProvider(CredentialProvider):
    """Mints "token-for-<unixname>" (recognized by _auth_gated_backend's
    middleware) -- or a configurable garbage token to exercise the
    "unauthorized" classification (an injected credential the backend itself
    rejects)."""

    cred_class = "fake"
    execution_model = ExecutionModel.DELEGATED

    def __init__(
        self,
        *,
        unlinked_subjects: frozenset[str] = frozenset(),
        mint_garbage: bool = False,
    ) -> None:
        self.unlinked_subjects = unlinked_subjects
        self.mint_garbage = mint_garbage

    async def is_linked(self, principal: Principal) -> bool:
        return principal.subject not in self.unlinked_subjects

    async def issue(
        self,
        principal: Principal,
        target: str,
        min_remaining_seconds: int = 300,
        passphrase: Any = None,
    ) -> IssuedCredential:
        token = "bogus!" if self.mint_garbage else f"token-for-{principal.unixname}"
        return IssuedCredential(
            cred_class=self.cred_class,
            target=target,
            kind=CredentialKind.BEARER,
            expires_at=time.time() + 3600,
            payload={"access_token": token},
            audit_id="test-audit",
            source="test",
            execution_model=self.execution_model,
        )


@pytest.fixture
def policy() -> EntitlementPolicy:
    return EntitlementPolicy(
        group_permissions={"atlas": ["read_data"], "__authenticated__": []},
    )


def _spec(name: str, url: str, **overrides: Any) -> ServiceSpec:
    defaults: dict[str, Any] = {
        "prefix": name,
        "transport": "http",
        "required_permission": "__none__",
        "auth_type": "none",
        "description": f"The {name} backend.",
        "display_name": name.title(),
    }
    defaults.update(overrides)
    return ServiceSpec(name=name, url=url, **defaults)


def _make_app(
    registry: ServiceRegistry,
    policy: EntitlementPolicy,
    credential_registry: CredentialRegistry | None = None,
    principal_state: dict[str, Any] | None = None,
    broker_token_issuer: Any = None,
) -> tuple[FastAPI, dict[str, Any]]:
    """Minimal FastAPI app carrying only the new router plus the app.state
    the route reads -- same state names app.py's lifespan sets. Returns the
    app and the mutable ``{"principal": ...}`` holder (swap the value to
    change who the caller is, same trick as conftest's app_client)."""
    state = principal_state if principal_state is not None else {}
    app = FastAPI()
    app.include_router(catalog_tools.router, prefix="/v1")
    app.state.service_registry = registry
    app.state.entitlement_policy = policy
    app.state.credential_registry = credential_registry or CredentialRegistry()
    app.state.broker_token_issuer = broker_token_issuer
    app.dependency_overrides[keycloak_dependency] = lambda: state["principal"]
    return app, state


@asynccontextmanager
async def _api_client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


async def _get_tools(app: FastAPI, backend: str) -> httpx.Response:
    async with _api_client(app) as client:
        return await client.get(f"/v1/catalog/{backend}/tools")


# ---------------------------------------------------------------------------
# Shape and 404
# ---------------------------------------------------------------------------


async def test_unknown_backend_is_404(
    policy: EntitlementPolicy, make_principal: Callable[..., Any]
) -> None:
    app, state = _make_app(ServiceRegistry(), policy)
    state["principal"] = make_principal(groups=["atlas"])
    resp = await _get_tools(app, "no-such-backend")
    assert resp.status_code == 404, resp.text


async def test_open_backend_lists_namespaced_tools(
    policy: EntitlementPolicy,
    make_principal: Callable[..., Any],
    open_backend_url: str,
) -> None:
    registry = ServiceRegistry()
    registry.register(_spec("open", open_backend_url))
    app, state = _make_app(registry, policy)
    state["principal"] = make_principal(groups=[])

    resp = await _get_tools(app, "open")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["name"] == "open"
    assert body["display_name"] == "Open"
    assert body["description"] == "The open backend."
    assert body["status"] == "ok"
    assert body["status_detail"]
    tools = {t["name"]: t for t in body["tools"]}
    # apply_namespace=True (the default): names are what /mcp callers see.
    assert "open_ping" in tools
    assert tools["open_ping"]["description"]
    assert tools["open_ping"]["action_type"] == "read"
    # Light payload by design: never a tool's full input schema.
    assert "inputSchema" not in resp.text
    assert "input_schema" not in resp.text


async def test_display_name_falls_back_to_service_name(
    policy: EntitlementPolicy,
    make_principal: Callable[..., Any],
    open_backend_url: str,
) -> None:
    registry = ServiceRegistry()
    registry.register(_spec("open", open_backend_url, display_name=""))
    app, state = _make_app(registry, policy)
    state["principal"] = make_principal(groups=[])

    resp = await _get_tools(app, "open")
    assert resp.status_code == 200, resp.text
    assert resp.json()["display_name"] == "open"


async def test_apply_namespace_false_keeps_raw_tool_names(
    policy: EntitlementPolicy,
    make_principal: Callable[..., Any],
    open_backend_url: str,
) -> None:
    """A self-prefixing backend (rucio-mcp's shape) opts out of aggregator
    namespacing -- the listing must show its raw names, same as /mcp does."""
    registry = ServiceRegistry()
    registry.register(_spec("open", open_backend_url, apply_namespace=False))
    app, state = _make_app(registry, policy)
    state["principal"] = make_principal(groups=[])

    resp = await _get_tools(app, "open")
    assert resp.status_code == 200, resp.text
    names = {t["name"] for t in resp.json()["tools"]}
    assert "ping" in names
    assert "open_ping" not in names


async def test_action_type_reflects_policy_tool_overrides(
    make_principal: Callable[..., Any],
    open_backend_url: str,
) -> None:
    """Per-tool action_type resolves through the same get_action_type glob
    overrides real enforcement uses -- keyed by the namespaced name, exactly
    as AuthorizationMiddleware sees an invocation."""
    policy = EntitlementPolicy(
        group_permissions={"__authenticated__": []},
        target_action_types={"open": {"open_submit": "state_change"}},
    )
    registry = ServiceRegistry()
    registry.register(_spec("open", open_backend_url))
    app, state = _make_app(registry, policy)
    state["principal"] = make_principal(groups=[])

    resp = await _get_tools(app, "open")
    assert resp.status_code == 200, resp.text
    tools = {t["name"]: t["action_type"] for t in resp.json()["tools"]}
    assert tools["open_submit"] == "state_change"
    assert tools["open_ping"] == "read"


# ---------------------------------------------------------------------------
# Per-caller statuses -- a backend never vanishes; status says why instead.
# ---------------------------------------------------------------------------


async def test_permission_required_without_contacting_backend(
    policy: EntitlementPolicy,
    make_principal: Callable[..., Any],
    dead_backend_url: str,
) -> None:
    """A caller lacking the required permission gets "permission_required"
    -- derived locally, before any connection attempt (the dead URL proves
    no probe happened: it would classify "unavailable" instead)."""
    registry = ServiceRegistry()
    registry.register(
        _spec(
            "secure",
            dead_backend_url,
            required_permission="read_data",
            auth_type="bearer",
        )
    )
    app, state = _make_app(registry, policy)
    state["principal"] = make_principal(groups=[])

    resp = await _get_tools(app, "secure")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "permission_required"
    assert body["status_detail"]
    assert body["tools"] == []


async def test_not_linked_status_for_unlinked_caller(
    policy: EntitlementPolicy,
    make_principal: Callable[..., Any],
    secure_backend_url: str,
) -> None:
    registry = ServiceRegistry()
    registry.register(
        _spec(
            "secure",
            secure_backend_url,
            required_permission="read_data",
            auth_type="bearer",
        )
    )
    credential_registry = CredentialRegistry()
    credential_registry.register(
        "secure", _FakeProvider(unlinked_subjects=frozenset({"sub-abc"}))
    )
    app, state = _make_app(registry, policy, credential_registry)
    state["principal"] = make_principal(groups=["atlas"])

    resp = await _get_tools(app, "secure")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "not_linked"
    assert body["tools"] == []


async def test_linked_caller_lists_auth_gated_tools(
    policy: EntitlementPolicy,
    make_principal: Callable[..., Any],
    secure_backend_url: str,
) -> None:
    """The core reuse property: the endpoint mints the caller's credential
    through the same provider path the aggregator's list-time branch uses,
    so an auth-gated backend (401 without a token, rucio-mcp's shape) still
    lists."""
    registry = ServiceRegistry()
    registry.register(
        _spec(
            "secure",
            secure_backend_url,
            required_permission="read_data",
            auth_type="bearer",
        )
    )
    credential_registry = CredentialRegistry()
    credential_registry.register("secure", _FakeProvider())
    app, state = _make_app(registry, policy, credential_registry)
    state["principal"] = make_principal(groups=["atlas"])

    resp = await _get_tools(app, "secure")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "ok"
    assert "secure_whoami" in {t["name"] for t in body["tools"]}


async def test_unauthorized_when_injected_credential_is_rejected(
    policy: EntitlementPolicy,
    make_principal: Callable[..., Any],
    secure_backend_url: str,
) -> None:
    """A minted-and-injected credential the backend 401s means the stored
    credential itself is bad -- "unauthorized" (re-link is the fix), never
    conflated with "not_linked" or a generic outage."""
    registry = ServiceRegistry()
    registry.register(
        _spec(
            "secure",
            secure_backend_url,
            required_permission="read_data",
            auth_type="bearer",
        )
    )
    credential_registry = CredentialRegistry()
    credential_registry.register("secure", _FakeProvider(mint_garbage=True))
    app, state = _make_app(registry, policy, credential_registry)
    state["principal"] = make_principal(groups=["atlas"])

    resp = await _get_tools(app, "secure")
    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] == "unauthorized"


async def test_unavailable_when_backend_is_down(
    policy: EntitlementPolicy,
    make_principal: Callable[..., Any],
    dead_backend_url: str,
) -> None:
    registry = ServiceRegistry()
    registry.register(
        _spec(
            "dead",
            dead_backend_url,
            required_permission="read_data",
            auth_type="bearer",
        )
    )
    credential_registry = CredentialRegistry()
    credential_registry.register("dead", _FakeProvider())
    app, state = _make_app(registry, policy, credential_registry)
    state["principal"] = make_principal(groups=["atlas"])

    resp = await _get_tools(app, "dead")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "unavailable"
    assert body["tools"] == []


async def test_x509_backend_lists_with_broker_identity_token(
    policy: EntitlementPolicy,
    make_principal: Callable[..., Any],
    secure_backend_url: str,
) -> None:
    """An x509 backend gets an AF Broker Identity Token at list time,
    mirroring the aggregator's _x509_factory list-time branch."""

    class _StubIssuer:
        def mint(self, subject: str, target: str) -> tuple[str, float]:
            return f"token-for-{target}", time.time() + 300

    registry = ServiceRegistry()
    registry.register(
        _spec(
            "secure",
            secure_backend_url,
            required_permission="read_data",
            auth_type="x509",
        )
    )
    app, state = _make_app(registry, policy, broker_token_issuer=_StubIssuer())
    state["principal"] = make_principal(groups=["atlas"])

    resp = await _get_tools(app, "secure")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "ok"
    assert "secure_whoami" in {t["name"] for t in body["tools"]}


async def test_response_never_exposes_backend_url(
    policy: EntitlementPolicy,
    make_principal: Callable[..., Any],
    open_backend_url: str,
) -> None:
    registry = ServiceRegistry()
    registry.register(_spec("open", open_backend_url))
    app, state = _make_app(registry, policy)
    state["principal"] = make_principal(groups=[])

    resp = await _get_tools(app, "open")
    assert resp.status_code == 200, resp.text
    assert "url" not in json.dumps(resp.json())


# ---------------------------------------------------------------------------
# TTL cache -- one process-wide catalog of tool schemas per backend, so
# repeated expands don't fan out to the backend every time. Statuses are
# never cached: entitlement/linkage run per caller on every request.
# ---------------------------------------------------------------------------


def _counting_backend() -> tuple[Any, dict[str, int]]:
    """The open backend wrapped in an ASGI middleware that counts every HTTP
    request it receives -- the cache tests' observable: a cache hit performs
    no backend traffic at all, a miss does (initialize + tools/list)."""
    counter = {"requests": 0}
    inner = _open_backend().http_app(path="/mcp")

    class _CountRequests:
        def __init__(self, app: Any) -> None:
            self.app = app

        async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
            if scope["type"] == "http":
                counter["requests"] += 1
            await self.app(scope, receive, send)

    return _CountRequests(inner), counter


async def test_successful_listing_is_served_from_cache(
    policy: EntitlementPolicy,
    make_principal: Callable[..., Any],
) -> None:
    """After one successful listing, a repeat request within the TTL is
    answered from cache -- no backend traffic at all on the second call."""
    registry = ServiceRegistry()
    credential_registry = CredentialRegistry()
    app, state = _make_app(registry, policy, credential_registry)
    state["principal"] = make_principal(groups=[])

    backend_app, counter = _counting_backend()
    async with _run_asgi_app(backend_app) as url:
        registry.register(_spec("open", f"{url}/mcp"))
        first = await _get_tools(app, "open")
        assert first.status_code == 200, first.text
        assert first.json()["status"] == "ok"
        requests_after_first = counter["requests"]
        assert requests_after_first > 0

        second = await _get_tools(app, "open")
        assert second.status_code == 200, second.text
        body = second.json()
        assert body["status"] == "ok"
        assert "open_ping" in {t["name"] for t in body["tools"]}
        assert counter["requests"] == requests_after_first


async def test_tools_cache_ttl_zero_disables_caching(
    policy: EntitlementPolicy,
    make_principal: Callable[..., Any],
) -> None:
    registry = ServiceRegistry()
    app, state = _make_app(registry, policy)
    state["principal"] = make_principal(groups=[])

    backend_app, counter = _counting_backend()
    async with _run_asgi_app(backend_app) as url:
        registry.register(_spec("open", f"{url}/mcp", tools_cache_ttl=0))
        first = await _get_tools(app, "open")
        assert first.json()["status"] == "ok"
        requests_after_first = counter["requests"]

        second = await _get_tools(app, "open")
        assert second.json()["status"] == "ok"
        assert counter["requests"] > requests_after_first


async def test_cache_never_masks_a_degraded_callers_status(
    policy: EntitlementPolicy,
    make_principal: Callable[..., Any],
    secure_backend_url: str,
) -> None:
    """A linked caller's successful listing populates the cache, but an
    unlinked caller must still see "not_linked" -- their credential state is
    evaluated live on every request, never papered over by another caller's
    cached success."""
    registry = ServiceRegistry()
    registry.register(
        _spec(
            "secure",
            secure_backend_url,
            required_permission="read_data",
            auth_type="bearer",
        )
    )
    credential_registry = CredentialRegistry()
    credential_registry.register(
        "secure", _FakeProvider(unlinked_subjects=frozenset({"sub-unlinked"}))
    )
    app, state = _make_app(registry, policy, credential_registry)

    state["principal"] = make_principal(groups=["atlas"], subject="sub-linked")
    first = await _get_tools(app, "secure")
    assert first.json()["status"] == "ok"

    state["principal"] = make_principal(groups=["atlas"], subject="sub-unlinked")
    second = await _get_tools(app, "secure")
    body = second.json()
    assert body["status"] == "not_linked"
    assert body["tools"] == []
