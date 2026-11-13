from __future__ import annotations

import contextlib
import itertools
import json
import shutil
import socketserver
import subprocess
import time
from contextlib import asynccontextmanager, contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Self

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable, Iterator

    from fastmcp import FastMCP

import fastmcp
import httpx2
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from fastmcp.utilities.asgi_transport import StreamingASGITransport, run_asgi_lifespan
from fastmcp.utilities.http import find_available_port
from fastmcp.utilities.tests import ASGIServer, asgi_server
from jwt.algorithms import RSAAlgorithm
from pydantic import SecretStr

from af_mcp_broker import identity
from af_mcp_broker.audit import measure
from af_mcp_broker.config import Settings, get_settings
from af_mcp_broker.mcp import aggregator as aggregator_module
from af_mcp_broker.mcp.aggregator import build_asgi_auth_middleware

# fastmcp v4's camelCase compat bridge (mcp_camelcase_compat, default True)
# lets legacy reads like `tool.inputSchema`/`result.isError` keep working
# after mcp SDK v2's rename to snake_case, each emitting a
# FastMCPDeprecationWarning. Disabled for the whole test session (issue
# #238 B.2/B.10) to prove no camelCase read survives anywhere in the
# broker or its tests: with the bridge off, a lingering camelCase access
# raises AttributeError outright instead of silently warning.
fastmcp.settings.mcp_camelcase_compat = False

ISSUER = "https://keycloak.test/realms/connect"
AUDIENCE = "mcp-gateway"

# Point tests at the YAML files that actually ship with the broker so the
# entitlement decisions exercised here match production config.
_SRC = Path(__file__).resolve().parents[1] / "src" / "af_mcp_broker"
SHIPPED_POLICY = _SRC / "authorization" / "policy.yaml"
SHIPPED_SERVICES = _SRC / "mcp" / "services.yaml"

# Default `identity_providers` entry `app_client_factory` configures below —
# one keycloak-brokered provider bound to the historic default OIDCProvider
# targets, so `bearer`-auth backends (e.g. "rucio" in SHIPPED_SERVICES) still
# resolve to an OIDCProvider instance the way they did before issue #66 PR4
# replaced the single `oidc_idp_alias`-derived singleton with per-entry
# `identity_providers` config; plus a legacy-mode x509 entry (no
# `service_url`) covering SHIPPED_SERVICES' "ami" — every `auth_type: x509`
# backend must be covered by an explicit entry or the broker refuses to
# start (app.py's `_validate_x509_provider_targets`), so this fixture
# supplies the minimal one the shipped services.yaml needs. Tests that care
# about a specific `identity_providers` shape (test_identities.py,
# test_oauth21*.py, test_wellknown_cimd.py) override IDENTITY_PROVIDERS
# themselves.
_DEFAULT_IDENTITY_PROVIDERS = [
    {
        "type": "keycloak-brokered",
        "alias": "atlas-oidc",
        "display_name": "ATLAS IAM",
        "enables": "VOMS proxy generation and grid certificate credential brokering",
        "targets": ["rucio", "opendata", "af-internal"],
    },
    {
        "type": "x509",
        "alias": "x509",
        "display_name": "Grid certificate (x509)",
        "enables": (
            "VOMS proxy minting for x509-authenticated backends from your "
            "grid certificate"
        ),
        "targets": ["ami"],
    },
]


class _StubTiktokenEncoding:
    """Deterministic stand-in for a tiktoken Encoding: one token per 4 characters, minimum 1."""

    def encode(self, text: str, **kwargs: Any) -> list[int]:
        return [0] * max(1, len(text) // 4)


@pytest.fixture(autouse=True)
def stub_tiktoken(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep the suite off the network: tiktoken downloads encoding files
    from a CDN on first use, and audit/measure.py loads its encoding lazily
    inside the tool-call path, so any test driving a successful tool call
    with a non-empty result would otherwise trigger a download mid-suite.
    Replace the loader with a deterministic stub for every test and reset
    measure.py's module-level cache so no test observes another's load.
    test_measure.py re-patches the loader per-test where it exercises the
    loading/degradation behavior itself."""
    monkeypatch.setattr(measure, "_encoding", None)
    monkeypatch.setattr(measure, "_encoding_load_failed", False)
    monkeypatch.setattr(
        measure.tiktoken, "get_encoding", lambda name: _StubTiktokenEncoding()
    )


@pytest.fixture(autouse=True)
def fast_metrics_server_shutdown(monkeypatch: pytest.MonkeyPatch) -> None:
    """Shrink socketserver's serve_forever poll so app teardown is fast.

    The app lifespan runs prometheus_client's metrics server on a thread
    whose ``serve_forever`` uses the stdlib default ``poll_interval=0.5``;
    ``shutdown()`` blocks until that poll loop notices the flag, so every
    ``TestClient(app)`` teardown paid up to 0.5s of pure waiting. Tightening
    the poll interval changes only shutdown latency -- the exact same
    production code path (start, serve, shutdown) is still exercised.
    """
    orig = socketserver.BaseServer.serve_forever

    def fast_poll(self: Any, poll_interval: float = 0.005) -> None:
        orig(self, poll_interval)

    monkeypatch.setattr(socketserver.BaseServer, "serve_forever", fast_poll)


@dataclass
class RsaKey:
    """An RSA keypair plus its published JWK (with a stable ``kid``)."""

    kid: str
    private: rsa.RSAPrivateKey

    @property
    def jwk(self) -> dict[str, Any]:
        pub = json.loads(RSAAlgorithm.to_jwk(self.private.public_key()))
        pub.update({"kid": self.kid, "use": "sig", "alg": "RS256"})
        return pub

    def sign(self, claims: dict[str, Any]) -> str:
        return jwt.encode(
            claims, self.private, algorithm="RS256", headers={"kid": self.kid}
        )


def _make_key(kid: str) -> RsaKey:
    return RsaKey(
        kid=kid, private=rsa.generate_private_key(public_exponent=65537, key_size=2048)
    )


# Session-scoped: a 2048-bit keygen costs ~40ms, and well over a hundred
# tests request these fixtures -- that's seconds of pure prime hunting per
# run. The keys are interchangeable, read-only test material (tests only
# call .sign()/.jwk, never mutate), and the two kids stay distinct, so one
# generated-once pair serves the whole run without coupling tests.
@pytest.fixture(scope="session")
def sig_key() -> RsaKey:
    return _make_key("sig-key")


@pytest.fixture(scope="session")
def enc_key() -> RsaKey:
    return _make_key("enc-key")


@pytest.fixture(scope="session")
def postgres_dsn(tmp_path_factory: pytest.TempPathFactory) -> Iterator[str]:
    """DSN of a real, throwaway postgres started for this test session.

    Loopback TCP on a random free port (unix sockets disabled entirely --
    their path-length limit is easy to trip under pytest temp dirs), trust
    auth (it only ever listens on 127.0.0.1 for the lifetime of one test
    run), fsync off for speed on a database we're about to delete.
    """
    for binary in ("initdb", "pg_ctl"):
        if shutil.which(binary) is None:
            raise RuntimeError(
                f"{binary} not found -- the dev pixi environment provides "
                "the postgresql server these tests require (pixi.toml's dev "
                "feature); run via `pixi run -e dev pytest`."
            )

    datadir = tmp_path_factory.mktemp("pg") / "data"
    subprocess.run(
        ["initdb", "-D", str(datadir), "-U", "postgres", "--auth=trust", "--no-sync"],
        check=True,
        capture_output=True,
    )
    port = find_available_port()
    subprocess.run(
        [
            "pg_ctl",
            "-D",
            str(datadir),
            "-l",
            str(datadir / "server.log"),
            "-w",
            "-o",
            f"-p {port} -c listen_addresses=127.0.0.1 "
            "-c unix_socket_directories='' -c fsync=off",
            "start",
        ],
        check=True,
        capture_output=True,
    )
    try:
        yield f"postgresql://postgres@127.0.0.1:{port}/postgres"
    finally:
        subprocess.run(
            ["pg_ctl", "-D", str(datadir), "-m", "immediate", "stop"],
            check=False,
            capture_output=True,
        )


@pytest.fixture
def settings() -> Settings:
    return Settings(
        oidc_issuer=ISSUER,
        oidc_audience=AUDIENCE,
    )


@pytest.fixture
def prime_jwks(settings: Settings):
    """Seed the in-process JWKS TTL cache so no network fetch happens.

    Returns a callable that installs a given list of JWKs for the test's
    settings URI.
    """

    def _install(jwks: list[dict[str, Any]]) -> None:
        identity._jwks_cache[settings.oidc_jwks_uri] = identity._JwksEntry(
            keys=jwks, fetched_at=time.monotonic()
        )

    yield _install
    identity._jwks_cache.pop(settings.oidc_jwks_uri, None)


class HungBackend:
    """ASGI app that reads each request and never responds, recording how many requests arrived and how many connections were later closed by the client."""

    def __init__(self) -> None:
        self.requests = 0
        self.disconnects = 0

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] == "lifespan":
            # run_asgi_lifespan (the in-process harness) requires the handshake
            # to complete; uvicorn tolerates its absence.
            while True:
                message = await receive()
                if message["type"] == "lifespan.startup":
                    await send({"type": "lifespan.startup.complete"})
                else:
                    await send({"type": "lifespan.shutdown.complete"})
                    return
        if scope["type"] != "http":
            return
        self.requests += 1
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                self.disconnects += 1
                return


# fastmcp's Client has no default init_timeout (and no request timeout), so a
# test that connects to an app that never answers would wait for
# pytest-timeout (300 s) -- the silent-hang class of #237. Every Client built
# in the suite gets these bounds unless the caller passes its own.
_CLIENT_DEFAULT_TIMEOUT = 10.0


@pytest.fixture(autouse=True)
def _bound_client_timeouts(monkeypatch: pytest.MonkeyPatch) -> None:
    """Default every fastmcp Client's init_timeout and timeout to _CLIENT_DEFAULT_TIMEOUT."""
    orig_init = fastmcp.Client.__init__

    def bounded_init(self: Any, *args: Any, **kwargs: Any) -> None:
        kwargs.setdefault("init_timeout", _CLIENT_DEFAULT_TIMEOUT)
        if kwargs.get("timeout") is None:
            kwargs["timeout"] = _CLIENT_DEFAULT_TIMEOUT
        orig_init(self, *args, **kwargs)

    monkeypatch.setattr(fastmcp.Client, "__init__", bounded_init)


# --- In-process backends --------------------------------------------------
# The aggregator reaches each backend through an httpx2 client built by
# aggregator._checked_httpx_client_factory (which installs the #314 401 hook
# and the #362 invalid-response hook). _route_backends_in_process wraps that
# factory to add ``transport=`` -- an httpx2 client kwarg the factory already
# forwards -- so every hook, timeout and header still runs and only the
# bytes' path changes: a request to a host registered here is dispatched
# straight into that backend's ASGI app on the test's event loop (fastmcp's
# StreamingASGITransport: no socket, no uvicorn, no connection to reset or
# leave dead-but-open). Any other host (e.g. a port nothing listens
# on) still goes over a real connection, which is what the dead-backend
# tests need.
# host -> backend ASGI app; emptied after every test by the autouse fixture.
_IN_PROCESS_BACKENDS: dict[str, Any] = {}
_BACKEND_IDS = itertools.count()


class _BackendRouter(httpx2.AsyncBaseTransport):
    """httpx2 transport sending each request to the in-process backend registered for its URL host, or over the network when none is."""

    def __init__(self) -> None:
        self._stack = contextlib.AsyncExitStack()
        self._network = httpx2.AsyncHTTPTransport()
        self._routes: dict[str, StreamingASGITransport] = {}

    async def __aenter__(self) -> Self:
        # One ASGI transport per registered backend, each owning its own task
        # group for that backend's request handlers; the router belongs to a
        # single client, so those tasks end with the client.
        await self._stack.enter_async_context(self._network)
        for host, app in _IN_PROCESS_BACKENDS.items():
            self._routes[host] = await self._stack.enter_async_context(
                StreamingASGITransport(app)
            )
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self._stack.__aexit__(*exc_info)

    async def handle_async_request(self, request: httpx2.Request) -> httpx2.Response:
        route = self._routes.get(request.url.host, self._network)
        return await route.handle_async_request(request)


@pytest.fixture(autouse=True)
def _route_backends_in_process(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Route the aggregator's outbound backend traffic through _BackendRouter."""
    orig = aggregator_module._checked_httpx_client_factory

    def routed(*args: Any, **kwargs: Any) -> Callable[..., httpx2.AsyncClient]:
        inner = orig(*args, **kwargs)

        def factory(*f_args: Any, **f_kwargs: Any) -> httpx2.AsyncClient:
            f_kwargs.setdefault("transport", _BackendRouter())
            return inner(*f_args, **f_kwargs)

        return factory

    monkeypatch.setattr(aggregator_module, "_checked_httpx_client_factory", routed)
    yield
    _IN_PROCESS_BACKENDS.clear()


@asynccontextmanager
async def run_inprocess_asgi_app(app: Any) -> AsyncIterator[str]:
    """Serve an ASGI app (lifespan included) as an in-process backend and yield its base URL, a socket-free counterpart of serving it with uvicorn."""
    host = f"backend-{next(_BACKEND_IDS)}.test"
    async with run_asgi_lifespan(app):
        _IN_PROCESS_BACKENDS[host] = app
        try:
            yield f"http://{host}"
        finally:
            del _IN_PROCESS_BACKENDS[host]


@asynccontextmanager
async def run_inprocess_server(mcp: FastMCP, path: str = "/mcp") -> AsyncIterator[str]:
    """Serve a FastMCP backend in-process and yield its full MCP URL, a socket-free counterpart of fastmcp's run_server_async."""
    async with run_inprocess_asgi_app(mcp.http_app(path=path)) as base_url:
        yield f"{base_url}{path}"


@asynccontextmanager
async def run_aggregator_async(
    mcp: FastMCP, path: str = "/mcp"
) -> AsyncIterator[ASGIServer]:
    """Serve an aggregator built by mcp.aggregator.build_aggregator() in-process
    through fastmcp's asgi_server (no socket, no uvicorn), and yield the
    ASGIServer a test builds its clients from (``server.transport(...)``,
    ``server.client(...)``, ``server.http_client()``).

    Installs the ASGI-layer identity middleware (build_asgi_auth_middleware)
    the same way app.py does when mounting /mcp, since issue #138/#144 step 1
    moved identity enforcement to that layer, out of FastMCP's own middleware
    pipeline -- asgi_server forwards ``middleware`` to ``http_app()``, the
    same call run_http_async makes.

    The aggregator's outbound connections to its backends are in-process
    too, through _route_backends_in_process (see run_inprocess_server).
    """
    async with asgi_server(
        mcp, path=path, middleware=[build_asgi_auth_middleware(mcp)]
    ) as server:
        yield server


class _ServerState:
    """ASGI wrapper providing the ``state`` scope key a real server (uvicorn) provides: one dict the app's lifespan fills, copied into every request scope.

    fastmcp's run_asgi_lifespan builds a bare lifespan scope, which a
    Starlette app whose lifespan yields state (app.py's combine_lifespans)
    refuses to start under.
    """

    def __init__(self, app: Any) -> None:
        self._app = app
        self._state: dict[str, Any] = {}

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] == "lifespan":
            scope["state"] = self._state
        else:
            scope["state"] = dict(self._state)
        await self._app(scope, receive, send)


@asynccontextmanager
async def run_broker_in_process(
    app: Any, path: str = "/mcp/"
) -> AsyncIterator[ASGIServer]:
    """Serve a full ASGI app (the broker, with the aggregator mounted at *path*) in-process, lifespan included, and yield the ASGIServer a test builds its clients from.

    For tests that talk to the whole broker app rather than to a bare FastMCP aggregator
    (run_aggregator_async), so app.py's mount + combine_lifespans wiring
    still runs end to end.
    """
    served = _ServerState(app)
    async with run_asgi_lifespan(served):
        yield ASGIServer(
            url=f"http://127.0.0.1{path}", app=served, transport_type="http"
        )


def make_claims(**overrides: Any) -> dict[str, Any]:
    now = int(time.time())
    claims: dict[str, Any] = {
        "sub": "user-123",
        "email": "user@example.org",
        "groups": ["af-atlas-users"],
        "posix": {"uid": 50123, "gid": 5000, "unixname": "auser"},
        "aud": AUDIENCE,
        "iss": ISSUER,
        "iat": now,
        "exp": now + 300,
    }
    claims.update(overrides)
    return claims


@pytest.fixture
def policy():
    from af_mcp_broker.authorization import load_policy

    return load_policy(str(SHIPPED_POLICY))


@pytest.fixture
def static_principal_cache() -> tuple[Any, Any]:
    """A real ``PrincipalCache`` in front of a test-controlled ``PrincipalDirectory``, for tests exercising the directory-backed groups/POSIX resolution (issue #144 steps 3 and 3b) without a real Keycloak.

    Returns ``(cache, directory)``. Set ``directory.groups_by_subject[sub]``
    or ``directory.posix_by_subject[sub]`` (a ``{"uid": ..., "gid": ...,
    "unixname": ...}`` dict, any subset of keys) to control what the cache
    resolves for a given principal, or add a subject to
    ``directory.unavailable_subjects`` to simulate an outage (the directory
    raises instead of resolving). ``directory.resolve_calls`` records every
    principal id actually looked up, for tests asserting the directory was
    (or wasn't) consulted. Generous refresh/staleness bounds keep a test's
    own repeated ``get()`` calls from ever re-hitting the directory or
    falling back to a stale value unless the test wants that specifically.
    """
    from af_mcp_broker.principal_cache import (
        InMemoryPrincipalCacheBackend,
        PrincipalCache,
    )
    from af_mcp_broker.principal_directory import (
        PrincipalAttributes,
        PrincipalDirectory,
        PrincipalDisabledError,
    )

    class _StaticDirectory(PrincipalDirectory):
        def __init__(self) -> None:
            self.groups_by_subject: dict[str, list[str]] = {}
            self.posix_by_subject: dict[str, dict[str, int | str]] = {}
            self.resolve_calls: list[str] = []
            self.unavailable_subjects: set[str] = set()
            self.disabled_subjects: set[str] = set()

        async def resolve(self, principal_id: str) -> PrincipalAttributes:
            self.resolve_calls.append(principal_id)
            if principal_id in self.disabled_subjects:
                raise PrincipalDisabledError(principal_id)
            if principal_id in self.unavailable_subjects:
                raise RuntimeError(f"directory unavailable for {principal_id!r} (test)")
            posix = self.posix_by_subject.get(principal_id, {})
            return PrincipalAttributes(
                uid=posix.get("uid"),
                gid=posix.get("gid"),
                unixname=posix.get("unixname"),
                groups=list(self.groups_by_subject.get(principal_id, [])),
                email="",
            )

    directory = _StaticDirectory()
    cache = PrincipalCache(
        directory,
        backend=InMemoryPrincipalCacheBackend(),
        refresh_interval_seconds=1000.0,
        max_staleness_seconds=3600.0,
        heartbeat_interval_seconds=3600.0,
    )
    return cache, directory


@pytest.fixture
def make_principal() -> Callable[..., object]:
    from af_mcp_broker.identity import Principal

    def _make(
        *,
        groups: list[str] | None = None,
        uid: int | None = 1000,
        gid: int | None = 1000,
        unixname: str | None = "tuser",
        subject: str = "sub-abc",
        permission_grant: frozenset[str] | None = None,
        token_id: str | None = None,
    ) -> Principal:
        return Principal(
            subject=subject,
            email="tuser@example.org",
            uid=uid,
            gid=gid,
            unixname=unixname,
            groups=list(groups or []),
            raw_token=SecretStr("fake-token"),
            permission_grant=permission_grant,
            token_id=token_id,
        )

    return _make


@pytest.fixture
def app_client_factory(
    monkeypatch: pytest.MonkeyPatch,
    make_principal: Callable[..., object],
    tmp_path: Path,
) -> Callable[..., Any]:
    """Context manager that boots the real app against the shipped YAML.

    keycloak_dependency is bypassed via dependency_overrides; mutate
    ``state["principal"]`` to change who the caller is for a given request.
    """
    monkeypatch.setenv("POLICY_FILE", str(SHIPPED_POLICY))
    monkeypatch.setenv("SERVICES_FILE", str(SHIPPED_SERVICES))
    # An unreachable issuer keeps startup JWKS priming a no-op (non-fatal).
    monkeypatch.setenv("OIDC_ISSUER", "https://keycloak.invalid/realms/connect")
    # Ephemeral metrics port so test runs never collide on 9090.
    monkeypatch.setenv("METRICS_PORT", "0")
    monkeypatch.setenv("IDENTITY_PROVIDERS", json.dumps(_DEFAULT_IDENTITY_PROVIDERS))
    # Issue #144 step 3: app.py's lifespan now refuses to start without a
    # configured Keycloak admin service account (dev bypass aside) --
    # KeycloakPrincipalDirectory only derives an admin-API base URL from
    # OIDC_ISSUER at construction time (no network call), so fake
    # credentials are enough to satisfy the startup check here. Every route
    # test in this module overrides keycloak_dependency anyway, so the
    # directory this stands up is never actually queried.
    monkeypatch.setenv("KEYCLOAK_ADMIN_CLIENT_ID", "test-admin-client")
    monkeypatch.setenv("KEYCLOAK_ADMIN_CLIENT_SECRET", "test-admin-secret")

    # X509Provider.is_linked() checks for a real usercert.pem/userkey.pem pair
    # under HOME_ROOT/<unixname>/.globus/ — pre-create that pair for the
    # default test principal's unixname ("tuser") so tests exercising the
    # x509 "ami" target (cache-miss -> NeedsUnlockError -> 409) see a *linked*
    # principal, same as before this pre-check existed.
    globus_dir = tmp_path / "tuser" / ".globus"
    globus_dir.mkdir(parents=True)
    (globus_dir / "usercert.pem").write_text("fake-cert")
    (globus_dir / "userkey.pem").write_text("fake-key")
    monkeypatch.setenv("HOME_ROOT", str(tmp_path))

    from af_mcp_broker.app import app
    from af_mcp_broker.identity import keycloak_dependency

    @contextmanager
    def _factory() -> Iterator[tuple[TestClient, dict]]:
        state: dict = {"principal": make_principal(groups=["atlas"])}
        app.dependency_overrides[keycloak_dependency] = lambda: state["principal"]
        # get_settings() is a process-wide lru_cache with no arguments, so a
        # route depending on it (e.g. GET /v1/identities) would otherwise
        # keep serving whichever Settings a *previous* test's env happened to
        # produce. Clear it so every test client reflects exactly the env
        # this factory call just set up.
        get_settings.cache_clear()
        try:
            with TestClient(app) as client:
                yield client, state
        finally:
            app.dependency_overrides.clear()

    return _factory


@pytest.fixture
def app_client(app_client_factory) -> Iterator[tuple[TestClient, dict]]:
    with app_client_factory() as pair:
        yield pair
