from __future__ import annotations

import asyncio
import contextlib
import json
import shutil
import socket
import socketserver
import subprocess
import time
from contextlib import asynccontextmanager, contextmanager
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable, Iterator

    from fastmcp import FastMCP

import jwt
import pytest
import uvicorn
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from fastmcp.utilities.http import find_available_port
from jwt.algorithms import RSAAlgorithm
from pydantic import SecretStr

from af_mcp_broker import identity
from af_mcp_broker.audit import measure
from af_mcp_broker.config import Settings, get_settings
from af_mcp_broker.mcp.aggregator import build_asgi_auth_middleware

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


# --- ClientSession hotfix -- modelcontextprotocol/python-sdk#1144 ----------
# An MCP streamable-HTTP client whose response dies mid-flight hangs forever
# on mcp v1: an Exception object the transport sends into the session's read
# stream is handled by a default no-op (the receive loop keeps iterating, so
# its teardown -- which WOULD fail all pending requests with
# CONNECTION_CLOSED -- never runs), and a connection that goes dead without
# delivering anything produces no event at all. Fixed upstream in mcp v2,
# which only fastmcp v4 (still beta) can use; until that migration this
# keeps a flaky server abort from wedging the suite (it caused the historic
# silent CI hangs, e.g. run 32922473653). Two halves:
#   - a wrapping message_handler closes the read stream when an Exception
#     arrives, so the receive loop exits NORMALLY and its own teardown
#     delivers CONNECTION_CLOSED to every waiter (cleaner than cancelling
#     the session task group, which races that same teardown);
#   - sessions with no read timeout get a default one, covering the
#     dead-but-open-connection case where no event ever arrives.
# Mutable so tests of the hotfix itself can shrink the timeout.
_CLIENT_SESSION_HOTFIX: dict[str, Any] = {"read_timeout": timedelta(seconds=30)}


@pytest.fixture(autouse=True)
def client_session_hotfix(monkeypatch: pytest.MonkeyPatch) -> None:
    """Bound every test ClientSession -- see _CLIENT_SESSION_HOTFIX above."""
    import mcp.client.session as mcp_client_session

    orig_init = mcp_client_session.ClientSession.__init__

    def patched_init(self: Any, *args: Any, **kwargs: Any) -> None:
        if kwargs.get("read_timeout_seconds") is None:
            kwargs["read_timeout_seconds"] = _CLIENT_SESSION_HOTFIX["read_timeout"]
        inner = kwargs.get("message_handler")

        async def close_on_stream_exception(message: Any) -> None:
            if isinstance(message, Exception):
                # Ends the receive loop's `async for`; its finally block then
                # fails every pending request with CONNECTION_CLOSED.
                await self._read_stream.aclose()
                return
            if inner is not None:
                await inner(message)

        kwargs["message_handler"] = close_on_stream_exception
        orig_init(self, *args, **kwargs)

    monkeypatch.setattr(mcp_client_session.ClientSession, "__init__", patched_init)


# How long a test server gets to report started before the harness gives up.
# Generous: startup is normally milliseconds even on a loaded CI runner --
# the point is a bounded, diagnosable failure instead of the silent
# until-the-6-hour-job-timeout hang an unbounded wait produces when the
# server task dies (e.g. the find_available_port TOCTOU race losing the
# port to another process between probe and bind).
_SERVER_START_TIMEOUT = 30.0


async def _contained(coro: Any) -> None:
    """Await *coro*, converting SystemExit into an ordinary exception.

    uvicorn reports a startup failure (e.g. a lost port-bind race) with
    ``sys.exit(3)`` -- and asyncio re-raises SystemExit from a task straight
    into the event loop, crashing whatever drives it, instead of containing
    it in the task like a normal exception. Wrapping the server coroutine
    keeps the failure inside the task where _await_server_started can
    surface it as a diagnosable error.
    """
    try:
        await coro
    except SystemExit as exc:
        raise RuntimeError(f"uvicorn exited during startup (code {exc.code})") from exc


async def _await_server_started(
    server_task: asyncio.Task[Any], started: Callable[[], bool]
) -> None:
    """Wait (bounded) for *started*, surfacing *server_task*'s death.

    The historic failure mode this replaces: the server task exits with an
    exception (uvicorn's bind failure raises SystemExit inside the task,
    contained by _contained above), the started flag therefore never flips,
    and an unbounded wait spins forever with the exception swallowed -- the
    CI hang. Checking ``server_task.done()`` on every poll turns that into
    an immediate, chained error.
    """
    deadline = time.monotonic() + _SERVER_START_TIMEOUT
    while not started():
        if server_task.done():
            # .exception() itself raises CancelledError if the task was
            # cancelled, which is equally a startup failure -- let it out.
            exc = server_task.exception()
            raise RuntimeError("server task exited before startup") from exc
        if time.monotonic() > deadline:
            server_task.cancel()
            raise TimeoutError(
                f"test server failed to start within {_SERVER_START_TIMEOUT}s"
            )
        await asyncio.sleep(0.01)


def _port_accepting(port: int) -> bool:
    """True once a TCP connect to 127.0.0.1:*port* succeeds (sub-ms on
    loopback) -- the real "uvicorn has bound and is accepting" condition."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.settimeout(0.05)
        return probe.connect_ex(("127.0.0.1", port)) == 0


@asynccontextmanager
async def run_asgi_app(app: Any, port: int | None = None) -> AsyncIterator[str]:
    """Run an arbitrary ASGI app (not necessarily a bare FastMCP server)
    behind a real uvicorn server on an ephemeral port -- fastmcp's own
    run_server_async only accepts a FastMCP instance directly, which can't
    carry the ASGI-level auth middleware some tests need (e.g. the
    _auth_gated_backend() doubles reproducing issue #121), nor exercise
    app.py's actual mount + combine_lifespans wiring end-to-end.

    The listening socket is bound HERE, synchronously, and handed to uvicorn
    -- unlike the probe-close-rebind of ``find_available_port``, there is no
    window for another process to steal the port, so the bind race that used
    to hang CI cannot occur on this harness at all. A genuinely occupied
    *port* (a harness-test seam, see test_server_harness.py; everything else
    leaves it None for an ephemeral one) fails the bind right here with a
    plain OSError instead.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", port or 0))
    port = sock.getsockname()[1]
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
    server = uvicorn.Server(config)
    task = asyncio.create_task(_contained(server.serve(sockets=[sock])))
    try:
        await _await_server_started(task, lambda: server.started)
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        # Bounded for the same reason as startup: a server wedged on
        # shutdown (e.g. a lingering keep-alive connection) must fail the
        # test, not stall the whole run.
        with contextlib.suppress(asyncio.CancelledError, asyncio.TimeoutError):
            await asyncio.wait_for(task, timeout=10.0)
        # uvicorn/asyncio normally close the socket on shutdown; make sure it
        # never outlives the harness even on an aborted startup.
        with contextlib.suppress(OSError):
            sock.close()


@asynccontextmanager
async def run_aggregator_async(mcp: FastMCP, path: str = "/mcp") -> AsyncIterator[str]:
    """Like fastmcp.utilities.tests.run_server_async, but for an aggregator
    built by mcp.aggregator.build_aggregator(): installs the ASGI-layer
    identity middleware (build_asgi_auth_middleware) the same way app.py
    does when mounting /mcp, since issue #138/#144 step 1 moved identity
    enforcement to that layer, out of FastMCP's own middleware pipeline --
    run_server_async's run_http_async() call has no way to attach it without
    reimplementing this same loop, so tests that need a real aggregator
    (rather than a bare test FastMCP backend) use this instead.

    Unlike run_server_async (unbounded ``await mcp._started.wait()``,
    upstream), startup here is bounded and surfaces the server task's death
    -- see _await_server_started.
    """
    port = find_available_port()
    await asyncio.sleep(0.01)
    server_task = asyncio.create_task(
        _contained(
            mcp.run_http_async(
                host="127.0.0.1",
                port=port,
                path=path,
                middleware=[build_asgi_auth_middleware(mcp)],
                show_banner=False,
            )
        )
    )
    try:
        await _await_server_started(server_task, mcp._started.is_set)
        # ``_started`` flips when the app lifespan is ready, which is BEFORE
        # uvicorn binds the listening socket -- upstream's run_server_async
        # papers over that gap with a flat 0.1s sleep ("give uvicorn a moment
        # to bind the port"). Poll the actual readiness condition instead: a
        # TCP connect succeeding means the port is accepting, so the harness
        # proceeds the moment the server is really up (same bounded loop, so
        # a server that never binds still fails diagnosably).
        await _await_server_started(server_task, lambda: _port_accepting(port))
        yield f"http://127.0.0.1:{port}{path}"
    finally:
        server_task.cancel()
        with contextlib.suppress(asyncio.CancelledError, asyncio.TimeoutError):
            await asyncio.wait_for(server_task, timeout=2.0)


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
    )

    class _StaticDirectory(PrincipalDirectory):
        def __init__(self) -> None:
            self.groups_by_subject: dict[str, list[str]] = {}
            self.posix_by_subject: dict[str, dict[str, int | str]] = {}
            self.resolve_calls: list[str] = []
            self.unavailable_subjects: set[str] = set()

        async def resolve(self, principal_id: str) -> PrincipalAttributes:
            self.resolve_calls.append(principal_id)
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
    # x509 "ami" target (cache-miss -> NeedsUnlock -> 409) see a *linked*
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
