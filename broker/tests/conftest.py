from __future__ import annotations

import asyncio
import contextlib
import json
import time
from contextlib import asynccontextmanager, contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable, Iterator

    from fastmcp import FastMCP

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from fastmcp.utilities.http import find_available_port
from jwt.algorithms import RSAAlgorithm
from pydantic import SecretStr

from af_mcp_broker import identity
from af_mcp_broker.config import Settings, get_settings
from af_mcp_broker.mcp.aggregator import build_asgi_auth_middleware

ISSUER = "https://keycloak.test/realms/connect"
AUDIENCE = "mcp-gateway"
JWKS_URI = "https://keycloak.test/realms/connect/protocol/openid-connect/certs"

# Point tests at the YAML files that actually ship with the broker so the
# entitlement decisions exercised here match production config.
_SRC = Path(__file__).resolve().parents[1] / "src" / "af_mcp_broker"
SHIPPED_POLICY = _SRC / "authorization" / "policy.yaml"
SHIPPED_BACKENDS = _SRC / "mcp" / "backends.yaml"

# Default `identity_providers` entry `app_client_factory` configures below —
# one keycloak-brokered provider bound to the historic default OIDCProvider
# targets, so `bearer`-auth backends (e.g. "rucio" in SHIPPED_BACKENDS) still
# resolve to an OIDCProvider instance the way they did before issue #66 PR4
# replaced the single `oidc_idp_alias`-derived singleton with per-entry
# `identity_providers` config. Tests that care about a specific
# `identity_providers` shape (test_identities.py, test_oauth21*.py,
# test_wellknown_cimd.py) override IDENTITY_PROVIDERS themselves.
_DEFAULT_IDENTITY_PROVIDERS = [
    {
        "type": "keycloak-brokered",
        "alias": "atlas-oidc",
        "display_name": "ATLAS IAM",
        "enables": "VOMS proxy generation and grid certificate credential brokering",
        "targets": ["rucio", "opendata", "af-internal"],
    }
]


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


@pytest.fixture
def sig_key() -> RsaKey:
    return _make_key("sig-key")


@pytest.fixture
def enc_key() -> RsaKey:
    return _make_key("enc-key")


@pytest.fixture
def settings() -> Settings:
    return Settings(
        oidc_issuer=ISSUER,
        oidc_audience=AUDIENCE,
        oidc_jwks_uri=JWKS_URI,
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
    """
    port = find_available_port()
    await asyncio.sleep(0.01)
    server_task = asyncio.create_task(
        mcp.run_http_async(
            host="127.0.0.1",
            port=port,
            path=path,
            middleware=[build_asgi_auth_middleware(mcp)],
            show_banner=False,
        )
    )
    await mcp._started.wait()
    await asyncio.sleep(0.1)
    try:
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
    """A real ``PrincipalCache`` in front of a test-controlled ``PrincipalDirectory``, for tests exercising the directory-backed groups resolution (issue #144 step 3) without a real Keycloak.

    Returns ``(cache, directory)``. Set ``directory.groups_by_subject[sub]``
    to control what the cache resolves for a given principal, or add a
    subject to ``directory.unavailable_subjects`` to simulate an outage (the
    directory raises instead of resolving). ``directory.resolve_calls``
    records every principal id actually looked up, for tests asserting the
    directory was (or wasn't) consulted. Generous refresh/staleness bounds
    keep a test's own repeated ``get()`` calls from ever re-hitting the
    directory or falling back to a stale value unless the test wants that
    specifically.
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
            self.resolve_calls: list[str] = []
            self.unavailable_subjects: set[str] = set()

        async def resolve(self, principal_id: str) -> PrincipalAttributes:
            self.resolve_calls.append(principal_id)
            if principal_id in self.unavailable_subjects:
                raise RuntimeError(f"directory unavailable for {principal_id!r} (test)")
            return PrincipalAttributes(
                uid=None,
                gid=None,
                unixname=None,
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
    ) -> Principal:
        return Principal(
            subject=subject,
            email="tuser@example.org",
            uid=uid,
            gid=gid,
            unixname=unixname,
            groups=list(groups or []),
            raw_token=SecretStr("fake-token"),
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
    monkeypatch.setenv("BACKENDS_FILE", str(SHIPPED_BACKENDS))
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
