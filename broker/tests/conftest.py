from __future__ import annotations

import json
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from jwt.algorithms import RSAAlgorithm
from pydantic import SecretStr

from af_mcp_broker import identity
from af_mcp_broker.config import Settings

ISSUER = "https://keycloak.test/realms/connect"
AUDIENCE = "mcp-gateway"
JWKS_URI = "https://keycloak.test/realms/connect/protocol/openid-connect/certs"

# Point tests at the YAML files that actually ship with the broker so the
# entitlement decisions exercised here match production config.
_SRC = Path(__file__).resolve().parents[1] / "src" / "af_mcp_broker"
SHIPPED_POLICY = _SRC / "authorization" / "policy.yaml"
SHIPPED_BACKENDS = _SRC / "mcp" / "backends.yaml"


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
        keycloak_issuer=ISSUER,
        keycloak_audience=AUDIENCE,
        keycloak_jwks_uri=JWKS_URI,
    )


@pytest.fixture
def prime_jwks(settings: Settings):
    """Seed the in-process JWKS TTL cache so no network fetch happens.

    Returns a callable that installs a given list of JWKs for the test's
    settings URI.
    """

    def _install(jwks: list[dict[str, Any]]) -> None:
        identity._jwks_cache[settings.keycloak_jwks_uri] = identity._JwksEntry(
            keys=jwks, fetched_at=time.monotonic()
        )

    yield _install
    identity._jwks_cache.pop(settings.keycloak_jwks_uri, None)


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
def make_principal() -> Callable[..., object]:
    from af_mcp_broker.identity import Principal

    def _make(
        *,
        groups: list[str] | None = None,
        uid: int = 1000,
        gid: int = 1000,
        unixname: str = "tuser",
        iam_sub: str | None = None,
    ) -> Principal:
        return Principal(
            subject="sub-abc",
            email="tuser@example.org",
            uid=uid,
            gid=gid,
            unixname=unixname,
            groups=list(groups or []),
            iam_sub=iam_sub,
            cern_sub=None,
            raw_token=SecretStr("fake-token"),
        )

    return _make


@pytest.fixture
def app_client_factory(
    monkeypatch: pytest.MonkeyPatch, make_principal: Callable[..., object]
) -> Callable[..., Any]:
    """Context manager that boots the real app against the shipped YAML.

    keycloak_dependency is bypassed via dependency_overrides; mutate
    ``state["principal"]`` to change who the caller is for a given request.
    """
    monkeypatch.setenv("POLICY_FILE", str(SHIPPED_POLICY))
    monkeypatch.setenv("BACKENDS_FILE", str(SHIPPED_BACKENDS))
    # An unreachable issuer keeps startup JWKS priming a no-op (non-fatal).
    monkeypatch.setenv("KEYCLOAK_ISSUER", "https://keycloak.invalid/realms/connect")
    # Ephemeral metrics port so test runs never collide on 9090.
    monkeypatch.setenv("METRICS_PORT", "0")

    from af_mcp_broker.app import app
    from af_mcp_broker.identity import keycloak_dependency

    @contextmanager
    def _factory() -> Iterator[tuple[TestClient, dict]]:
        state: dict = {
            "principal": make_principal(groups=["atlas"], iam_sub="iam-sub-1")
        }
        app.dependency_overrides[keycloak_dependency] = lambda: state["principal"]
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
