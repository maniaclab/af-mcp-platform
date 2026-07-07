from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

from af_mcp_broker import identity
from af_mcp_broker.config import Settings

ISSUER = "https://keycloak.test/realms/connect"
AUDIENCE = "mcp-gateway"
JWKS_URI = "https://keycloak.test/realms/connect/protocol/openid-connect/certs"


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
    return RsaKey(kid=kid, private=rsa.generate_private_key(public_exponent=65537, key_size=2048))


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
