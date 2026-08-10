"""Shared fixtures for af-credentials tests.

RSA keys are generated once per test module scope via the ``rsa_keypair``
fixture (key generation is comparatively slow; nothing here mutates the
key, so sharing it across tests in a module is safe) and turned into a JWK
+ JWKS document the same way ``af_mcp_broker.credentials.broker_issued``
does, so tokens minted here verify the same way a real AF Broker Identity
Token would.
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

ISSUER = "https://broker.af.example.org"
AUDIENCE = "ami-mcp"


def rfc7638_thumbprint(public_key: rsa.RSAPublicKey) -> str:
    """Independently compute the RFC 7638 JWK thumbprint used as ``kid``, mirroring af_mcp_broker.credentials.broker_issued._rfc7638_thumbprint."""
    jwk = json.loads(RSAAlgorithm.to_jwk(public_key))
    canonical = json.dumps(
        {"e": jwk["e"], "kty": jwk["kty"], "n": jwk["n"]},
        sort_keys=True,
        separators=(",", ":"),
    )
    digest = hashlib.sha256(canonical.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def public_jwk(public_key: rsa.RSAPublicKey) -> dict[str, Any]:
    jwk = json.loads(RSAAlgorithm.to_jwk(public_key))
    jwk.update({"kid": rfc7638_thumbprint(public_key), "use": "sig", "alg": "RS256"})
    return jwk


@pytest.fixture(scope="module")
def rsa_keypair() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def second_rsa_keypair() -> rsa.RSAPrivateKey:
    """A second, distinct key -- used to simulate key rotation (a new kid the verifier hasn't cached yet)."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def jwks_document(rsa_keypair: rsa.RSAPrivateKey) -> dict[str, Any]:
    return {"keys": [public_jwk(rsa_keypair.public_key())]}


def mint_token(
    private_key: rsa.RSAPrivateKey,
    *,
    sub: str = "af|12345",
    aud: str = AUDIENCE,
    iss: str = ISSUER,
    ttl_seconds: int = 600,
    uid: int | None = None,
    gid: int | None = None,
    unixname: str | None = None,
    kid: str | None = None,
    extra_claims: dict[str, Any] | None = None,
) -> str:
    """Mint a token shaped exactly like BrokerTokenIssuer.mint() (af_mcp_broker/credentials/broker_issued.py): iss/sub/aud/exp/iat/jti always, uid/gid/unixname only when passed."""
    now = int(time.time())
    claims: dict[str, Any] = {
        "iss": iss,
        "sub": sub,
        "aud": aud,
        "exp": now + ttl_seconds,
        "iat": now,
        "jti": "test-jti-0001",
    }
    if uid is not None:
        claims["uid"] = uid
    if gid is not None:
        claims["gid"] = gid
    if unixname is not None:
        claims["unixname"] = unixname
    if extra_claims:
        claims.update(extra_claims)
    header_kid = (
        kid if kid is not None else rfc7638_thumbprint(private_key.public_key())
    )
    return jwt.encode(
        claims, private_key, algorithm="RS256", headers={"kid": header_kid}
    )
