"""Unit tests for the JWKS cache and the broker-token verifier (U2, U7)."""

from __future__ import annotations

import json
import time
from typing import Any

import httpx2
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from shelf_mcp.auth import BrokerTokenVerifier, JwksCache

ISSUER = "https://broker.example.org"
AUDIENCE = "shelf-mcp"
URI = "https://broker.example.org/.well-known/jwks.json"

pytestmark = pytest.mark.asyncio


def _keypair(kid: str) -> tuple[rsa.RSAPrivateKey, dict[str, Any]]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    return key, {**jwk, "kid": kid, "alg": "RS256", "use": "sig"}


class FakeBroker:
    """An httpx2 transport that serves a JWKS and records each fetch."""

    def __init__(self, *jwks: dict[str, Any]) -> None:
        self.keys = list(jwks)
        self.fetches = 0
        self.down = False

    def client(self) -> httpx2.AsyncClient:
        return httpx2.AsyncClient(transport=httpx2.MockTransport(self._handle))

    def _handle(self, request: httpx2.Request) -> httpx2.Response:
        self.fetches += 1
        if self.down:
            msg = "broker unreachable"
            raise httpx2.ConnectError(msg, request=request)
        return httpx2.Response(200, json={"keys": self.keys})


async def test_repeated_lookups_fetch_once() -> None:
    _, jwk = _keypair("k1")
    broker = FakeBroker(jwk)
    cache = JwksCache(URI, broker.client())

    for _ in range(10):
        await cache.key("k1")

    assert broker.fetches == 1


async def test_unknown_kid_refetches_once_per_cooldown() -> None:
    _, jwk = _keypair("k1")
    broker = FakeBroker(jwk)
    cache = JwksCache(URI, broker.client(), min_refetch=3600)
    await cache.key("k1")

    for _ in range(5):
        with pytest.raises(KeyError):
            await cache.key("forged")

    assert broker.fetches == 1


async def test_rotated_key_is_found_by_an_early_refetch() -> None:
    _, old = _keypair("old")
    _, new = _keypair("new")
    broker = FakeBroker(old)
    cache = JwksCache(URI, broker.client(), min_refetch=0)
    await cache.key("old")
    broker.keys = [old, new]

    assert (await cache.key("new")).key_id == "new"
    assert broker.fetches == 2


async def test_failed_refetch_keeps_serving_known_keys() -> None:
    _, jwk = _keypair("k1")
    broker = FakeBroker(jwk)
    cache = JwksCache(URI, broker.client(), ttl=0)
    await cache.key("k1")
    broker.down = True

    assert (await cache.key("k1")).key_id == "k1"
    assert broker.fetches == 2


class TestBrokerTokenVerifier:
    """Signature, issuer, audience and expiry are all enforced."""

    @staticmethod
    def _verifier_and_signer() -> tuple[BrokerTokenVerifier, rsa.RSAPrivateKey]:
        key, jwk = _keypair("k1")
        cache = JwksCache(URI, FakeBroker(jwk).client())
        return BrokerTokenVerifier(cache, ISSUER, AUDIENCE), key

    @staticmethod
    def _token(key: rsa.RSAPrivateKey, **overrides: Any) -> str:
        now = int(time.time())
        claims = {
            "iss": ISSUER,
            "sub": "user-sub-1",
            "aud": AUDIENCE,
            "iat": now,
            "exp": now + 600,
        } | overrides
        return jwt.encode(claims, key, algorithm="RS256", headers={"kid": "k1"})

    async def test_valid_token_yields_the_subject(self) -> None:
        verifier, key = self._verifier_and_signer()

        access = await verifier.verify_token(self._token(key))

        assert access is not None
        assert access.claims["sub"] == "user-sub-1"

    @pytest.mark.parametrize(
        "overrides",
        [{"aud": "other"}, {"iss": "https://evil.example"}, {"exp": 1}],
        ids=["audience", "issuer", "expiry"],
    )
    async def test_invalid_claims_are_rejected(self, overrides: dict[str, Any]) -> None:
        verifier, key = self._verifier_and_signer()

        assert await verifier.verify_token(self._token(key, **overrides)) is None

    async def test_token_signed_by_another_key_is_rejected(self) -> None:
        verifier, _ = self._verifier_and_signer()
        other, _ = _keypair("k1")

        assert await verifier.verify_token(self._token(other)) is None

    async def test_garbage_is_rejected(self) -> None:
        verifier, _ = self._verifier_and_signer()

        assert await verifier.verify_token("not-a-jwt") is None
