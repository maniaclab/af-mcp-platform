"""Tests for BrokerTokenVerifier (af_credentials.verifier).

Tokens are minted exactly like af_mcp_broker.credentials.broker_issued's
BrokerTokenIssuer.mint() (see conftest.mint_token): iss/sub/aud/exp/iat/jti
always, uid/gid/unixname only when present -- af-credentials is the
consumer side of that same contract (docs/auth.md "AF Broker Identity
Token").
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

import httpx2
import pytest
from conftest import AUDIENCE, ISSUER, mint_token, public_jwk

from af_credentials.verifier import BrokerClaims, BrokerTokenVerifier

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric import rsa


def _jwks_client(
    jwks_by_call: list[dict[str, object]],
) -> tuple[httpx2.AsyncClient, list[str]]:
    """Return a client whose transport serves the successive JWKS documents in *jwks_by_call* (one per call; the last is repeated once exhausted) and a list this appends one entry to per request, for call-count assertions."""
    calls: list[str] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        calls.append(str(request.url))
        index = min(len(calls) - 1, len(jwks_by_call) - 1)
        return httpx2.Response(200, json=jwks_by_call[index])

    return httpx2.AsyncClient(transport=httpx2.MockTransport(handler)), calls


class TestVerifyValidToken:
    async def test_returns_claims(self, rsa_keypair: rsa.RSAPrivateKey) -> None:
        client, _calls = _jwks_client(
            [{"keys": [public_jwk(rsa_keypair.public_key())]}]
        )
        verifier = BrokerTokenVerifier(
            "https://broker.example/.well-known/jwks.json",
            ISSUER,
            AUDIENCE,
            http_client=client,
        )
        token = mint_token(rsa_keypair)

        claims = await verifier.verify(token)

        assert claims == BrokerClaims(
            sub="af|12345", jti="test-jti-0001", exp=claims.exp
        )
        assert claims.uid is None
        assert claims.gid is None
        assert claims.unixname is None

    async def test_returns_posix_claims_when_present(
        self, rsa_keypair: rsa.RSAPrivateKey
    ) -> None:
        client, _calls = _jwks_client(
            [{"keys": [public_jwk(rsa_keypair.public_key())]}]
        )
        verifier = BrokerTokenVerifier(
            "https://broker.example/.well-known/jwks.json",
            ISSUER,
            AUDIENCE,
            http_client=client,
        )
        token = mint_token(rsa_keypair, uid=33155, gid=33155, unixname="kratsg")

        claims = await verifier.verify(token)

        assert claims is not None
        assert (claims.uid, claims.gid, claims.unixname) == (33155, 33155, "kratsg")


class TestVerifyRejectsBadClaims:
    async def test_wrong_audience_returns_none(
        self, rsa_keypair: rsa.RSAPrivateKey
    ) -> None:
        client, _calls = _jwks_client(
            [{"keys": [public_jwk(rsa_keypair.public_key())]}]
        )
        verifier = BrokerTokenVerifier(
            "https://broker.example/.well-known/jwks.json",
            ISSUER,
            AUDIENCE,
            http_client=client,
        )
        token = mint_token(rsa_keypair, aud="some-other-backend")

        assert await verifier.verify(token) is None

    async def test_wrong_issuer_returns_none(
        self, rsa_keypair: rsa.RSAPrivateKey
    ) -> None:
        client, _calls = _jwks_client(
            [{"keys": [public_jwk(rsa_keypair.public_key())]}]
        )
        verifier = BrokerTokenVerifier(
            "https://broker.example/.well-known/jwks.json",
            ISSUER,
            AUDIENCE,
            http_client=client,
        )
        token = mint_token(rsa_keypair, iss="https://not-the-broker.example")

        assert await verifier.verify(token) is None

    async def test_expired_token_returns_none(
        self, rsa_keypair: rsa.RSAPrivateKey
    ) -> None:
        client, _calls = _jwks_client(
            [{"keys": [public_jwk(rsa_keypair.public_key())]}]
        )
        verifier = BrokerTokenVerifier(
            "https://broker.example/.well-known/jwks.json",
            ISSUER,
            AUDIENCE,
            http_client=client,
        )
        token = mint_token(rsa_keypair, ttl_seconds=-10)

        assert await verifier.verify(token) is None

    async def test_garbage_token_returns_none(
        self, rsa_keypair: rsa.RSAPrivateKey
    ) -> None:
        client, _calls = _jwks_client(
            [{"keys": [public_jwk(rsa_keypair.public_key())]}]
        )
        verifier = BrokerTokenVerifier(
            "https://broker.example/.well-known/jwks.json",
            ISSUER,
            AUDIENCE,
            http_client=client,
        )

        assert await verifier.verify("not-a-jwt-at-all") is None

    async def test_wrong_signing_key_returns_none(
        self,
        rsa_keypair: rsa.RSAPrivateKey,
        second_rsa_keypair: rsa.RSAPrivateKey,
    ) -> None:
        """A token signed by a key whose kid the JWKS never publishes (not even after refetch) must not verify."""
        client, _calls = _jwks_client(
            [{"keys": [public_jwk(rsa_keypair.public_key())]}]
        )
        verifier = BrokerTokenVerifier(
            "https://broker.example/.well-known/jwks.json",
            ISSUER,
            AUDIENCE,
            http_client=client,
        )
        token = mint_token(second_rsa_keypair)

        assert await verifier.verify(token) is None


class TestKeyRotation:
    async def test_unknown_kid_triggers_one_refetch(
        self,
        rsa_keypair: rsa.RSAPrivateKey,
        second_rsa_keypair: rsa.RSAPrivateKey,
    ) -> None:
        """A token signed by a newly-rotated-in key, whose kid isn't in the verifier's cached JWKS yet, must succeed after exactly one refetch."""
        stale_jwks = {"keys": [public_jwk(rsa_keypair.public_key())]}
        rotated_jwks = {
            "keys": [
                public_jwk(rsa_keypair.public_key()),
                public_jwk(second_rsa_keypair.public_key()),
            ]
        }
        client, calls = _jwks_client([stale_jwks, rotated_jwks])
        verifier = BrokerTokenVerifier(
            "https://broker.example/.well-known/jwks.json",
            ISSUER,
            AUDIENCE,
            http_client=client,
        )
        # Prime the cache with the stale JWKS (one fetch already spent).
        await verifier.verify(mint_token(rsa_keypair))
        assert len(calls) == 1

        token = mint_token(second_rsa_keypair)
        claims = await verifier.verify(token)

        assert claims is not None
        assert claims.sub == "af|12345"
        assert len(calls) == 2

    async def test_unknown_kid_that_never_appears_returns_none_after_one_refetch(
        self,
        rsa_keypair: rsa.RSAPrivateKey,
        second_rsa_keypair: rsa.RSAPrivateKey,
    ) -> None:
        jwks = {"keys": [public_jwk(rsa_keypair.public_key())]}
        client, calls = _jwks_client([jwks])
        verifier = BrokerTokenVerifier(
            "https://broker.example/.well-known/jwks.json",
            ISSUER,
            AUDIENCE,
            http_client=client,
        )
        # Warm the cache with a known-good token first (1 fetch) so the
        # unknown-kid lookup below is against an already-populated cache,
        # not a cold one -- otherwise the initial populate and the "refetch"
        # would be the same fetch.
        await verifier.verify(mint_token(rsa_keypair))
        assert len(calls) == 1

        token = mint_token(second_rsa_keypair)

        assert await verifier.verify(token) is None
        # One refetch for the unknown kid -- never a second refetch for the
        # same still-missing kid.
        assert len(calls) == 2


class TestCacheTtl:
    async def test_within_ttl_does_not_refetch(
        self, rsa_keypair: rsa.RSAPrivateKey
    ) -> None:
        client, calls = _jwks_client([{"keys": [public_jwk(rsa_keypair.public_key())]}])
        verifier = BrokerTokenVerifier(
            "https://broker.example/.well-known/jwks.json",
            ISSUER,
            AUDIENCE,
            cache_ttl=300.0,
            http_client=client,
        )
        token = mint_token(rsa_keypair)

        await verifier.verify(token)
        await verifier.verify(token)
        await verifier.verify(token)

        assert len(calls) == 1

    async def test_ttl_expiry_triggers_refetch(
        self, rsa_keypair: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client, calls = _jwks_client([{"keys": [public_jwk(rsa_keypair.public_key())]}])
        verifier = BrokerTokenVerifier(
            "https://broker.example/.well-known/jwks.json",
            ISSUER,
            AUDIENCE,
            cache_ttl=0.01,
            http_client=client,
        )
        token = mint_token(rsa_keypair)

        await verifier.verify(token)
        time.sleep(0.02)
        await verifier.verify(token)

        assert len(calls) == 2


class TestTransportErrorsPropagate:
    async def test_connect_error_raises(self, rsa_keypair: rsa.RSAPrivateKey) -> None:
        def handler(request: httpx2.Request) -> httpx2.Response:
            raise httpx2.ConnectError("connection refused")

        client = httpx2.AsyncClient(transport=httpx2.MockTransport(handler))
        verifier = BrokerTokenVerifier(
            "https://broker.example/.well-known/jwks.json",
            ISSUER,
            AUDIENCE,
            http_client=client,
        )
        token = mint_token(rsa_keypair)

        with pytest.raises(httpx2.ConnectError):
            await verifier.verify(token)

    async def test_server_error_raises(self, rsa_keypair: rsa.RSAPrivateKey) -> None:
        def handler(request: httpx2.Request) -> httpx2.Response:
            return httpx2.Response(500, text="internal error")

        client = httpx2.AsyncClient(transport=httpx2.MockTransport(handler))
        verifier = BrokerTokenVerifier(
            "https://broker.example/.well-known/jwks.json",
            ISSUER,
            AUDIENCE,
            http_client=client,
        )
        token = mint_token(rsa_keypair)

        with pytest.raises(httpx2.HTTPStatusError):
            await verifier.verify(token)
