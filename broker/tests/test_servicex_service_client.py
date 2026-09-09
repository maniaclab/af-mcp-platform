"""Tests for the servicex-token-service client (issue #295).

``ServiceXTokenServiceClient`` speaks the contract documented in
maniaclab/servicex-token-service: ``POST {url}/v1/redeem`` authenticated by
an AF Broker Identity Token with ``aud=servicex-token-service``, JSON body
``{"refresh_token"}``, returning ``{"access_token", "expires_in"}``.

servicex-token-service draws one client-actionable distinction: 400 means
ServiceX itself rejected the refresh token (``ServiceXBadRefreshTokenError``).
Everything else (401/403/429/5xx, unreachable, timeout) is an infra failure
(``ServiceXServiceMintError``) that must not be confused with a bad token.
"""

from __future__ import annotations

import json
import time
from typing import TYPE_CHECKING

import httpx
import jwt
import pytest
from pydantic import SecretStr
from test_broker_issued import _make_rsa_key, _private_pem

from af_mcp_broker.credentials.broker_issued import BrokerTokenIssuer
from af_mcp_broker.credentials.servicex_service import (
    RedeemedServiceXToken,
    ServiceXBadRefreshTokenError,
    ServiceXServiceMintError,
    ServiceXTokenServiceClient,
)

if TYPE_CHECKING:
    from collections.abc import Callable

_ISSUER_URL = "https://mcp.example.com"
_SERVICE_URL = "http://servicex-token-service.servicex-token.svc.cluster.local:8080"

_REDEEM_RESPONSE = {"access_token": "fake-access-token", "expires_in": 3600}


@pytest.fixture
def issuer() -> BrokerTokenIssuer:
    return BrokerTokenIssuer(
        private_key_pem=_private_pem(_make_rsa_key()), issuer=_ISSUER_URL
    )


@pytest.fixture
def make_client(
    issuer: BrokerTokenIssuer,
) -> Callable[..., tuple[ServiceXTokenServiceClient, list[httpx.Request]]]:
    """Build a client whose HTTP layer is a ``httpx.MockTransport``.

    Returns ``(client, requests)`` where *requests* records every request
    the client sent. *responder* maps a request to a response (default: 200
    with the canned redeem response); pass an exception instance to have the
    transport raise it instead.
    """

    def _make(
        responder: httpx.Response | Exception | None = None,
        service_url: str = _SERVICE_URL,
        **kwargs: object,
    ) -> tuple[ServiceXTokenServiceClient, list[httpx.Request]]:
        requests: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            requests.append(request)
            if isinstance(responder, Exception):
                raise responder
            if responder is None:
                return httpx.Response(200, json=_REDEEM_RESPONSE)
            return responder

        http_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        client = ServiceXTokenServiceClient(
            issuer=issuer,
            service_url=service_url,
            http_client=http_client,
            **kwargs,  # type: ignore[arg-type]
        )
        return client, requests

    return _make


async def _redeem(
    client: ServiceXTokenServiceClient, **kwargs: object
) -> RedeemedServiceXToken:
    kwargs.setdefault("subject", "user1")
    kwargs.setdefault("refresh_token", SecretStr("a-refresh-token"))
    return await client.redeem(**kwargs)  # type: ignore[arg-type]


class TestRedeemResponse:
    async def test_redeem_success_parses_response(self, make_client) -> None:
        client, _ = make_client()
        before = time.time()
        redeemed = await _redeem(client)
        assert redeemed.access_token == "fake-access-token"
        assert redeemed.expires_at == pytest.approx(before + 3600, abs=5)

    async def test_redeem_posts_refresh_token_and_bearer_auth(
        self, make_client
    ) -> None:
        client, requests = make_client()
        await _redeem(client, refresh_token=SecretStr("secret-refresh"))
        assert len(requests) == 1
        request = requests[0]
        assert request.url == f"{_SERVICE_URL}/v1/redeem"
        assert request.headers["authorization"].startswith("Bearer ")
        body = json.loads(request.content.decode())
        assert body == {"refresh_token": "secret-refresh"}

    async def test_redeem_default_audience(self, make_client) -> None:
        client, requests = make_client()
        await _redeem(client)
        # The broker token's aud claim defaults to servicex-token-service --
        # decode without verification just to inspect the claim.
        token = requests[0].headers["authorization"].removeprefix("Bearer ")
        claims = jwt.decode(token, options={"verify_signature": False})
        assert claims["aud"] == "servicex-token-service"


class TestRedeemFailures:
    async def test_redeem_400_raises_bad_refresh_token_error(self, make_client) -> None:
        client, _ = make_client(httpx.Response(400, json={"detail": "bad token"}))
        with pytest.raises(ServiceXBadRefreshTokenError):
            await _redeem(client)

    async def test_redeem_401_raises_mint_error(self, make_client) -> None:
        client, _ = make_client(httpx.Response(401, json={"detail": "nope"}))
        with pytest.raises(ServiceXServiceMintError):
            await _redeem(client)

    async def test_redeem_429_raises_mint_error(self, make_client) -> None:
        client, _ = make_client(httpx.Response(429, json={"detail": "rate limited"}))
        with pytest.raises(ServiceXServiceMintError):
            await _redeem(client)

    async def test_redeem_502_raises_mint_error(self, make_client) -> None:
        client, _ = make_client(httpx.Response(502, json={"detail": "bad gateway"}))
        with pytest.raises(ServiceXServiceMintError):
            await _redeem(client)

    async def test_redeem_unreachable_raises_mint_error(self, make_client) -> None:
        client, _ = make_client(httpx.ConnectError("connection refused"))
        with pytest.raises(ServiceXServiceMintError):
            await _redeem(client)

    async def test_mint_error_message_never_carries_response_body(
        self, make_client
    ) -> None:
        client, _ = make_client(
            httpx.Response(500, json={"detail": "some internal secret path"})
        )
        with pytest.raises(ServiceXServiceMintError) as exc_info:
            await _redeem(client)
        assert "some internal secret path" not in str(exc_info.value)


class TestEndpointJoin:
    async def test_trailing_slash_on_service_url_is_stripped(self, make_client) -> None:
        client, requests = make_client(service_url=f"{_SERVICE_URL}/")
        await _redeem(client)
        assert requests[0].url == f"{_SERVICE_URL}/v1/redeem"
