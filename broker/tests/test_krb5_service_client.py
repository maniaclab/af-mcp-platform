"""Tests for the krb5-token-service mint client (issue #274).

``Krb5TokenServiceClient`` speaks the contract documented in
maniaclab/krb5-token-service: ``POST {url}/v1/mint`` authenticated by an AF
Broker Identity Token with ``aud=krb5-token-service``, JSON body
``{"username", "password", "lifetime"?, "renewable_lifetime"?}``, returning
``{"ccache_b64", "principal", "realm", "expires_at", "renew_until"}``.

Unlike ``voms_service.py``'s single "bad passphrase" signal, krb5-token-service
draws several client-actionable distinctions: 400 (bad username/password), 403
(CERN account revoked/expired), 422 (malformed request) and 429
(rate-limited, with ``Retry-After``). 401 and 5xx mean the broker's own
identity token or the service itself is broken -- a broker<->service
contract failure the end user cannot act on -- and must stay clearly
distinct from a bad CERN password.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import TYPE_CHECKING

import httpx
import pytest
from pydantic import SecretStr
from test_broker_issued import _make_rsa_key, _private_pem

from af_mcp_broker.credentials.broker_issued import BrokerTokenIssuer
from af_mcp_broker.credentials.krb5_service import (
    Krb5TokenAccountError,
    Krb5TokenBadCredentialError,
    Krb5TokenInvalidRequestError,
    Krb5TokenMintError,
    Krb5TokenRateLimitedError,
    Krb5TokenServiceClient,
    MintedTicket,
)

if TYPE_CHECKING:
    from collections.abc import Callable

_ISSUER_URL = "https://mcp.example.com"
_SERVICE_URL = "http://krb5-token-service.af-mcp.svc.cluster.local:8000"

_MINT_RESPONSE = {
    "ccache_b64": "ZmFrZQ==",
    "principal": "alice@CERN.CH",
    "realm": "CERN.CH",
    "expires_at": "2099-01-01T00:00:00+00:00",
    "renew_until": "2099-01-08T00:00:00+00:00",
}
_EXPECTED_NOT_AFTER = datetime(2099, 1, 1, 0, 0, 0, tzinfo=UTC).timestamp()
_EXPECTED_RENEW_UNTIL = datetime(2099, 1, 8, 0, 0, 0, tzinfo=UTC).timestamp()


@pytest.fixture
def issuer() -> BrokerTokenIssuer:
    return BrokerTokenIssuer(
        private_key_pem=_private_pem(_make_rsa_key()), issuer=_ISSUER_URL
    )


@pytest.fixture
def make_client(
    issuer: BrokerTokenIssuer,
) -> Callable[..., tuple[Krb5TokenServiceClient, list[httpx.Request]]]:
    """Build a client whose HTTP layer is a ``httpx.MockTransport``.

    Returns ``(client, requests)`` where *requests* records every request
    the client sent. *responder* maps a request to a response (default: 200
    with the canned mint response); pass an exception instance to have the
    transport raise it instead.
    """

    def _make(
        responder: httpx.Response | Exception | None = None,
        service_url: str = _SERVICE_URL,
        **kwargs: object,
    ) -> tuple[Krb5TokenServiceClient, list[httpx.Request]]:
        requests: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            requests.append(request)
            if isinstance(responder, Exception):
                raise responder
            if responder is None:
                return httpx.Response(200, json=_MINT_RESPONSE)
            return responder

        http_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        client = Krb5TokenServiceClient(
            issuer=issuer,
            service_url=service_url,
            http_client=http_client,
            **kwargs,  # type: ignore[arg-type]
        )
        return client, requests

    return _make


async def _mint(client: Krb5TokenServiceClient, **kwargs: object) -> MintedTicket:
    kwargs.setdefault("subject", "user1")
    kwargs.setdefault("username", "alice")
    kwargs.setdefault("password", SecretStr("hunter2"))
    return await client.mint(**kwargs)  # type: ignore[arg-type]


class TestMintResponse:
    async def test_mint_success_parses_response(self, make_client) -> None:
        client, _ = make_client()
        ticket = await _mint(client)
        assert ticket.ccache_b64 == "ZmFrZQ=="
        assert ticket.principal == "alice@CERN.CH"
        assert ticket.realm == "CERN.CH"
        assert ticket.not_after == pytest.approx(_EXPECTED_NOT_AFTER)
        assert ticket.renew_until == pytest.approx(_EXPECTED_RENEW_UNTIL)

    async def test_mint_renew_until_null_stays_none(self, make_client) -> None:
        response = dict(_MINT_RESPONSE, renew_until=None)
        client, _ = make_client(httpx.Response(200, json=response))
        ticket = await _mint(client)
        assert ticket.renew_until is None

    async def test_missing_renew_until_key_raises(self, make_client) -> None:
        """The contract pins ``renew_until`` as always present (string or
        null) -- Giordon owns the deploy of both this broker and
        krb5-token-service, so there is no scenario where a deployed
        service omits the key -- an absent key is a service bug to surface
        loudly, not skew to tolerate (same doctrine as voms_service.py's
        ``nickname``)."""
        response = dict(_MINT_RESPONSE)
        del response["renew_until"]
        client, _ = make_client(httpx.Response(200, json=response))
        with pytest.raises(KeyError):
            await _mint(client)


class TestMintFailures:
    async def test_mint_400_raises_bad_credential_error(self, make_client) -> None:
        client, _ = make_client(httpx.Response(400, json={"detail": "bad password"}))
        with pytest.raises(Krb5TokenBadCredentialError):
            await _mint(client)

    async def test_mint_403_raises_account_error(self, make_client) -> None:
        client, _ = make_client(httpx.Response(403, json={"detail": "account revoked"}))
        with pytest.raises(Krb5TokenAccountError):
            await _mint(client)

    async def test_mint_422_raises_invalid_request_error(self, make_client) -> None:
        client, _ = make_client(
            httpx.Response(422, json={"detail": "invalid lifetime"})
        )
        with pytest.raises(Krb5TokenInvalidRequestError):
            await _mint(client)

    async def test_mint_429_raises_rate_limited_error_with_retry_after(
        self, make_client
    ) -> None:
        client, _ = make_client(httpx.Response(429, headers={"Retry-After": "30"}))
        with pytest.raises(Krb5TokenRateLimitedError) as exc_info:
            await _mint(client)
        assert exc_info.value.retry_after == "30"

    async def test_mint_429_without_retry_after_header_is_none(
        self, make_client
    ) -> None:
        client, _ = make_client(httpx.Response(429))
        with pytest.raises(Krb5TokenRateLimitedError) as exc_info:
            await _mint(client)
        assert exc_info.value.retry_after is None

    async def test_mint_401_raises_generic_mint_error(self, make_client) -> None:
        """401 means the BROKER's own identity token was rejected -- a
        broker<->service contract failure the end user cannot act on, so it
        must NOT read as a bad CERN password (unlike condor-token's
        doctrine, krb5 has genuine client-actionable 400/403 cases, so 401
        must stay clearly distinct)."""
        client, _ = make_client(httpx.Response(401))
        with pytest.raises(Krb5TokenMintError):
            await _mint(client)

    async def test_mint_502_raises_generic_mint_error(self, make_client) -> None:
        client, _ = make_client(httpx.Response(502))
        with pytest.raises(Krb5TokenMintError):
            await _mint(client)

    async def test_connection_error_is_generic_mint_error(self, make_client) -> None:
        client, _ = make_client(httpx.ConnectError("connection refused"))
        with pytest.raises(Krb5TokenMintError):
            await _mint(client)

    async def test_error_message_never_carries_the_password_or_body(
        self, make_client
    ) -> None:
        client, _ = make_client(
            httpx.Response(502, text="hunter2 leaked into an error page")
        )
        with pytest.raises(Krb5TokenMintError) as e:
            await _mint(client)
        assert "hunter2" not in str(e.value)


class TestMintRequest:
    async def test_mint_sends_broker_token_and_credentials_in_body(
        self, make_client, issuer: BrokerTokenIssuer
    ) -> None:
        client, requests = make_client()
        await _mint(
            client,
            username="alice",
            password=SecretStr("hunter2"),
            lifetime="8:00",
            renewable_lifetime="7d",
        )
        assert len(requests) == 1
        assert str(requests[0].url) == f"{_SERVICE_URL}/v1/mint"

        auth = requests[0].headers["authorization"]
        assert auth.startswith("Bearer ")
        claims = issuer.verify(auth.removeprefix("Bearer "))
        assert claims is not None
        assert claims["aud"] == "krb5-token-service"

        body = json.loads(requests[0].content)
        assert body["username"] == "alice"
        assert body["password"] == "hunter2"
        assert body["lifetime"] == "8:00"
        assert body["renewable_lifetime"] == "7d"

    async def test_optional_lifetime_fields_are_omitted_by_default(
        self, make_client
    ) -> None:
        client, requests = make_client()
        await _mint(client)
        body = json.loads(requests[0].content)
        assert "lifetime" not in body
        assert "renewable_lifetime" not in body

    async def test_service_url_trailing_slash_is_normalized(self, make_client) -> None:
        client, requests = make_client(service_url=f"{_SERVICE_URL}/")
        await _mint(client)
        assert str(requests[0].url) == f"{_SERVICE_URL}/v1/mint"

    async def test_audience_is_configurable(
        self, make_client, issuer: BrokerTokenIssuer
    ) -> None:
        client, requests = make_client(audience="krb5-mint")
        await _mint(client)
        claims = issuer.verify(
            requests[0].headers["authorization"].removeprefix("Bearer ")
        )
        assert claims is not None
        assert claims["aud"] == "krb5-mint"
