"""Tests for the voms-token-service mint client (issue #112 follow-up).

``VomsTokenServiceClient`` speaks the contract documented in
maniaclab/voms-token-service: ``POST {url}/v1/mint`` authenticated by an AF
Broker Identity Token with ``aud=voms-token-service``, JSON body
``{"unixname", "uid", "gid", "passphrase", "voms", "valid"}``, returning
``{"pem", "dn", "voms_attributes", "expires_at"}``. A 400 is the service's
"bad passphrase" signal (counts against the unlock rate limiter); anything
else — 401/403/5xx, timeouts, connection failures — is an infra failure that
must NOT count, the same distinction ``ProxyHarvestError`` draws for the
legacy k8s-Job mint path.
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
from af_mcp_broker.credentials.voms_service import (
    MintedProxy,
    VomsServiceBadPassphraseError,
    VomsServiceMintError,
    VomsTokenServiceClient,
)

if TYPE_CHECKING:
    from collections.abc import Callable

_ISSUER_URL = "https://mcp.example.com"
_SERVICE_URL = "http://voms-token-service.af-mcp.svc.cluster.local:8000"

_MINT_RESPONSE = {
    "pem": "-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----\n",
    "dn": "/DC=ch/DC=cern/CN=Test User",
    "voms_attributes": ["/atlas/Role=NULL", "/atlas"],
    "expires_at": "2030-06-15T12:00:00+00:00",
}
_EXPECTED_NOT_AFTER = datetime(2030, 6, 15, 12, 0, 0, tzinfo=UTC).timestamp()


@pytest.fixture
def issuer() -> BrokerTokenIssuer:
    return BrokerTokenIssuer(
        private_key_pem=_private_pem(_make_rsa_key()), issuer=_ISSUER_URL
    )


@pytest.fixture
def make_client(
    issuer: BrokerTokenIssuer,
) -> Callable[..., tuple[VomsTokenServiceClient, list[httpx.Request]]]:
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
    ) -> tuple[VomsTokenServiceClient, list[httpx.Request]]:
        requests: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            requests.append(request)
            if isinstance(responder, Exception):
                raise responder
            if responder is None:
                return httpx.Response(200, json=_MINT_RESPONSE)
            return responder

        http_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        client = VomsTokenServiceClient(
            issuer=issuer,
            service_url=service_url,
            http_client=http_client,
            **kwargs,  # type: ignore[arg-type]
        )
        return client, requests

    return _make


async def _mint(client: VomsTokenServiceClient) -> MintedProxy:
    return await client.mint(
        subject="user-123",
        unixname="auser",
        uid=50123,
        gid=5000,
        passphrase=SecretStr("hunter2-passphrase"),
    )


class TestMintRequest:
    async def test_posts_to_v1_mint(self, make_client) -> None:
        client, requests = make_client()
        await _mint(client)
        assert len(requests) == 1
        assert requests[0].method == "POST"
        assert str(requests[0].url) == f"{_SERVICE_URL}/v1/mint"

    async def test_service_url_trailing_slash_is_normalized(self, make_client) -> None:
        # AnyHttpUrl-normalized origins carry a trailing slash; the endpoint
        # join must never produce "//v1/mint" (same guard as condor.py).
        client, requests = make_client(service_url=f"{_SERVICE_URL}/")
        await _mint(client)
        assert str(requests[0].url) == f"{_SERVICE_URL}/v1/mint"

    async def test_bearer_token_is_broker_issued_with_service_audience(
        self, make_client, issuer: BrokerTokenIssuer
    ) -> None:
        client, requests = make_client()
        await _mint(client)
        auth = requests[0].headers["authorization"]
        assert auth.startswith("Bearer ")
        claims = issuer.verify(auth.removeprefix("Bearer "))
        assert claims is not None
        assert claims["sub"] == "user-123"
        assert claims["aud"] == "voms-token-service"

    async def test_audience_is_configurable(
        self, make_client, issuer: BrokerTokenIssuer
    ) -> None:
        client, requests = make_client(audience="voms-mint")
        await _mint(client)
        claims = issuer.verify(
            requests[0].headers["authorization"].removeprefix("Bearer ")
        )
        assert claims is not None
        assert claims["aud"] == "voms-mint"

    async def test_body_carries_posix_identity_passphrase_and_defaults(
        self, make_client
    ) -> None:
        client, requests = make_client()
        await _mint(client)
        body = json.loads(requests[0].content)
        assert body == {
            "unixname": "auser",
            "uid": 50123,
            "gid": 5000,
            "passphrase": "hunter2-passphrase",
            "voms": "atlas",
            "valid": "192:00",
        }

    async def test_voms_and_valid_are_configurable(self, make_client) -> None:
        client, requests = make_client(voms="atlas:/atlas/usatlas", valid="24:00")
        await _mint(client)
        body = json.loads(requests[0].content)
        assert body["voms"] == "atlas:/atlas/usatlas"
        assert body["valid"] == "24:00"


class TestMintResponse:
    async def test_success_returns_minted_proxy(self, make_client) -> None:
        client, _ = make_client()
        minted = await _mint(client)
        assert minted.pem == _MINT_RESPONSE["pem"]
        assert minted.dn == _MINT_RESPONSE["dn"]
        assert minted.voms_attributes == _MINT_RESPONSE["voms_attributes"]
        assert minted.not_after == pytest.approx(_EXPECTED_NOT_AFTER)

    async def test_naive_expires_at_is_interpreted_as_utc(self, make_client) -> None:
        response = dict(_MINT_RESPONSE)
        response["expires_at"] = "2030-06-15T12:00:00"  # no tzinfo
        client, _ = make_client(httpx.Response(200, json=response))
        minted = await _mint(client)
        assert minted.not_after == pytest.approx(_EXPECTED_NOT_AFTER)


class TestMintFailures:
    async def test_400_is_bad_passphrase(self, make_client) -> None:
        client, _ = make_client(httpx.Response(400, json={"detail": "bad passphrase"}))
        with pytest.raises(VomsServiceBadPassphraseError):
            await _mint(client)

    async def test_bad_passphrase_is_a_value_error(self, make_client) -> None:
        """Existing ``except ValueError`` call sites (the legacy mint path's
        bad-passphrase convention) must keep catching the new signal."""
        client, _ = make_client(httpx.Response(400, json={"detail": "bad passphrase"}))
        with pytest.raises(ValueError, match="passphrase"):
            await _mint(client)

    @pytest.mark.parametrize("status_code", [401, 403, 500, 502, 503])
    async def test_non_400_error_status_is_infra_failure(
        self, make_client, status_code: int
    ) -> None:
        client, _ = make_client(
            httpx.Response(status_code, json={"detail": "internals"})
        )
        with pytest.raises(VomsServiceMintError):
            await _mint(client)

    async def test_infra_failure_is_not_a_bad_passphrase(self, make_client) -> None:
        """The two failure types must stay disjoint: callers rate-limit on
        one and not the other."""
        client, _ = make_client(httpx.Response(502, json={"detail": "boom"}))
        with pytest.raises(VomsServiceMintError) as excinfo:
            await _mint(client)
        assert not isinstance(excinfo.value, VomsServiceBadPassphraseError)

    async def test_connection_error_is_infra_failure(self, make_client) -> None:
        client, _ = make_client(httpx.ConnectError("connection refused"))
        with pytest.raises(VomsServiceMintError):
            await _mint(client)

    async def test_timeout_is_infra_failure(self, make_client) -> None:
        client, _ = make_client(httpx.ReadTimeout("timed out"))
        with pytest.raises(VomsServiceMintError):
            await _mint(client)

    @pytest.mark.parametrize(
        "responder",
        [
            httpx.Response(400, json={"detail": "bad passphrase"}),
            httpx.Response(502, text="hunter2-passphrase leaked into an error page"),
        ],
    )
    async def test_error_messages_never_carry_the_passphrase_or_body(
        self, make_client, responder: httpx.Response
    ) -> None:
        client, _ = make_client(responder)
        with pytest.raises((VomsServiceBadPassphraseError, VomsServiceMintError)) as e:
            await _mint(client)
        assert "hunter2-passphrase" not in str(e.value)
