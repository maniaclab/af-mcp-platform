"""Tests for ProxyClient (af_credentials.proxy): the client side of the
x509/VOMS proxy redeem contract this library codes against --
``POST {broker_url}/v1/credentials/x509/redeem`` (to be implemented broker-
side; see the module docstring in proxy.py and this package's README for
the exact request/response shape).
"""

from __future__ import annotations

import stat
from datetime import UTC, datetime, timedelta

import httpx2
import pytest

from af_credentials.proxy import ProxyClient, ProxyNotAvailableError, ProxyRedeemError

BROKER_URL = "https://broker.af.example.org"
_REDEEM_PATH = "/v1/credentials/x509/redeem"

_PEM = "-----BEGIN CERTIFICATE-----\nfake-proxy-material\n-----END CERTIFICATE-----\n"
_DN = "/DC=ch/DC=cern/OU=Organic Units/OU=Users/CN=kratsg/CN=123456/CN=Giordon Stark"
_EXPIRES_AT = (datetime.now(UTC) + timedelta(hours=1)).isoformat()


def _redeem_response(
    *,
    status_code: int = 200,
    remaining_seconds: int = 3600,
    detail: str | None = None,
) -> dict[str, object]:
    if status_code != 200:
        return {"detail": detail or "error"}
    return {
        "pem": _PEM,
        "dn": _DN,
        "voms_attributes": ["/atlas/Role=NULL/Capability=NULL"],
        "expires_at": _EXPIRES_AT,
        "remaining_seconds": remaining_seconds,
    }


def _client_for(
    response_kwargs: dict[str, object] | None = None,
    *,
    status_code: int = 200,
    captured_requests: list[httpx2.Request] | None = None,
) -> httpx2.AsyncClient:
    body = _redeem_response(status_code=status_code, **(response_kwargs or {}))

    def handler(request: httpx2.Request) -> httpx2.Response:
        if captured_requests is not None:
            captured_requests.append(request)
        return httpx2.Response(status_code, json=body)

    return httpx2.AsyncClient(transport=httpx2.MockTransport(handler))


class TestProxyFileHappyPath:
    async def test_sends_expected_request(self) -> None:
        requests: list[httpx2.Request] = []
        http_client = _client_for(captured_requests=requests)
        client = ProxyClient(BROKER_URL, http_client=http_client)

        with await client.proxy_file("my-bearer-token"):
            pass

        assert len(requests) == 1
        request = requests[0]
        assert request.method == "POST"
        assert str(request.url) == f"{BROKER_URL}{_REDEEM_PATH}"
        assert request.headers["authorization"] == "Bearer my-bearer-token"
        assert request.content == b"{}"

    async def test_file_created_with_content_and_0600_permissions(self) -> None:
        http_client = _client_for()
        client = ProxyClient(BROKER_URL, http_client=http_client)

        with await client.proxy_file("bearer") as handle:
            assert handle.path.exists()
            assert handle.path.read_text() == _PEM
            mode = stat.S_IMODE(handle.path.stat().st_mode)
            assert mode == 0o600
            assert handle.dn == _DN

    async def test_directory_created_with_0700_permissions(self) -> None:
        http_client = _client_for()
        client = ProxyClient(BROKER_URL, http_client=http_client)

        with await client.proxy_file("bearer") as handle:
            mode = stat.S_IMODE(handle.path.parent.stat().st_mode)
            assert mode == 0o700

    async def test_context_manager_deletes_file_on_exit(self) -> None:
        http_client = _client_for()
        client = ProxyClient(BROKER_URL, http_client=http_client)

        handle = await client.proxy_file("bearer")
        path = handle.path
        assert path.exists()
        with handle:
            pass
        assert not path.exists()

    async def test_close_is_idempotent(self) -> None:
        http_client = _client_for()
        client = ProxyClient(BROKER_URL, http_client=http_client)

        handle = await client.proxy_file("bearer")
        handle.close()
        handle.close()  # must not raise on an already-deleted file
        assert not handle.path.exists()

    async def test_two_calls_get_independent_handles(self) -> None:
        """No caching of handles across calls -- each proxy_file() call gets its own file, and closing one must not affect the other."""
        http_client = _client_for()
        client = ProxyClient(BROKER_URL, http_client=http_client)

        first = await client.proxy_file("bearer")
        second = await client.proxy_file("bearer")

        assert first.path != second.path
        first.close()
        assert second.path.exists()
        second.close()


class TestPemBytes:
    async def test_returns_pem_as_bytes(self) -> None:
        http_client = _client_for()
        client = ProxyClient(BROKER_URL, http_client=http_client)

        result = await client.pem_bytes("bearer")

        assert result == _PEM.encode()

    async def test_does_not_write_any_file(self) -> None:
        http_client = _client_for()
        client = ProxyClient(BROKER_URL, http_client=http_client)

        await client.pem_bytes("bearer")

        assert client._dir is None  # whitebox: no lazy dir created


class TestProxyNotAvailable:
    async def test_404_raises_proxy_not_available_with_detail(self) -> None:
        http_client = _client_for(
            status_code=404,
            response_kwargs={"detail": "no linked .globus for this user"},
        )
        client = ProxyClient(BROKER_URL, http_client=http_client)

        with pytest.raises(ProxyNotAvailableError, match="no linked"):
            await client.proxy_file("bearer")

    async def test_short_remaining_raises_proxy_not_available(self) -> None:
        http_client = _client_for(response_kwargs={"remaining_seconds": 30})
        client = ProxyClient(BROKER_URL, min_remaining=60.0, http_client=http_client)

        with pytest.raises(ProxyNotAvailableError, match="30"):
            await client.proxy_file("bearer")

    async def test_remaining_exactly_at_floor_is_accepted(self) -> None:
        http_client = _client_for(response_kwargs={"remaining_seconds": 60})
        client = ProxyClient(BROKER_URL, min_remaining=60.0, http_client=http_client)

        handle = await client.proxy_file("bearer")
        handle.close()


class TestProxyRedeemError:
    async def test_500_raises_proxy_redeem_error(self) -> None:
        http_client = _client_for(
            status_code=500, response_kwargs={"detail": "mint failed"}
        )
        client = ProxyClient(BROKER_URL, http_client=http_client)

        with pytest.raises(ProxyRedeemError, match="mint failed"):
            await client.proxy_file("bearer")

    async def test_500_error_carries_status_code(self) -> None:
        http_client = _client_for(status_code=500)
        client = ProxyClient(BROKER_URL, http_client=http_client)

        with pytest.raises(ProxyRedeemError) as exc_info:
            await client.proxy_file("bearer")
        assert exc_info.value.status_code == 500


class TestTransportErrorsPropagate:
    async def test_connect_error_raises(self) -> None:
        def handler(request: httpx2.Request) -> httpx2.Response:
            raise httpx2.ConnectError("connection refused")

        http_client = httpx2.AsyncClient(transport=httpx2.MockTransport(handler))
        client = ProxyClient(BROKER_URL, http_client=http_client)

        with pytest.raises(httpx2.ConnectError):
            await client.proxy_file("bearer")
