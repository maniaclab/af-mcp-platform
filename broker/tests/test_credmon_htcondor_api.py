"""Tests for the htcondor-api credential store client (docs/credmon.md).

``HTCondorApiCredentialStore`` speaks golang-htcondor's REST contract
(webapi/httpserver/handlers_credd.go): ``POST {url}/api/v1/creds/service/
{service}`` with JSON ``{"cred_type", "credential", "service", "user",
"refresh"}``. ``credential`` is sent base64-encoded because the handler
base64-decodes it when it can and falls back to the raw string otherwise
-- explicit base64 removes that ambiguity. ``refresh: true`` makes credd
write a ``.top`` file (the credmon's input) rather than a ``.use``.
"""

from __future__ import annotations

import base64
import json
from typing import TYPE_CHECKING

import httpx
import pytest
from pydantic import SecretStr

from af_mcp_broker.credmon.htcondor_api import HTCondorApiCredentialStore
from af_mcp_broker.credmon.storer import CredentialStoreError

if TYPE_CHECKING:
    from collections.abc import Callable

_API_URL = "https://htcondor-api.af.example.org"


@pytest.fixture
def make_store() -> Callable[
    ..., tuple[HTCondorApiCredentialStore, list[httpx.Request]]
]:
    def _make(
        responder: httpx.Response | Exception | None = None,
        api_url: str = _API_URL,
    ) -> tuple[HTCondorApiCredentialStore, list[httpx.Request]]:
        requests: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            requests.append(request)
            if isinstance(responder, Exception):
                raise responder
            if responder is None:
                return httpx.Response(201, json={"exists": True})
            return responder

        store = HTCondorApiCredentialStore(
            api_url=api_url,
            token=SecretStr("storer-idtoken"),
            http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        )
        return store, requests

    return _make


async def test_store_posts_oauth_top_credential_for_user(make_store) -> None:
    store, requests = make_store()

    await store.store_service_credential(
        user="alice", service="af_krb5", credential={"access_token": "top-token"}
    )

    assert len(requests) == 1
    request = requests[0]
    assert request.method == "POST"
    assert str(request.url) == f"{_API_URL}/api/v1/creds/service/af_krb5"
    assert request.headers["Authorization"] == "Bearer storer-idtoken"
    body = json.loads(request.content)
    assert body["cred_type"] == "oauth"
    assert body["service"] == "af_krb5"
    assert body["user"] == "alice"
    assert body["refresh"] is True
    assert json.loads(base64.b64decode(body["credential"])) == {
        "access_token": "top-token"
    }


async def test_trailing_slash_in_api_url_is_normalized(make_store) -> None:
    store, requests = make_store(api_url=f"{_API_URL}/")

    await store.store_service_credential(
        user="alice", service="af_x509", credential={"access_token": "t"}
    )

    assert str(requests[0].url) == f"{_API_URL}/api/v1/creds/service/af_x509"


async def test_error_status_raises_with_status_and_detail(make_store) -> None:
    store, _ = make_store(
        httpx.Response(
            500, json={"error": "Failed to store service credential: denied"}
        )
    )

    with pytest.raises(CredentialStoreError) as exc_info:
        await store.store_service_credential(
            user="alice", service="af_krb5", credential={"access_token": "top-token"}
        )

    message = str(exc_info.value)
    assert "500" in message
    assert "denied" in message
    assert "top-token" not in message


async def test_transport_error_raises_credential_store_error(make_store) -> None:
    store, _ = make_store(httpx.ConnectError("connection refused"))

    with pytest.raises(CredentialStoreError, match="could not be reached"):
        await store.store_service_credential(
            user="alice", service="af_krb5", credential={"access_token": "t"}
        )
