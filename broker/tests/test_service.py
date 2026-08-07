"""Unit tests for ServiceProvider.is_linked().

ServiceProvider uses the broker's own shared service credential, not any
per-user linkage, so is_linked() has exactly one behavior to verify: it is
always True regardless of the principal.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from pydantic import SecretStr

from af_mcp_broker.config import Settings
from af_mcp_broker.credentials import service as service_module
from af_mcp_broker.credentials.service import ServiceProvider
from af_mcp_broker.identity import Principal


def _principal() -> Principal:
    return Principal(
        subject="user-123",
        email="user@example.org",
        uid=50123,
        gid=5000,
        unixname="auser",
        groups=["af-atlas-users"],
        raw_token=SecretStr("fake-token"),
    )


@pytest.mark.asyncio
async def test_is_linked_always_true():
    provider = ServiceProvider(settings=SimpleNamespace())

    assert await provider.is_linked(_principal()) is True


@pytest.mark.asyncio
async def test_client_credentials_grant_uses_internal_url_when_set(monkeypatch):
    """The service-account token grant is a server-side call and must follow
    oidc_internal_url, not the externally-advertised issuer."""
    captured_urls: list[str] = []

    class _FakeResponse:
        def raise_for_status(self) -> None:
            pass

        def json(self) -> dict[str, object]:
            return {"access_token": "svc-token", "expires_in": 3600}

    class _UrlCapturingClient:
        async def post(self, url: str, **kwargs: object) -> _FakeResponse:
            captured_urls.append(url)
            return _FakeResponse()

    monkeypatch.setattr(service_module, "get_http_client", _UrlCapturingClient)
    monkeypatch.delenv("AF_SERVICE_TOKEN", raising=False)
    monkeypatch.delenv("AF_SERVICE_TOKEN_FILE", raising=False)
    monkeypatch.setenv("AF_SERVICE_CLIENT_ID", "svc-client")
    monkeypatch.setenv("AF_SERVICE_CLIENT_SECRET", "svc-secret")

    internal = "http://keycloak.svc.test:8080/realms/connect"
    provider = ServiceProvider(
        settings=Settings(
            oidc_issuer="https://keycloak.test/realms/connect",
            oidc_internal_url=internal,
        )
    )
    token, _expires_at = await provider._refresh_service_token()

    assert token == "svc-token"
    assert captured_urls == [f"{internal}/protocol/openid-connect/token"]
