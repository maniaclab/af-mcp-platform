from __future__ import annotations

from typing import Any

from pydantic import SecretStr

from af_mcp_broker.config import Settings
from af_mcp_broker.credentials import oidc
from af_mcp_broker.credentials.cache import CredentialCache
from af_mcp_broker.identity import Principal

REAL_TOKEN = "real-af-access-token-value"


def _principal() -> Principal:
    return Principal(
        subject="user-123",
        email="user@example.org",
        uid=50123,
        gid=5000,
        unixname="auser",
        groups=["af-atlas-users"],
        iam_sub="iam-abc",
        cern_sub=None,
        raw_token=SecretStr(REAL_TOKEN),
    )


class _FakeResponse:
    status_code = 200

    def raise_for_status(self) -> None:
        pass

    def json(self) -> dict[str, Any]:
        return {"access_token": "iam-token", "expires_in": 3600}


class _FakeClient:
    """Captures the headers passed to ``get`` for assertion."""

    captured: dict[str, str] = {}

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        pass

    async def __aenter__(self) -> _FakeClient:
        return self

    async def __aexit__(self, *args: Any) -> None:
        pass

    async def get(self, url: str, headers: dict[str, str]) -> _FakeResponse:
        type(self).captured = dict(headers)
        return _FakeResponse()


async def test_fetch_brokered_token_sends_real_token(monkeypatch):
    """Regression for bug 2 — the real token, not the masked SecretStr repr."""
    monkeypatch.setattr(oidc.httpx, "AsyncClient", _FakeClient)

    provider = oidc.OIDCProvider(
        settings=Settings(keycloak_issuer="https://keycloak.test/realms/connect"),
        cache=CredentialCache(),
    )
    token, expires_at = await provider._fetch_brokered_token(_principal())

    assert token == "iam-token"
    auth = _FakeClient.captured["Authorization"]
    assert auth == f"Bearer {REAL_TOKEN}"
    assert "*" not in auth
