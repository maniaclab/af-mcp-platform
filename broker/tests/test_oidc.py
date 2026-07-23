from __future__ import annotations

from typing import Any, ClassVar

import httpx
import pytest
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

    captured: ClassVar[dict[str, str]] = {}

    async def get(
        self, url: str, headers: dict[str, str], **kwargs: Any
    ) -> _FakeResponse:
        type(self).captured = dict(headers)
        return _FakeResponse()


async def test_fetch_brokered_token_sends_real_token(monkeypatch):
    """Regression for bug 2 — the real token, not the masked SecretStr repr."""
    monkeypatch.setattr(oidc, "get_http_client", _FakeClient)

    provider = oidc.OIDCProvider(
        settings=Settings(oidc_issuer="https://keycloak.test/realms/connect"),
        cache=CredentialCache(),
    )
    token, _expires_at = await provider._fetch_brokered_token(_principal())

    assert token == "iam-token"
    auth = _FakeClient.captured["Authorization"]
    assert auth == f"Bearer {REAL_TOKEN}"
    assert "*" not in auth


# ---------------------------------------------------------------------------
# is_linked()
# ---------------------------------------------------------------------------


class _FakeLinkClient:
    """Fake httpx client for is_linked() probing.

    Counts HEAD/GET calls separately so tests can assert both the TTL cache
    (no repeat network calls within the window) and the HEAD-unsupported
    fallback (HEAD then GET, in that order).
    """

    def __init__(self, status_code: int = 200, *, head_status: int | None = None):
        self.status_code = status_code
        self.head_status = head_status if head_status is not None else status_code
        self.head_calls = 0
        self.get_calls = 0

    async def head(self, url: str, headers: dict[str, str], **kwargs: Any):
        self.head_calls += 1
        return httpx.Response(self.head_status)

    async def get(self, url: str, headers: dict[str, str], **kwargs: Any):
        self.get_calls += 1
        return httpx.Response(self.status_code)


def _make_provider() -> oidc.OIDCProvider:
    return oidc.OIDCProvider(
        settings=Settings(oidc_issuer="https://keycloak.test/realms/connect"),
        cache=CredentialCache(),
    )


async def test_is_linked_true_on_200(monkeypatch):
    client = _FakeLinkClient(status_code=200)
    monkeypatch.setattr(oidc, "get_http_client", lambda: client)

    assert await _make_provider().is_linked(_principal()) is True
    assert client.head_calls == 1


@pytest.mark.parametrize("status_code", [403, 404])
async def test_is_linked_false_on_4xx(monkeypatch, status_code):
    client = _FakeLinkClient(status_code=status_code)
    monkeypatch.setattr(oidc, "get_http_client", lambda: client)

    assert await _make_provider().is_linked(_principal()) is False


async def test_is_linked_falls_back_to_get_when_head_unsupported(monkeypatch):
    client = _FakeLinkClient(status_code=200, head_status=405)
    monkeypatch.setattr(oidc, "get_http_client", lambda: client)

    assert await _make_provider().is_linked(_principal()) is True
    assert client.head_calls == 1
    assert client.get_calls == 1


async def test_is_linked_false_on_network_error(monkeypatch):
    class _FailingClient:
        async def head(self, *args: Any, **kwargs: Any):
            raise httpx.ConnectError("boom")

    monkeypatch.setattr(oidc, "get_http_client", _FailingClient)

    assert await _make_provider().is_linked(_principal()) is False


async def test_is_linked_respects_cache_within_ttl(monkeypatch):
    """Two calls inside the TTL window must cost exactly one Keycloak probe."""
    client = _FakeLinkClient(status_code=200)
    monkeypatch.setattr(oidc, "get_http_client", lambda: client)

    provider = _make_provider()
    principal = _principal()

    assert await provider.is_linked(principal) is True
    assert await provider.is_linked(principal) is True
    assert client.head_calls == 1


async def test_is_linked_reprobes_after_ttl_expires(monkeypatch):
    client = _FakeLinkClient(status_code=200)
    monkeypatch.setattr(oidc, "get_http_client", lambda: client)

    provider = _make_provider()
    principal = _principal()

    assert await provider.is_linked(principal) is True
    # Force the cached entry to look stale without sleeping in the test.
    cached = provider._link_cache[principal.uid]
    cached.checked_at -= oidc._LINK_CACHE_TTL_SECONDS + 1

    assert await provider.is_linked(principal) is True
    assert client.head_calls == 2
