from __future__ import annotations

import asyncio
from typing import Any, ClassVar

import httpx
import pytest
from fastapi import HTTPException
from pydantic import SecretStr

from af_mcp_broker.config import Settings
from af_mcp_broker.credentials import oidc
from af_mcp_broker.credentials.cache import CredentialCache
from af_mcp_broker.identity import Principal

REAL_TOKEN = "real-af-access-token-value"


def _principal(
    *,
    subject: str = "user-123",
    uid: int | None = 50123,
    gid: int | None = 5000,
    unixname: str | None = "auser",
) -> Principal:
    return Principal(
        subject=subject,
        email="user@example.org",
        uid=uid,
        gid=gid,
        unixname=unixname,
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
        alias="atlas-oidc",
    )
    token, _expires_at = await provider._fetch_brokered_token(_principal())

    assert token == "iam-token"
    auth = _FakeClient.captured["Authorization"]
    assert auth == f"Bearer {REAL_TOKEN}"
    assert "*" not in auth


async def test_fetch_brokered_token_raises_403_with_actionable_detail(monkeypatch):
    """A 403 from Keycloak's broker endpoint means the caller lacks the
    `read-token` client role — surface that distinctly from the existing
    401 (session expired)/404 (never linked) handling rather than letting
    it fall through to raise_for_status()'s opaque 5xx-shaped error."""

    class _ForbiddenClient:
        async def get(self, url: str, headers: dict[str, str], **kwargs: Any):
            return httpx.Response(403)

    monkeypatch.setattr(oidc, "get_http_client", _ForbiddenClient)

    provider = oidc.OIDCProvider(
        settings=Settings(oidc_issuer="https://keycloak.test/realms/connect"),
        cache=CredentialCache(),
        alias="atlas-oidc",
    )

    with pytest.raises(HTTPException) as exc_info:
        await provider._fetch_brokered_token(_principal())

    assert exc_info.value.status_code == 403


async def test_fetch_brokered_token_uses_internal_url_when_set(monkeypatch):
    """The stored-brokered-token fetch is a server-side call and must follow
    oidc_internal_url, not the externally-advertised issuer."""
    captured_urls: list[str] = []

    class _UrlCapturingClient:
        async def get(
            self, url: str, headers: dict[str, str], **kwargs: Any
        ) -> _FakeResponse:
            captured_urls.append(url)
            return _FakeResponse()

    monkeypatch.setattr(oidc, "get_http_client", _UrlCapturingClient)

    internal = "http://keycloak.svc.test:8080/realms/connect"
    provider = oidc.OIDCProvider(
        settings=Settings(
            oidc_issuer="https://keycloak.test/realms/connect",
            oidc_internal_url=internal,
        ),
        cache=CredentialCache(),
        alias="atlas-oidc",
    )
    await provider._fetch_brokered_token(_principal())

    assert captured_urls == [f"{internal}/broker/atlas-oidc/token"]


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
        alias="atlas-oidc",
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


async def test_link_status_flags_permission_denied_on_403(monkeypatch):
    """A 403 means the caller's own bearer token lacks the `read-token`
    client role Keycloak's broker endpoint requires — distinct from "not
    linked yet" (issue: users blocked from ever seeing a completed link
    reflected, with no indication the real cause is a missing role)."""
    client = _FakeLinkClient(status_code=403)
    monkeypatch.setattr(oidc, "get_http_client", lambda: client)

    status = await _make_provider().link_status(_principal())

    assert status.linked is False
    assert status.permission_denied is True


async def test_link_status_not_permission_denied_on_404(monkeypatch):
    """404 (no stored token yet) must NOT be flagged as permission_denied —
    only 403 means the role, not the linkage, is the blocker."""
    client = _FakeLinkClient(status_code=404)
    monkeypatch.setattr(oidc, "get_http_client", lambda: client)

    status = await _make_provider().link_status(_principal())

    assert status.linked is False
    assert status.permission_denied is False


async def test_link_status_not_permission_denied_on_network_error(monkeypatch):
    class _FailingClient:
        async def head(self, *args: Any, **kwargs: Any):
            raise httpx.ConnectError("boom")

    monkeypatch.setattr(oidc, "get_http_client", _FailingClient)

    status = await _make_provider().link_status(_principal())

    assert status.linked is False
    assert status.permission_denied is False


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
    cached = provider._link_cache[principal.subject]
    cached.checked_at -= oidc._LINK_CACHE_TTL_SECONDS + 1

    assert await provider.is_linked(principal) is True
    assert client.head_calls == 2


# ---------------------------------------------------------------------------
# issue() single-flighting (issue #94)
# ---------------------------------------------------------------------------


class _CountingTokenClient:
    """Fake httpx client for the brokered-token fetch; counts calls and
    forces a real suspension so concurrent callers actually overlap instead
    of each running to completion before the next one starts."""

    def __init__(self):
        self.calls = 0

    async def get(self, url: str, headers: dict[str, str], **kwargs: Any):
        self.calls += 1
        await asyncio.sleep(0.01)
        return _FakeResponse()


async def test_issue_single_flights_concurrent_misses(monkeypatch):
    """N concurrent issue() calls for the same (uid, target) must cost
    exactly one Keycloak brokered-token fetch (issue #94)."""
    client = _CountingTokenClient()
    monkeypatch.setattr(oidc, "get_http_client", lambda: client)

    provider = _make_provider()
    principal = _principal()

    results = await asyncio.gather(
        *[provider.issue(principal, "rucio") for _ in range(5)]
    )

    assert client.calls == 1
    assert all(r.payload["access_token"] == "iam-token" for r in results)


async def test_issue_different_targets_do_not_serialize(monkeypatch):
    """Concurrent misses for different targets must not block on each
    other's single-flight lock."""
    entered: list[str] = []
    both_entered = asyncio.Event()

    class _BlockingClient:
        async def get(self, url: str, headers: dict[str, str], **kwargs: Any):
            entered.append(url)
            if len(entered) == 2:
                both_entered.set()
            # Deadlocks (and the test times out) if the two targets were
            # serialized behind a single shared lock instead of per-key ones.
            await asyncio.wait_for(both_entered.wait(), timeout=2.0)
            return _FakeResponse()

    monkeypatch.setattr(oidc, "get_http_client", _BlockingClient)

    provider = _make_provider()
    principal = _principal()

    results = await asyncio.wait_for(
        asyncio.gather(
            provider.issue(principal, "rucio"),
            provider.issue(principal, "opendata"),
        ),
        timeout=2.0,
    )

    assert len(entered) == 2
    assert {r.target for r in results} == {"rucio", "opendata"}


# ---------------------------------------------------------------------------
# Cache isolation without POSIX identity (issue #148)
# ---------------------------------------------------------------------------


class _PerCallTokenClient:
    """Fake httpx client returning a distinct access_token per call, so a
    cache-key collision (two principals sharing one cached credential) shows
    up as an assertion failure rather than silently passing."""

    def __init__(self) -> None:
        self.calls = 0

    async def get(self, url: str, headers: dict[str, str], **kwargs: Any):
        self.calls += 1
        return _FakeResponseWithToken(f"token-{self.calls}")


class _FakeResponseWithToken:
    status_code = 200

    def __init__(self, token: str) -> None:
        self._token = token

    def raise_for_status(self) -> None:
        pass

    def json(self) -> dict[str, Any]:
        return {"access_token": self._token, "expires_in": 3600}


async def test_issue_does_not_collide_for_two_posix_less_principals(monkeypatch):
    """Two different principals with no POSIX identity (both uid=None) must
    never share a cached credential -- the CredentialCache key is
    principal.subject, not uid, precisely so this can't happen (issue #148).
    """
    client = _PerCallTokenClient()
    monkeypatch.setattr(oidc, "get_http_client", lambda: client)

    provider = _make_provider()
    alice = _principal(subject="alice", uid=None, gid=None, unixname=None)
    bob = _principal(subject="bob", uid=None, gid=None, unixname=None)

    alice_cred = await provider.issue(alice, "rucio")
    bob_cred = await provider.issue(bob, "rucio")

    assert client.calls == 2
    assert alice_cred.payload["access_token"] != bob_cred.payload["access_token"]
