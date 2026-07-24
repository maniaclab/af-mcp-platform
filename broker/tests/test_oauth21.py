"""Tests for OAuth 2.1 credential brokering (issue #66 PR1).

Covers the ``TokenStore`` protocol + ``InMemoryTokenStore`` CAS semantics,
the Fernet-encrypted state token, ``OAuth21Provider.is_linked``/``issue``,
and the ``/v1/oauth/authorize`` + ``/v1/oauth/callback`` routes end-to-end
against an in-process fake backend authorization server.
"""

from __future__ import annotations

import asyncio
import json
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from cryptography.fernet import Fernet
from fastapi import HTTPException
from fastapi.testclient import TestClient
from pydantic import SecretStr

from af_mcp_broker.app import app as broker_app
from af_mcp_broker.config import get_settings
from af_mcp_broker.credentials.oauth21 import (
    InMemoryTokenStore,
    OAuth21Provider,
    StoredOAuthCredential,
    VersionConflict,
)
from af_mcp_broker.identity import Principal
from af_mcp_broker.oauth_state import (
    NONCE_COOKIE_NAME,
    NONCE_COOKIE_PATH,
    StateTokenError,
    append_linked_query_param,
    build_state_token,
    decrypt_state_token,
    sanitize_return_url,
)

ALIAS = "rucio-mcp-atlas"
SUBJECT = "kc-subject-123"

# Matches the fixed OIDC_ISSUER `app_client_factory` (conftest.py) sets before
# every test — `settings.oauth21_effective_state_issuer` falls back to it
# whenever OAUTH21_STATE_ISSUER is unset, which none of these tests set.
EXPECTED_STATE_ISSUER = "https://keycloak.invalid/realms/connect"

_SRC = Path(__file__).resolve().parents[1] / "src" / "af_mcp_broker"
SHIPPED_POLICY = _SRC / "authorization" / "policy.yaml"
SHIPPED_BACKENDS = _SRC / "mcp" / "backends.yaml"

AUTHORIZATION_ENDPOINT = "https://backend-as.example/authorize"
TOKEN_ENDPOINT = "https://backend-as.example/token"
PROVIDER_ISSUER = "https://backend-as.example"
CLIENT_ID = "https://mcp.af.uchicago.edu/.well-known/cimd"

# The canonical origin every outgoing OAuth 2.1 redirect_uri is built from
# (see api/oauth21.py's `_callback_url`) — deliberately different from
# TestClient's default request host ("testserver") so a test asserting on
# this value actually proves the redirect_uri is public-origin-derived
# rather than request-relative.
PUBLIC_ORIGIN = "https://mcp-portal.example"


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _make_cred(**overrides: Any) -> StoredOAuthCredential:
    now = datetime.now(UTC)
    defaults: dict[str, Any] = {
        "alias": ALIAS,
        "subject": SUBJECT,
        "access_token": SecretStr("access-token-1"),
        "refresh_token": SecretStr("refresh-token-1"),
        "expires_at": now + timedelta(hours=1),
        "refresh_expires_at": now + timedelta(days=30),
        "scope": ["openid", "profile"],
        "issuer": PROVIDER_ISSUER,
        "token_endpoint": TOKEN_ENDPOINT,
    }
    defaults.update(overrides)
    return StoredOAuthCredential(**defaults)


def _principal(subject: str = SUBJECT) -> Principal:
    return Principal(
        subject=subject,
        email="tuser@example.org",
        uid=1000,
        gid=1000,
        unixname="tuser",
        groups=[],
        raw_token=SecretStr("fake-token"),
    )


def _make_provider(store: InMemoryTokenStore) -> OAuth21Provider:
    return OAuth21Provider(
        alias=ALIAS,
        targets=frozenset({ALIAS}),
        authorization_endpoint=AUTHORIZATION_ENDPOINT,
        token_endpoint=TOKEN_ENDPOINT,
        issuer=PROVIDER_ISSUER,
        scope="openid profile",
        store=store,
    )


class _FakeTokenClient:
    """Fake httpx client capturing token-endpoint POSTs, for monkeypatching
    ``get_http_client`` in both the provider (refresh) and route (exchange)
    code paths.
    """

    def __init__(self, status_code: int = 200, json_body: dict[str, Any] | None = None):
        self.status_code = status_code
        self.json_body = json_body or {}
        self.calls: list[dict[str, Any]] = []

    async def post(
        self, url: str, data: dict[str, Any], **kwargs: Any
    ) -> httpx.Response:
        self.calls.append({"url": url, "data": data})
        # `request=` must be set -- `Response.raise_for_status()` (called by
        # the production code on success too) requires it even for 2xx.
        return httpx.Response(
            self.status_code, json=self.json_body, request=httpx.Request("POST", url)
        )


def _run(coro: Any) -> Any:
    """Run a coroutine to completion from a sync test body.

    ``InMemoryTokenStore.get`` takes no lock, so running it on a fresh loop
    here (separate from the TestClient's own request-handling loop) is safe.
    """
    return asyncio.run(coro)


def _configure_oauth21_env(monkeypatch: pytest.MonkeyPatch, fernet_key: str) -> None:
    monkeypatch.setenv("BROKER_STATE_KEY", fernet_key)
    monkeypatch.setenv("OAUTH21_CLIENT_ID", CLIENT_ID)
    monkeypatch.setenv("BROKER_PUBLIC_ORIGIN", PUBLIC_ORIGIN)
    monkeypatch.setenv(
        "IDENTITY_PROVIDERS",
        json.dumps(
            [
                {
                    "type": "oauth21-direct",
                    "alias": ALIAS,
                    "targets": [ALIAS],
                    "authorization_endpoint": AUTHORIZATION_ENDPOINT,
                    "token_endpoint": TOKEN_ENDPOINT,
                    "issuer": PROVIDER_ISSUER,
                    "scope": "openid profile",
                    "display_name": "Rucio (ATLAS)",
                    "enables": "ATLAS Rucio operations via rucio-mcp",
                }
            ]
        ),
    )


# ---------------------------------------------------------------------------
# TokenStore / InMemoryTokenStore CAS semantics
# ---------------------------------------------------------------------------


async def test_get_returns_none_on_missing() -> None:
    store = InMemoryTokenStore()
    assert await store.get(SUBJECT, ALIAS) is None


async def test_write_cas_creates_when_missing_returns_version_1() -> None:
    store = InMemoryTokenStore()
    version = await store.write_cas(SUBJECT, ALIAS, _make_cred(), expected_version=None)

    assert version == 1
    got = await store.get(SUBJECT, ALIAS)
    assert got is not None
    got_cred, got_version = got
    assert got_version == 1
    assert got_cred.access_token.get_secret_value() == "access-token-1"


async def test_write_cas_none_raises_when_existing() -> None:
    store = InMemoryTokenStore()
    await store.write_cas(SUBJECT, ALIAS, _make_cred(), expected_version=None)

    with pytest.raises(VersionConflict):
        await store.write_cas(SUBJECT, ALIAS, _make_cred(), expected_version=None)


async def test_write_cas_succeeds_when_version_matches() -> None:
    store = InMemoryTokenStore()
    await store.write_cas(SUBJECT, ALIAS, _make_cred(), expected_version=None)

    version = await store.write_cas(
        SUBJECT,
        ALIAS,
        _make_cred(access_token=SecretStr("access-token-2")),
        expected_version=1,
    )

    assert version == 2


async def test_write_cas_raises_when_version_stale() -> None:
    store = InMemoryTokenStore()
    await store.write_cas(SUBJECT, ALIAS, _make_cred(), expected_version=None)  # v1
    await store.write_cas(SUBJECT, ALIAS, _make_cred(), expected_version=1)  # v2

    with pytest.raises(VersionConflict):
        await store.write_cas(SUBJECT, ALIAS, _make_cred(), expected_version=1)


async def test_delete_is_idempotent() -> None:
    store = InMemoryTokenStore()
    await store.delete(SUBJECT, ALIAS)  # no entry yet -- must not raise

    await store.write_cas(SUBJECT, ALIAS, _make_cred(), expected_version=None)
    await store.delete(SUBJECT, ALIAS)
    assert await store.get(SUBJECT, ALIAS) is None

    await store.delete(SUBJECT, ALIAS)  # already gone -- still must not raise


# ---------------------------------------------------------------------------
# State token
# ---------------------------------------------------------------------------


def _build_state(cipher: Fernet, **overrides: Any) -> str:
    kwargs: dict[str, Any] = {
        "iss": EXPECTED_STATE_ISSUER,
        "sub": SUBJECT,
        "alias": ALIAS,
        "pkce_verifier": "verifier-abc",
        "return_url": "/identities",
        "nonce": "nonce-xyz",
    }
    kwargs.update(overrides)
    return build_state_token(cipher, **kwargs)


def test_state_token_round_trip() -> None:
    cipher = Fernet(Fernet.generate_key())
    token = _build_state(cipher)

    payload = decrypt_state_token(cipher, token, expected_iss=EXPECTED_STATE_ISSUER)

    assert payload.sub == SUBJECT
    assert payload.alias == ALIAS
    assert payload.pkce_verifier == "verifier-abc"
    assert payload.return_url == "/identities"
    assert payload.nonce == "nonce-xyz"


def test_state_token_expired_raises() -> None:
    cipher = Fernet(Fernet.generate_key())
    now = int(time.time())
    payload = {
        "iss": EXPECTED_STATE_ISSUER,
        "aud": EXPECTED_STATE_ISSUER,
        "sub": SUBJECT,
        "alias": ALIAS,
        "pkce_verifier": "v",
        "return_url": "/",
        "nonce": "n",
        "iat": now - 400,
        "exp": now - 100,
    }
    # Fernet's own `encrypt_at` mints the token as if created 400s ago, so its
    # `ttl=` check rejects it without needing to sleep in the test.
    token = cipher.encrypt_at_time(json.dumps(payload).encode(), now - 400).decode()

    with pytest.raises(StateTokenError):
        decrypt_state_token(cipher, token, expected_iss=EXPECTED_STATE_ISSUER)


def test_state_token_wrong_key_raises() -> None:
    cipher_a = Fernet(Fernet.generate_key())
    cipher_b = Fernet(Fernet.generate_key())
    token = _build_state(cipher_a)

    with pytest.raises(StateTokenError):
        decrypt_state_token(cipher_b, token, expected_iss=EXPECTED_STATE_ISSUER)


def test_state_token_mismatched_iss_aud_raises() -> None:
    cipher = Fernet(Fernet.generate_key())
    now = int(time.time())
    payload = {
        "iss": EXPECTED_STATE_ISSUER,
        "aud": "https://other-deployment.example/realms/connect",
        "sub": SUBJECT,
        "alias": ALIAS,
        "pkce_verifier": "v",
        "return_url": "/",
        "nonce": "n",
        "iat": now,
        "exp": now + 300,
    }
    token = cipher.encrypt(json.dumps(payload).encode()).decode()

    with pytest.raises(StateTokenError):
        decrypt_state_token(cipher, token, expected_iss=EXPECTED_STATE_ISSUER)


def test_state_token_malformed_raises() -> None:
    cipher = Fernet(Fernet.generate_key())

    with pytest.raises(StateTokenError):
        decrypt_state_token(
            cipher, "not-a-fernet-token", expected_iss=EXPECTED_STATE_ISSUER
        )


def test_sanitize_return_url_defaults_to_root_when_none() -> None:
    assert sanitize_return_url(None) == "/"


def test_sanitize_return_url_accepts_relative_path() -> None:
    assert sanitize_return_url("/identities") == "/identities"


@pytest.mark.parametrize(
    "bad_url",
    [
        "https://evil.example/x",
        "//evil.example",
        "/a/../b",
        "no-leading-slash",
    ],
)
def test_sanitize_return_url_rejects_unsafe(bad_url: str) -> None:
    with pytest.raises(ValueError, match="return_url"):
        sanitize_return_url(bad_url)


def test_append_linked_query_param_no_existing_query() -> None:
    assert append_linked_query_param("/identities", "rucio-mcp-atlas") == (
        "/identities?linked=rucio-mcp-atlas"
    )


def test_append_linked_query_param_preserves_existing_query() -> None:
    assert append_linked_query_param("/identities?foo=bar", "rucio-mcp-atlas") == (
        "/identities?foo=bar&linked=rucio-mcp-atlas"
    )


# ---------------------------------------------------------------------------
# OAuth21Provider.is_linked
# ---------------------------------------------------------------------------


async def test_is_linked_false_when_missing() -> None:
    provider = _make_provider(InMemoryTokenStore())
    assert await provider.is_linked(_principal()) is False


async def test_is_linked_false_when_expired() -> None:
    store = InMemoryTokenStore()
    await store.write_cas(
        SUBJECT,
        ALIAS,
        _make_cred(expires_at=datetime.now(UTC) - timedelta(seconds=10)),
        expected_version=None,
    )
    provider = _make_provider(store)

    assert await provider.is_linked(_principal()) is False


async def test_is_linked_true_when_future() -> None:
    store = InMemoryTokenStore()
    await store.write_cas(
        SUBJECT,
        ALIAS,
        _make_cred(expires_at=datetime.now(UTC) + timedelta(hours=1)),
        expected_version=None,
    )
    provider = _make_provider(store)

    assert await provider.is_linked(_principal()) is True


# ---------------------------------------------------------------------------
# OAuth21Provider.issue
# ---------------------------------------------------------------------------


async def test_issue_returns_bearer_when_plenty_of_life() -> None:
    store = InMemoryTokenStore()
    await store.write_cas(
        SUBJECT,
        ALIAS,
        _make_cred(expires_at=datetime.now(UTC) + timedelta(hours=1)),
        expected_version=None,
    )
    provider = _make_provider(store)

    issued = await provider.issue(_principal(), ALIAS)

    assert issued.payload["access_token"] == "access-token-1"
    assert issued.kind.value == "bearer"


async def test_issue_refreshes_when_within_window(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = InMemoryTokenStore()
    await store.write_cas(
        SUBJECT,
        ALIAS,
        _make_cred(expires_at=datetime.now(UTC) + timedelta(seconds=60)),
        expected_version=None,
    )
    provider = _make_provider(store)

    fake_client = _FakeTokenClient(
        status_code=200,
        json_body={"access_token": "access-token-2", "expires_in": 3600},
    )
    monkeypatch.setattr(
        "af_mcp_broker.credentials.oauth21.get_http_client", lambda: fake_client
    )

    issued = await provider.issue(_principal(), ALIAS)

    assert issued.payload["access_token"] == "access-token-2"
    assert len(fake_client.calls) == 1
    assert fake_client.calls[0]["data"]["grant_type"] == "refresh_token"
    assert fake_client.calls[0]["data"]["refresh_token"] == "refresh-token-1"

    stored = await store.get(SUBJECT, ALIAS)
    assert stored is not None
    new_cred, new_version = stored
    assert new_version == 2
    assert new_cred.access_token.get_secret_value() == "access-token-2"
    # The fake response omitted refresh_token -- must fall back to the existing one.
    assert new_cred.refresh_token is not None
    assert new_cred.refresh_token.get_secret_value() == "refresh-token-1"


async def test_issue_raises_404_when_missing() -> None:
    provider = _make_provider(InMemoryTokenStore())

    with pytest.raises(HTTPException) as exc_info:
        await provider.issue(_principal(), ALIAS)

    assert exc_info.value.status_code == 404


async def test_issue_raises_401_when_refresh_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = InMemoryTokenStore()
    await store.write_cas(
        SUBJECT,
        ALIAS,
        _make_cred(expires_at=datetime.now(UTC) + timedelta(seconds=10)),
        expected_version=None,
    )
    provider = _make_provider(store)

    fake_client = _FakeTokenClient(
        status_code=400, json_body={"error": "invalid_grant"}
    )
    monkeypatch.setattr(
        "af_mcp_broker.credentials.oauth21.get_http_client", lambda: fake_client
    )

    with pytest.raises(HTTPException) as exc_info:
        await provider.issue(_principal(), ALIAS)

    assert exc_info.value.status_code == 401


async def test_issue_raises_401_when_no_refresh_token() -> None:
    store = InMemoryTokenStore()
    await store.write_cas(
        SUBJECT,
        ALIAS,
        _make_cred(
            refresh_token=None, expires_at=datetime.now(UTC) + timedelta(seconds=10)
        ),
        expected_version=None,
    )
    provider = _make_provider(store)

    with pytest.raises(HTTPException) as exc_info:
        await provider.issue(_principal(), ALIAS)

    assert exc_info.value.status_code == 401


async def test_issue_handles_version_conflict_during_refresh(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Another replica refreshing concurrently must not be clobbered -- the
    caller gets back whichever credential won the race.
    """
    store = InMemoryTokenStore()
    await store.write_cas(
        SUBJECT,
        ALIAS,
        _make_cred(expires_at=datetime.now(UTC) + timedelta(seconds=10)),
        expected_version=None,
    )  # version 1
    provider = _make_provider(store)

    fake_client = _FakeTokenClient(
        status_code=200,
        json_body={"access_token": "our-refresh-token", "expires_in": 3600},
    )
    monkeypatch.setattr(
        "af_mcp_broker.credentials.oauth21.get_http_client", lambda: fake_client
    )

    real_write_cas = store.write_cas
    call_count = 0

    async def _racing_write_cas(
        subject: str,
        alias: str,
        cred: StoredOAuthCredential,
        expected_version: int | None,
    ) -> int:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            # Simulate a concurrent replica winning the race just before our
            # own write lands.
            racer_cred = _make_cred(access_token=SecretStr("winning-racer-token"))
            await real_write_cas(subject, alias, racer_cred, expected_version=1)
        return await real_write_cas(subject, alias, cred, expected_version)

    monkeypatch.setattr(store, "write_cas", _racing_write_cas)

    issued = await provider.issue(_principal(), ALIAS)

    assert issued.payload["access_token"] == "winning-racer-token"


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


def test_authorize_redirects_with_correct_params(
    monkeypatch: pytest.MonkeyPatch, app_client_factory: Any
) -> None:
    fernet_key = Fernet.generate_key().decode()
    _configure_oauth21_env(monkeypatch, fernet_key)

    with app_client_factory() as (client, _state):
        resp = client.get(f"/v1/oauth/authorize/{ALIAS}", follow_redirects=False)

    assert resp.status_code == 302, resp.text
    location = resp.headers["location"]
    assert location.startswith(AUTHORIZATION_ENDPOINT + "?")

    query = parse_qs(urlparse(location).query)
    assert query["client_id"] == [CLIENT_ID]
    assert query["code_challenge_method"] == ["S256"]
    assert query["response_type"] == ["code"]
    assert query["scope"] == ["openid profile"]
    assert "code_challenge" in query

    nonce_cookie = resp.cookies.get(NONCE_COOKIE_NAME)
    assert nonce_cookie is not None

    cipher = Fernet(fernet_key.encode())
    payload = decrypt_state_token(
        cipher, query["state"][0], expected_iss=EXPECTED_STATE_ISSUER
    )
    assert payload.sub == "sub-abc"  # make_principal()'s default subject
    assert payload.alias == ALIAS
    assert payload.nonce == nonce_cookie


def test_authorize_url_uses_public_origin_for_redirect_uri(
    monkeypatch: pytest.MonkeyPatch, app_client_factory: Any
) -> None:
    """The outgoing `redirect_uri` must come from `broker_public_origin`,
    not whichever host the request actually arrived on (Bug 3 — the nonce
    cookie is host-only, so authorize and callback must share an origin).
    """
    fernet_key = Fernet.generate_key().decode()
    _configure_oauth21_env(monkeypatch, fernet_key)

    with app_client_factory() as (client, _state):
        resp = client.get(
            f"/v1/oauth/authorize/{ALIAS}",
            follow_redirects=False,
            # TestClient's default request host is "testserver" -- a
            # request-relative redirect_uri would reflect *this* Host
            # instead, which is exactly the bug being fixed.
            headers={"Host": "attacker-controlled.example"},
        )

    assert resp.status_code == 302, resp.text
    query = parse_qs(urlparse(resp.headers["location"]).query)
    assert query["redirect_uri"] == [f"{PUBLIC_ORIGIN}/v1/oauth/callback/{ALIAS}"]


def test_authorize_returns_json_when_accept_json(
    monkeypatch: pytest.MonkeyPatch, app_client_factory: Any
) -> None:
    fernet_key = Fernet.generate_key().decode()
    _configure_oauth21_env(monkeypatch, fernet_key)

    with app_client_factory() as (client, _state):
        resp = client.get(
            f"/v1/oauth/authorize/{ALIAS}",
            headers={"Accept": "application/json"},
            follow_redirects=False,
        )

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["authorize_url"].startswith(AUTHORIZATION_ENDPOINT + "?")
    query = parse_qs(urlparse(body["authorize_url"]).query)
    assert query["redirect_uri"] == [f"{PUBLIC_ORIGIN}/v1/oauth/callback/{ALIAS}"]
    assert resp.cookies.get(NONCE_COOKIE_NAME) is not None


def test_authorize_returns_302_when_accept_html(
    monkeypatch: pytest.MonkeyPatch, app_client_factory: Any
) -> None:
    fernet_key = Fernet.generate_key().decode()
    _configure_oauth21_env(monkeypatch, fernet_key)

    with app_client_factory() as (client, _state):
        resp = client.get(
            f"/v1/oauth/authorize/{ALIAS}",
            headers={"Accept": "text/html"},
            follow_redirects=False,
        )

    assert resp.status_code == 302, resp.text
    assert resp.headers["location"].startswith(AUTHORIZATION_ENDPOINT + "?")


def test_authorize_returns_302_when_no_accept(
    monkeypatch: pytest.MonkeyPatch, app_client_factory: Any
) -> None:
    fernet_key = Fernet.generate_key().decode()
    _configure_oauth21_env(monkeypatch, fernet_key)

    with app_client_factory() as (client, _state):
        resp = client.get(f"/v1/oauth/authorize/{ALIAS}", follow_redirects=False)

    assert resp.status_code == 302, resp.text
    assert resp.headers["location"].startswith(AUTHORIZATION_ENDPOINT + "?")


def test_authorize_404_for_unknown_alias(
    monkeypatch: pytest.MonkeyPatch, app_client_factory: Any
) -> None:
    fernet_key = Fernet.generate_key().decode()
    _configure_oauth21_env(monkeypatch, fernet_key)

    with app_client_factory() as (client, _state):
        resp = client.get("/v1/oauth/authorize/does-not-exist")

    assert resp.status_code == 404


@pytest.mark.parametrize(
    "bad_return",
    ["https://evil.example/x", "//evil.example", "/a/../b"],
)
def test_authorize_400_for_unsafe_return_url(
    monkeypatch: pytest.MonkeyPatch, app_client_factory: Any, bad_return: str
) -> None:
    fernet_key = Fernet.generate_key().decode()
    _configure_oauth21_env(monkeypatch, fernet_key)

    with app_client_factory() as (client, _state):
        resp = client.get(f"/v1/oauth/authorize/{ALIAS}", params={"return": bad_return})

    assert resp.status_code == 400


def _bootstrap_no_override_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Point the app at the shipped YAML with no keycloak_dependency override."""
    monkeypatch.setenv("POLICY_FILE", str(SHIPPED_POLICY))
    monkeypatch.setenv("BACKENDS_FILE", str(SHIPPED_BACKENDS))
    monkeypatch.setenv("METRICS_PORT", "0")
    monkeypatch.setenv("OIDC_ISSUER", EXPECTED_STATE_ISSUER)


def _fresh_app() -> Any:
    """Clear the cached Settings + any leaked dependency override.

    ``af_mcp_broker.app.app`` is a process-wide singleton (imported once at
    module load), so "fresh" here means "re-read env-derived Settings and
    start from a clean dependency_overrides", not a re-import of the module.
    """
    get_settings.cache_clear()
    broker_app.dependency_overrides.clear()
    return broker_app


def test_authorize_401_without_bearer(monkeypatch: pytest.MonkeyPatch) -> None:
    _bootstrap_no_override_env(monkeypatch)
    fernet_key = Fernet.generate_key().decode()
    _configure_oauth21_env(monkeypatch, fernet_key)

    app = _fresh_app()
    with TestClient(app) as client:
        resp = client.get(f"/v1/oauth/authorize/{ALIAS}")

    assert resp.status_code == 401, resp.text


def test_callback_completes_flow_and_stores_credential(
    monkeypatch: pytest.MonkeyPatch, app_client_factory: Any
) -> None:
    fernet_key = Fernet.generate_key().decode()
    _configure_oauth21_env(monkeypatch, fernet_key)

    fake_token_client = _FakeTokenClient(
        status_code=200,
        json_body={
            "access_token": "linked-access-token",
            "refresh_token": "linked-refresh-token",
            "expires_in": 3600,
            "scope": "openid profile",
        },
    )
    monkeypatch.setattr(
        "af_mcp_broker.api.oauth21.get_http_client", lambda: fake_token_client
    )

    with app_client_factory() as (client, _state):
        authorize_resp = client.get(
            f"/v1/oauth/authorize/{ALIAS}",
            params={"return": "/identities"},
            follow_redirects=False,
        )
        state_token = parse_qs(urlparse(authorize_resp.headers["location"]).query)[
            "state"
        ][0]

        # The route sets the nonce cookie as Secure, which TestClient's plain
        # http:// transport correctly withholds from being resent on the
        # next request — so propagate it into the jar explicitly here, the
        # same way a real browser would resend it automatically over https.
        nonce_cookie = authorize_resp.cookies.get(NONCE_COOKIE_NAME)
        assert nonce_cookie is not None
        client.cookies.set(NONCE_COOKIE_NAME, nonce_cookie, path=NONCE_COOKIE_PATH)

        callback_resp = client.get(
            f"/v1/oauth/callback/{ALIAS}",
            params={"code": "auth-code-xyz", "state": state_token},
            follow_redirects=False,
        )

        assert callback_resp.status_code == 302, callback_resp.text
        assert callback_resp.headers["location"] == f"/identities?linked={ALIAS}"
        # Assert on the Set-Cookie header directly (expiry in the past,
        # value cleared) rather than the TestClient's cookie jar -- a
        # manually-injected jar entry (above) and the real cookie the jar
        # extracted from the authorize response are, confusingly, distinct
        # jar entries (different inferred domains), so jar-based assertions
        # here would test jar bookkeeping, not the route's actual behavior.
        deletion_header = callback_resp.headers["set-cookie"]
        assert f'{NONCE_COOKIE_NAME}=""' in deletion_header
        assert "Max-Age=0" in deletion_header

        assert len(fake_token_client.calls) == 1
        sent = fake_token_client.calls[0]["data"]
        assert sent["grant_type"] == "authorization_code"
        assert sent["code"] == "auth-code-xyz"
        assert sent["client_id"] == CLIENT_ID

        store = broker_app.state.oauth21_token_store
        stored = _run(store.get("sub-abc", ALIAS))
        assert stored is not None
        cred, version = stored
        assert version == 1
        assert cred.access_token.get_secret_value() == "linked-access-token"


def test_callback_400_when_nonce_cookie_missing(
    monkeypatch: pytest.MonkeyPatch, app_client_factory: Any
) -> None:
    fernet_key = Fernet.generate_key().decode()
    _configure_oauth21_env(monkeypatch, fernet_key)

    with app_client_factory() as (client, _state):
        resp = client.get(
            f"/v1/oauth/callback/{ALIAS}",
            params={"code": "x", "state": "irrelevant"},
        )

    assert resp.status_code == 400


def test_callback_400_when_nonce_mismatches_cookie(
    monkeypatch: pytest.MonkeyPatch, app_client_factory: Any
) -> None:
    fernet_key = Fernet.generate_key().decode()
    _configure_oauth21_env(monkeypatch, fernet_key)

    with app_client_factory() as (client, _state):
        authorize_resp = client.get(
            f"/v1/oauth/authorize/{ALIAS}", follow_redirects=False
        )
        state_token = parse_qs(urlparse(authorize_resp.headers["location"]).query)[
            "state"
        ][0]

        client.cookies.set(NONCE_COOKIE_NAME, "not-the-real-nonce")
        resp = client.get(
            f"/v1/oauth/callback/{ALIAS}",
            params={"code": "x", "state": state_token},
        )

    assert resp.status_code == 400


def test_callback_400_when_alias_mismatches_state(
    monkeypatch: pytest.MonkeyPatch, app_client_factory: Any
) -> None:
    fernet_key = Fernet.generate_key().decode()
    _configure_oauth21_env(monkeypatch, fernet_key)
    cipher = Fernet(fernet_key.encode())
    nonce = "fixed-nonce-for-alias-mismatch-test"
    state_token = build_state_token(
        cipher,
        iss=EXPECTED_STATE_ISSUER,
        sub="sub-abc",
        alias="a-different-alias",
        pkce_verifier="verifier",
        return_url="/",
        nonce=nonce,
    )

    with app_client_factory() as (client, _state):
        client.cookies.set(NONCE_COOKIE_NAME, nonce)
        resp = client.get(
            f"/v1/oauth/callback/{ALIAS}",
            params={"code": "x", "state": state_token},
        )

    assert resp.status_code == 400


def test_callback_400_when_state_malformed(
    monkeypatch: pytest.MonkeyPatch, app_client_factory: Any
) -> None:
    fernet_key = Fernet.generate_key().decode()
    _configure_oauth21_env(monkeypatch, fernet_key)

    with app_client_factory() as (client, _state):
        client.cookies.set(NONCE_COOKIE_NAME, "whatever")
        resp = client.get(
            f"/v1/oauth/callback/{ALIAS}",
            params={"code": "x", "state": "not-a-valid-fernet-token"},
        )

    assert resp.status_code == 400


def test_callback_400_when_state_expired(
    monkeypatch: pytest.MonkeyPatch, app_client_factory: Any
) -> None:
    fernet_key = Fernet.generate_key().decode()
    _configure_oauth21_env(monkeypatch, fernet_key)
    cipher = Fernet(fernet_key.encode())
    now = int(time.time())
    nonce = "fixed-nonce-for-expired-test"
    payload = {
        "iss": EXPECTED_STATE_ISSUER,
        "aud": EXPECTED_STATE_ISSUER,
        "sub": "sub-abc",
        "alias": ALIAS,
        "pkce_verifier": "v",
        "return_url": "/",
        "nonce": nonce,
        "iat": now - 400,
        "exp": now - 100,
    }
    state_token = cipher.encrypt_at_time(
        json.dumps(payload).encode(), now - 400
    ).decode()

    with app_client_factory() as (client, _state):
        client.cookies.set(NONCE_COOKIE_NAME, nonce)
        resp = client.get(
            f"/v1/oauth/callback/{ALIAS}",
            params={"code": "x", "state": state_token},
        )

    assert resp.status_code == 400


def test_config_raises_when_state_key_missing_but_providers_configured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Startup validation (config.py `_validate_oauth21_config`), exercised
    through a full app boot so the failure surfaces at the same point a real
    misconfigured deployment would hit it.
    """
    _bootstrap_no_override_env(monkeypatch)
    monkeypatch.setenv("OAUTH21_CLIENT_ID", CLIENT_ID)
    monkeypatch.setenv(
        "IDENTITY_PROVIDERS",
        json.dumps(
            [
                {
                    "type": "oauth21-direct",
                    "alias": ALIAS,
                    "targets": [ALIAS],
                    "authorization_endpoint": AUTHORIZATION_ENDPOINT,
                    "token_endpoint": TOKEN_ENDPOINT,
                    "issuer": PROVIDER_ISSUER,
                }
            ]
        ),
    )
    # BROKER_STATE_KEY intentionally left unset.

    app = _fresh_app()
    with pytest.raises(ValueError, match="broker_state_key"), TestClient(app):
        pass
