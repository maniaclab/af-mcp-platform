"""Integration tests for the area ``test_oauth21.py`` covers; the unit tests live in ``unit/test_oauth21.py``."""

from __future__ import annotations

import asyncio
import json
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

import pytest
from conftest import TEST_SERVICES
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from oauth21_support import (  # noqa: F401
    ALIAS,
    AUTHORIZATION_ENDPOINT,
    CLIENT_ID,
    CONFIDENTIAL_CLIENT_ID,
    CONFIDENTIAL_CLIENT_SECRET,
    EXPECTED_STATE_ISSUER,
    PROVIDER_ISSUER,
    SUBJECT,
    TOKEN_ENDPOINT,
    _FakeTokenClient,
    _make_cred,
    x509_service_env_fixture,
)

from af_mcp_broker.api import oauth21 as oauth21_module
from af_mcp_broker.api.auth import keycloak_dependency
from af_mcp_broker.app import app as broker_app
from af_mcp_broker.config import get_settings
from af_mcp_broker.oauth_state import (
    NONCE_COOKIE_NAME,
    NONCE_COOKIE_PATH,
    build_state_token,
    decrypt_state_token,
)

_SRC = Path(__file__).resolve().parents[2] / "src" / "af_mcp_broker"
SHIPPED_POLICY = _SRC / "authorization" / "policy.yaml"

# The canonical origin every outgoing OAuth 2.1 redirect_uri is built from
# (see api/oauth21.py's `_callback_url`) — deliberately different from
# TestClient's default request host ("testserver") so a test asserting on
# this value actually proves the redirect_uri is public-origin-derived
# rather than request-relative.
PUBLIC_ORIGIN = "https://mcp-portal.example"


def _run(coro: Any) -> Any:
    """Run a coroutine to completion from a sync test body.

    ``InMemoryTokenStore.get`` takes no lock, so running it on a fresh loop
    here (separate from the TestClient's own request-handling loop) is safe.
    """
    return asyncio.run(coro)


def _configure_oauth21_env(
    monkeypatch: pytest.MonkeyPatch,
    fernet_key: str,
    provider_overrides: dict[str, Any] | None = None,
) -> None:
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
                    **(provider_overrides or {}),
                },
                # This override replaces conftest's default entirely (or,
                # for tests that boot the app directly via _fresh_app, is
                # the only IDENTITY_PROVIDERS source at all) -- either way,
                # the shipped services.yaml's "ami" (auth_type: x509) still
                # needs an explicit entry or the broker refuses to start.
                {
                    "type": "x509",
                    "voms": "atlas",
                    "service_url": "http://voms-token-service.invalid:8000",
                    "alias": "x509",
                    "targets": ["ami"],
                },
            ]
        ),
    )


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


@pytest.mark.parametrize(
    "headers",
    [
        pytest.param({"Accept": "text/html"}, id="accept_html"),
        pytest.param({}, id="no_accept"),
    ],
)
def test_authorize_returns_302(
    monkeypatch: pytest.MonkeyPatch,
    app_client_factory: Any,
    headers: dict[str, str],
) -> None:
    fernet_key = Fernet.generate_key().decode()
    _configure_oauth21_env(monkeypatch, fernet_key)

    with app_client_factory() as (client, _state):
        resp = client.get(
            f"/v1/oauth/authorize/{ALIAS}", headers=headers, follow_redirects=False
        )

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
    assert resp.json()["detail"] == (
        "Unknown OAuth 2.1 provider alias 'does-not-exist'"
    )


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
    assert resp.json()["detail"].startswith("return_url must ")
    assert repr(bad_return) in resp.json()["detail"]


def _bootstrap_no_override_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Point the app at the shipped YAML with no keycloak_dependency override."""
    monkeypatch.setenv("POLICY_FILE", str(SHIPPED_POLICY))
    monkeypatch.setenv("SERVICES_FILE", str(TEST_SERVICES))
    monkeypatch.setenv("METRICS_PORT", "0")
    monkeypatch.setenv("OIDC_ISSUER", EXPECTED_STATE_ISSUER)
    # Issue #144 step 3: the broker refuses to start without a configured
    # Keycloak admin service account (dev bypass aside) -- these tests boot
    # the real app with no dependency override, so it must actually start.
    monkeypatch.setenv("KEYCLOAK_ADMIN_CLIENT_ID", "test-admin-client")
    monkeypatch.setenv("KEYCLOAK_ADMIN_CLIENT_SECRET", "test-admin-secret")


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
    assert resp.json()["detail"] == "Not authenticated"


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
        "af_mcp_broker.app.build_http_client", lambda _stack: fake_token_client
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

        store = broker_app.state.broker.oauth21_token_store
        stored = _run(store.get("sub-abc", ALIAS))
        assert stored is not None
        cred, version = stored
        assert version == 1
        assert cred.access_token.get_secret_value() == "linked-access-token"


def test_callback_notifies_listing_caches_for_the_linking_subject(
    monkeypatch: pytest.MonkeyPatch, app_client_factory: Any
) -> None:
    fernet_key = Fernet.generate_key().decode()
    _configure_oauth21_env(monkeypatch, fernet_key)
    fake_token_client = _FakeTokenClient(
        status_code=200,
        json_body={"access_token": "linked-access-token", "expires_in": 3600},
    )
    monkeypatch.setattr(
        "af_mcp_broker.app.build_http_client", lambda _stack: fake_token_client
    )

    with app_client_factory() as (client, _state):
        linked: list[tuple[str, str]] = []
        client.app.state.broker.credential_cache._on_link = lambda subject, target: (
            linked.append((subject, target))
        )
        authorize_resp = client.get(
            f"/v1/oauth/authorize/{ALIAS}", follow_redirects=False
        )
        state_token = parse_qs(urlparse(authorize_resp.headers["location"]).query)[
            "state"
        ][0]
        nonce_cookie = authorize_resp.cookies.get(NONCE_COOKIE_NAME)
        assert nonce_cookie is not None
        client.cookies.set(NONCE_COOKIE_NAME, nonce_cookie, path=NONCE_COOKIE_PATH)

        resp = client.get(
            f"/v1/oauth/callback/{ALIAS}",
            params={"code": "auth-code-xyz", "state": state_token},
            follow_redirects=False,
        )

    assert resp.status_code == 302, resp.text
    assert linked == [("sub-abc", ALIAS)]


def test_callback_backend_error_does_not_notify_listing_caches(
    monkeypatch: pytest.MonkeyPatch, app_client_factory: Any
) -> None:
    fernet_key = Fernet.generate_key().decode()
    _configure_oauth21_env(monkeypatch, fernet_key)

    with app_client_factory() as (client, _state):
        linked: list[tuple[str, str]] = []
        client.app.state.broker.credential_cache._on_link = lambda subject, target: (
            linked.append((subject, target))
        )
        authorize_resp = client.get(
            f"/v1/oauth/authorize/{ALIAS}", follow_redirects=False
        )
        state_token = parse_qs(urlparse(authorize_resp.headers["location"]).query)[
            "state"
        ][0]
        nonce_cookie = authorize_resp.cookies.get(NONCE_COOKIE_NAME)
        assert nonce_cookie is not None
        client.cookies.set(NONCE_COOKIE_NAME, nonce_cookie, path=NONCE_COOKIE_PATH)

        resp = client.get(
            f"/v1/oauth/callback/{ALIAS}",
            params={"error": "access_denied", "state": state_token},
            follow_redirects=False,
        )

    assert resp.status_code == 302, resp.text
    assert linked == []


def test_callback_never_calls_keycloak_dependency(
    monkeypatch: pytest.MonkeyPatch, app_client_factory: Any
) -> None:
    """Regression: the callback is a browser redirect back from the backend
    AS, which can never carry the user's Keycloak bearer token (see the
    route's own docstring), so it must never be wired behind a dependency
    that itself requires one -- as api/router.py's maintenance-gated
    oauth21.router inclusion did since b98af52, 401ing every link attempt
    with "Not authenticated" before the handler ran.

    Every other callback test here runs through app_client_factory's blanket
    keycloak_dependency override, which masks exactly that. This test keeps
    the override for /authorize (which legitimately requires the user's
    Keycloak identity) and removes it for the callback, so a credential-less
    request is what drives the callback's response.
    """
    fernet_key = Fernet.generate_key().decode()
    _configure_oauth21_env(monkeypatch, fernet_key)
    fake_token_client = _FakeTokenClient(
        status_code=200,
        json_body={"access_token": "linked-access-token", "expires_in": 3600},
    )
    monkeypatch.setattr(
        "af_mcp_broker.app.build_http_client", lambda _stack: fake_token_client
    )

    with app_client_factory() as (client, _state):
        authorize_resp = client.get(
            f"/v1/oauth/authorize/{ALIAS}", follow_redirects=False
        )
        state_token = parse_qs(urlparse(authorize_resp.headers["location"]).query)[
            "state"
        ][0]
        # See test_callback_completes_flow_and_stores_credential for why the
        # Secure nonce cookie is propagated into the jar by hand.
        nonce_cookie = authorize_resp.cookies.get(NONCE_COOKIE_NAME)
        assert nonce_cookie is not None
        client.cookies.set(NONCE_COOKIE_NAME, nonce_cookie, path=NONCE_COOKIE_PATH)

        client.app.dependency_overrides.pop(keycloak_dependency, None)
        callback_resp = client.get(
            f"/v1/oauth/callback/{ALIAS}",
            params={"code": "auth-code-xyz", "state": state_token},
            follow_redirects=False,
        )

    assert callback_resp.status_code == 302, callback_resp.text
    assert callback_resp.headers["location"] == f"/?linked={ALIAS}"
    assert len(fake_token_client.calls) == 1


def _configure_confidential_oauth21_env(
    monkeypatch: pytest.MonkeyPatch, fernet_key: str
) -> None:
    """Same provider, registered as a confidential client with its own id."""
    _configure_oauth21_env(
        monkeypatch,
        fernet_key,
        provider_overrides={"client_id": CONFIDENTIAL_CLIENT_ID, "confidential": True},
    )
    # ALIAS "rucio-mcp-atlas" -> uppercased, "-" -> "_".
    monkeypatch.setenv(
        "OAUTH21_CLIENT_SECRET_RUCIO_MCP_ATLAS", CONFIDENTIAL_CLIENT_SECRET
    )


def _link_through_callback(client: Any) -> Any:
    """Drive authorize -> callback in one TestClient; return the callback response."""
    authorize_resp = client.get(f"/v1/oauth/authorize/{ALIAS}", follow_redirects=False)
    state_token = parse_qs(urlparse(authorize_resp.headers["location"]).query)["state"][
        0
    ]
    # See test_callback_completes_flow_and_stores_credential for why the
    # Secure nonce cookie is propagated into the jar by hand.
    nonce_cookie = authorize_resp.cookies.get(NONCE_COOKIE_NAME)
    assert nonce_cookie is not None
    client.cookies.set(NONCE_COOKIE_NAME, nonce_cookie, path=NONCE_COOKIE_PATH)
    return client.get(
        f"/v1/oauth/callback/{ALIAS}",
        params={"code": "auth-code-xyz", "state": state_token},
        follow_redirects=False,
    )


def test_authorize_uses_provider_own_client_id(
    monkeypatch: pytest.MonkeyPatch, app_client_factory: Any
) -> None:
    fernet_key = Fernet.generate_key().decode()
    _configure_confidential_oauth21_env(monkeypatch, fernet_key)

    with app_client_factory() as (client, _state):
        resp = client.get(f"/v1/oauth/authorize/{ALIAS}", follow_redirects=False)

    assert resp.status_code == 302, resp.text
    query = parse_qs(urlparse(resp.headers["location"]).query)
    assert query["client_id"] == [CONFIDENTIAL_CLIENT_ID]
    # The secret only ever travels on the back channel.
    assert "client_secret" not in query
    # PKCE is still sent: harmless for an AS that ignores it, and required by
    # OAuth 2.1 for one that doesn't.
    assert query["code_challenge_method"] == ["S256"]


def test_callback_sends_client_secret_post_when_confidential(
    monkeypatch: pytest.MonkeyPatch, app_client_factory: Any
) -> None:
    fernet_key = Fernet.generate_key().decode()
    _configure_confidential_oauth21_env(monkeypatch, fernet_key)

    # No refresh_token, the shape JupyterHub's token endpoint returns.
    fake_token_client = _FakeTokenClient(
        status_code=200,
        json_body={
            "access_token": "linked-access-token",
            "token_type": "Bearer",
            "expires_in": 1209600,
        },
    )
    monkeypatch.setattr(
        "af_mcp_broker.app.build_http_client", lambda _stack: fake_token_client
    )

    with app_client_factory() as (client, _state):
        callback_resp = _link_through_callback(client)

        assert callback_resp.status_code == 302, callback_resp.text
        assert len(fake_token_client.calls) == 1
        sent = fake_token_client.calls[0]["data"]
        assert sent["grant_type"] == "authorization_code"
        assert sent["client_id"] == CONFIDENTIAL_CLIENT_ID
        assert sent["client_secret"] == CONFIDENTIAL_CLIENT_SECRET

        store = broker_app.state.broker.oauth21_token_store
        stored = _run(store.get("sub-abc", ALIAS))
        assert stored is not None
        cred, _version = stored
        assert cred.refresh_token is None


def test_callback_omits_client_secret_when_public(
    monkeypatch: pytest.MonkeyPatch, app_client_factory: Any
) -> None:
    fernet_key = Fernet.generate_key().decode()
    _configure_oauth21_env(monkeypatch, fernet_key)

    fake_token_client = _FakeTokenClient(
        status_code=200,
        json_body={"access_token": "linked-access-token", "expires_in": 3600},
    )
    monkeypatch.setattr(
        "af_mcp_broker.app.build_http_client", lambda _stack: fake_token_client
    )

    with app_client_factory() as (client, _state):
        callback_resp = _link_through_callback(client)

    assert callback_resp.status_code == 302, callback_resp.text
    sent = fake_token_client.calls[0]["data"]
    assert sent["client_id"] == CLIENT_ID
    assert "client_secret" not in sent


def test_callback_relink_clears_a_rejected_credential(
    monkeypatch: pytest.MonkeyPatch, app_client_factory: Any
) -> None:
    """Re-linking is the user's way out of a rejected credential (issue #344):
    the freshly exchanged token replaces it, no longer rejected."""
    fernet_key = Fernet.generate_key().decode()
    _configure_oauth21_env(monkeypatch, fernet_key)

    fake_token_client = _FakeTokenClient(
        status_code=200, json_body={"access_token": "relinked-access-token"}
    )
    monkeypatch.setattr(
        "af_mcp_broker.app.build_http_client", lambda _stack: fake_token_client
    )

    with app_client_factory() as (client, _state):
        store = broker_app.state.broker.oauth21_token_store
        _run(
            store.write_cas(
                "sub-abc",
                ALIAS,
                _make_cred(subject="sub-abc", rejected_at=datetime.now(UTC)),
                expected_version=None,
            )
        )

        callback_resp = _link_through_callback(client)

        assert callback_resp.status_code == 302, callback_resp.text
        stored = _run(store.get("sub-abc", ALIAS))
        assert stored is not None
        cred, _version = stored
        assert cred.access_token.get_secret_value() == "relinked-access-token"
        assert cred.rejected_at is None


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
    assert resp.json()["detail"] == "Missing OAuth state nonce cookie"


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
    assert resp.json()["detail"] == "OAuth state nonce does not match cookie"


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
    assert resp.json()["detail"] == "OAuth state alias does not match callback URL"


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
    assert resp.json()["detail"] == "state token is invalid or expired"


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
    assert resp.json()["detail"] == "state token is invalid or expired"


def test_callback_returns_400_when_neither_code_nor_error(
    monkeypatch: pytest.MonkeyPatch, app_client_factory: Any
) -> None:
    fernet_key = Fernet.generate_key().decode()
    _configure_oauth21_env(monkeypatch, fernet_key)

    with app_client_factory() as (client, _state):
        resp = client.get(f"/v1/oauth/callback/{ALIAS}", params={"state": "irrelevant"})

    assert resp.status_code == 400
    assert "code or error" in resp.text


def test_callback_redirects_to_return_url_with_error_params(
    monkeypatch: pytest.MonkeyPatch, app_client_factory: Any
) -> None:
    fernet_key = Fernet.generate_key().decode()
    _configure_oauth21_env(monkeypatch, fernet_key)

    with app_client_factory() as (client, _state):
        authorize_resp = client.get(
            f"/v1/oauth/authorize/{ALIAS}",
            params={"return": "/identities"},
            follow_redirects=False,
        )
        state_token = parse_qs(urlparse(authorize_resp.headers["location"]).query)[
            "state"
        ][0]
        nonce_cookie = authorize_resp.cookies.get(NONCE_COOKIE_NAME)
        assert nonce_cookie is not None
        client.cookies.set(NONCE_COOKIE_NAME, nonce_cookie, path=NONCE_COOKIE_PATH)

        callback_resp = client.get(
            f"/v1/oauth/callback/{ALIAS}",
            params={
                "state": state_token,
                "error": "server_error",
                "error_description": "An unexpected error occurred",
            },
            follow_redirects=False,
        )

    assert callback_resp.status_code == 302, callback_resp.text
    location = callback_resp.headers["location"]
    parsed_path = urlparse(location).path
    query = parse_qs(urlparse(location).query)
    assert parsed_path == "/identities"
    assert query["linked_error_alias"] == [ALIAS]
    assert query["linked_error"] == ["server_error"]
    assert query["linked_error_description"] == ["An unexpected error occurred"]
    # Nonce cookie must be cleared on the error path too, same as success.
    deletion_header = callback_resp.headers["set-cookie"]
    assert f'{NONCE_COOKIE_NAME}=""' in deletion_header
    assert "Max-Age=0" in deletion_header


def test_callback_logs_error_at_warn(
    monkeypatch: pytest.MonkeyPatch, app_client_factory: Any
) -> None:
    fernet_key = Fernet.generate_key().decode()
    _configure_oauth21_env(monkeypatch, fernet_key)

    events: list[tuple[str, dict[str, Any]]] = []
    original_warning = oauth21_module.log.warning

    def _capture(event: str, **kwargs: Any) -> Any:
        events.append((event, kwargs))
        return original_warning(event, **kwargs)

    monkeypatch.setattr(oauth21_module.log, "warning", _capture)

    with app_client_factory() as (client, _state):
        authorize_resp = client.get(
            f"/v1/oauth/authorize/{ALIAS}", follow_redirects=False
        )
        state_token = parse_qs(urlparse(authorize_resp.headers["location"]).query)[
            "state"
        ][0]
        nonce_cookie = authorize_resp.cookies.get(NONCE_COOKIE_NAME)
        assert nonce_cookie is not None
        client.cookies.set(NONCE_COOKIE_NAME, nonce_cookie, path=NONCE_COOKIE_PATH)

        client.get(
            f"/v1/oauth/callback/{ALIAS}",
            params={
                "state": state_token,
                "error": "server_error",
                "error_description": "An unexpected error occurred",
            },
            follow_redirects=False,
        )

    assert len(events) == 1
    event, kwargs = events[0]
    assert event == "oauth21.callback.backend_error"
    assert kwargs["alias"] == ALIAS
    assert kwargs["subject"] == "sub-abc"
    assert kwargs["error"] == "server_error"
    assert kwargs["error_description"] == "An unexpected error occurred"


def test_callback_state_still_validated_on_error_path(
    monkeypatch: pytest.MonkeyPatch, app_client_factory: Any
) -> None:
    """A malformed/expired state must still 400 on the error path -- state
    validation runs before any branching on code vs error.
    """
    fernet_key = Fernet.generate_key().decode()
    _configure_oauth21_env(monkeypatch, fernet_key)

    with app_client_factory() as (client, _state):
        client.cookies.set(NONCE_COOKIE_NAME, "whatever")
        resp = client.get(
            f"/v1/oauth/callback/{ALIAS}",
            params={"state": "not-a-valid-fernet-token", "error": "server_error"},
        )

    assert resp.status_code == 400
    assert resp.json()["detail"] == "state token is invalid or expired"


def test_callback_missing_state_cookie_on_error_path(
    monkeypatch: pytest.MonkeyPatch, app_client_factory: Any
) -> None:
    fernet_key = Fernet.generate_key().decode()
    _configure_oauth21_env(monkeypatch, fernet_key)

    with app_client_factory() as (client, _state):
        resp = client.get(
            f"/v1/oauth/callback/{ALIAS}",
            params={"state": "irrelevant", "error": "server_error"},
        )

    assert resp.status_code == 400
    assert resp.json()["detail"] == "Missing OAuth state nonce cookie"


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
