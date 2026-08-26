"""Tests for MCP OAuth discovery + PAT bootstrap (issue #140).

Covers the ground rules laid out for this issue:

* both protected-resource metadata paths return valid metadata naming the
  broker as the authorization server
* the authorization-server metadata advertises CIMD support
* an unauthenticated /mcp request returns 401 carrying a WWW-Authenticate
  whose resource_metadata pointer actually resolves
* a full authorize -> Keycloak callback -> token round trip yields a working
  PAT that then authenticates against /mcp
* that PAT appears in GET /v1/tokens with a sensible name
* a PAT from bootstrap is still rejected on /v1
* PKCE and state are validated (a tampered or replayed state is rejected)
* the callback enforces the `mcp-gateway` audience gate (issue #245): the
  login exchange's access token must verify against the broker's
  resource-server audience, or the flow ends in `access_denied` with no PAT
  minted and no auth code stored -- fail-closed when the access token is
  missing, garbage, expired, or lacks the audience
"""

from __future__ import annotations

import json
import time
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qs, urlparse

import httpx
from cryptography.fernet import Fernet

from af_mcp_broker.api.mcp_oauth import (
    _keycloak_authorization_endpoint,
    _keycloak_token_endpoint,
)
from af_mcp_broker.config import Settings
from af_mcp_broker.mcp_auth_codes import McpAuthCodeRecord, McpAuthCodeStore
from af_mcp_broker.oauth_state import build_mcp_authorize_state, generate_pkce_pair

if TYPE_CHECKING:
    from collections.abc import Callable

    import pytest

    from tests.conftest import RsaKey

ISSUER = "https://keycloak.test/realms/connect"
JWKS_URI = "https://keycloak.test/realms/connect/protocol/openid-connect/certs"
BROKER_ORIGIN = "https://mcp.af.example.org"
LOGIN_CLIENT_ID = "mcp-login-client"
LOGIN_CLIENT_SECRET = "mcp-login-secret"
MCP_CLIENT_ID = "https://93.184.216.34/.well-known/oauth-client"
MCP_REDIRECT_URI = "http://localhost:54321/callback"
# Settings.oidc_audience's default -- the resource-server audience the
# bootstrap callback verifies the login exchange's access token against
# (issue #245), same as conftest's AUDIENCE.
GATEWAY_AUDIENCE = "mcp-gateway"


class _FakeMcpOAuthHttpClient:
    """Fake httpx client serving the MCP client's CIMD document and Keycloak's token endpoint, for monkeypatching ``af_mcp_broker.api.mcp_oauth.get_http_client``."""

    def __init__(
        self,
        cimd_doc: dict[str, Any],
        id_token: str,
        access_token: str | None = None,
    ) -> None:
        self.cimd_doc = cimd_doc
        self.id_token = id_token
        # None simulates a Keycloak response with no access_token at all --
        # the key is omitted from the token-endpoint response entirely.
        self.access_token = access_token
        self.token_calls: list[dict[str, Any]] = []
        self.token_status_code = 200

    async def get(self, url: str, **_: Any) -> httpx.Response:
        return httpx.Response(
            200, json=self.cimd_doc, request=httpx.Request("GET", url)
        )

    async def post(self, url: str, data: dict[str, Any], **_: Any) -> httpx.Response:
        self.token_calls.append({"url": url, "data": data})
        body: dict[str, Any] = {"id_token": self.id_token}
        if self.access_token is not None:
            body["access_token"] = self.access_token
        return httpx.Response(
            self.token_status_code,
            json=body,
            request=httpx.Request("POST", url),
        )


def _configure_env(monkeypatch: pytest.MonkeyPatch, fernet_key: str) -> None:
    monkeypatch.setenv("OIDC_ISSUER", ISSUER)
    monkeypatch.setenv("BROKER_STATE_KEY", fernet_key)
    monkeypatch.setenv("BROKER_PUBLIC_ORIGIN", BROKER_ORIGIN)
    monkeypatch.setenv("TOKEN_MINT_CLIENT_ID", LOGIN_CLIENT_ID)
    monkeypatch.setenv("TOKEN_MINT_CLIENT_SECRET", LOGIN_CLIENT_SECRET)


def _cimd_doc() -> dict[str, Any]:
    return {
        "client_id": MCP_CLIENT_ID,
        "redirect_uris": [MCP_REDIRECT_URI],
        "client_name": "Test MCP Client",
    }


# ---------------------------------------------------------------------------
# Discovery metadata
# ---------------------------------------------------------------------------


def test_protected_resource_metadata_root_names_broker_as_as(
    monkeypatch: pytest.MonkeyPatch, app_client_factory: Callable[..., Any]
) -> None:
    monkeypatch.setenv("BROKER_PUBLIC_ORIGIN", BROKER_ORIGIN)

    with app_client_factory() as (client, _):
        resp: Any = client.get("/.well-known/oauth-protected-resource")

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["resource"] == f"{BROKER_ORIGIN}/mcp"
    assert body["authorization_servers"] == [BROKER_ORIGIN]


def test_protected_resource_metadata_mcp_suffixed_matches_root(
    monkeypatch: pytest.MonkeyPatch, app_client_factory: Callable[..., Any]
) -> None:
    monkeypatch.setenv("BROKER_PUBLIC_ORIGIN", BROKER_ORIGIN)

    with app_client_factory() as (client, _):
        root: Any = client.get("/.well-known/oauth-protected-resource")
        suffixed: Any = client.get("/.well-known/oauth-protected-resource/mcp")

    assert suffixed.status_code == 200, suffixed.text
    assert suffixed.json() == root.json()


def test_protected_resource_metadata_503_when_unconfigured(
    app_client_factory: Callable[..., Any],
) -> None:
    with app_client_factory() as (client, _):
        resp: Any = client.get("/.well-known/oauth-protected-resource")

    assert resp.status_code == 503


def test_authorization_server_metadata_advertises_cimd(
    monkeypatch: pytest.MonkeyPatch, app_client_factory: Callable[..., Any]
) -> None:
    monkeypatch.setenv("BROKER_PUBLIC_ORIGIN", BROKER_ORIGIN)

    with app_client_factory() as (client, _):
        resp: Any = client.get("/.well-known/oauth-authorization-server")

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["issuer"] == BROKER_ORIGIN
    assert body["authorization_endpoint"] == f"{BROKER_ORIGIN}/v1/oauth/authorize"
    assert body["token_endpoint"] == f"{BROKER_ORIGIN}/v1/oauth/token"
    assert body["client_id_metadata_document_supported"] is True
    assert "S256" in body["code_challenge_methods_supported"]


def test_mcp_401_carries_resolvable_resource_metadata(
    monkeypatch: pytest.MonkeyPatch, app_client_factory: Callable[..., Any]
) -> None:
    monkeypatch.setenv("BROKER_PUBLIC_ORIGIN", BROKER_ORIGIN)

    with app_client_factory() as (client, _):
        resp: Any = client.post(
            "/mcp/",
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "t", "version": "0"},
                },
            },
            headers={
                "Accept": "application/json, text/event-stream",
                "Content-Type": "application/json",
            },
        )
        assert resp.status_code == 401, resp.text
        www_auth = resp.headers["www-authenticate"]
        assert "resource_metadata=" in www_auth
        metadata_url = www_auth.split("resource_metadata=", 1)[1].strip('"')
        assert (
            metadata_url == f"{BROKER_ORIGIN}/.well-known/oauth-protected-resource/mcp"
        )

        metadata_resp: Any = client.get(urlparse(metadata_url).path)

    assert metadata_resp.status_code == 200, metadata_resp.text
    assert metadata_resp.json()["resource"] == f"{BROKER_ORIGIN}/mcp"


# ---------------------------------------------------------------------------
# Full authorize -> Keycloak callback -> token round trip
# ---------------------------------------------------------------------------


def test_full_bootstrap_round_trip_yields_working_pat(
    monkeypatch: pytest.MonkeyPatch,
    app_client_factory: Callable[..., Any],
    sig_key: RsaKey,
    prime_jwks: Callable[[list[dict[str, Any]]], None],
    static_principal_cache: tuple[Any, Any],
    make_principal: Callable[..., Any],
) -> None:
    fernet_key = Fernet.generate_key().decode()
    _configure_env(monkeypatch, fernet_key)
    prime_jwks([sig_key.jwk])

    principal_sub = "kc-sub-abc123"
    now = int(time.time())
    id_token = sig_key.sign(
        {
            "sub": principal_sub,
            "iss": ISSUER,
            "aud": LOGIN_CLIENT_ID,
            "iat": now,
            "exp": now + 300,
        }
    )
    # An entitled user's access token: Keycloak stamped the broker's
    # resource-server audience on it (issue #245's gate lets this through).
    access_token = sig_key.sign(
        {
            "sub": principal_sub,
            "iss": ISSUER,
            "aud": GATEWAY_AUDIENCE,
            "iat": now,
            "exp": now + 300,
        }
    )
    fake_client = _FakeMcpOAuthHttpClient(
        _cimd_doc(), id_token, access_token=access_token
    )
    monkeypatch.setattr(
        "af_mcp_broker.api.mcp_oauth.get_http_client", lambda: fake_client
    )

    mcp_verifier, mcp_challenge = generate_pkce_pair()

    with app_client_factory() as (client, state):
        # AsgiAuthMiddleware resolves a PAT's authority via IdentityMiddleware's
        # own principal_cache handle (see mcp/aggregator.py's populate_aggregator/
        # _find_middleware), not request.app.state -- swap in a directory-backed
        # cache that needs no real Keycloak, same seam
        # test_mcp_middleware_identity.py's own PAT tests use.
        from af_mcp_broker.app import _mcp_aggregator
        from af_mcp_broker.mcp.aggregator import _find_middleware

        identity_mw, _, _ = _find_middleware(_mcp_aggregator)
        identity_mw.principal_cache = static_principal_cache[0]

        authorize_resp: Any = client.get(
            "/v1/oauth/authorize",
            params={
                "response_type": "code",
                "client_id": MCP_CLIENT_ID,
                "redirect_uri": MCP_REDIRECT_URI,
                "state": "client-state-1",
                "code_challenge": mcp_challenge,
                "code_challenge_method": "S256",
            },
            follow_redirects=False,
        )
        assert authorize_resp.status_code == 302, authorize_resp.text
        kc_location = authorize_resp.headers["location"]
        assert kc_location.startswith(f"{ISSUER}/protocol/openid-connect/auth?")
        kc_query = parse_qs(urlparse(kc_location).query)
        assert kc_query["client_id"] == [LOGIN_CLIENT_ID]
        # The login leg asks Keycloak for the broker audience explicitly --
        # redundant while the scope is attached as Default on the login
        # client, but load-bearing if that's ever flipped to Optional.
        assert kc_query["scope"] == [f"openid {GATEWAY_AUDIENCE}"]
        broker_state = kc_query["state"][0]

        # TestClient's cookie jar won't carry a `Secure` cookie back over
        # the plain-http testserver, so extract and re-set it explicitly --
        # same workaround test_oauth21.py's own callback tests already use
        # for the sibling NONCE_COOKIE_NAME cookie.
        nonce_cookie = authorize_resp.cookies.get("mcp_oauth_state_nonce")
        assert nonce_cookie is not None
        client.cookies.set(
            "mcp_oauth_state_nonce",
            nonce_cookie,
            path="/v1/oauth/keycloak-login/callback",
        )

        callback_resp: Any = client.get(
            "/v1/oauth/keycloak-login/callback",
            params={"code": "keycloak-auth-code-1", "state": broker_state},
            follow_redirects=False,
        )
        assert callback_resp.status_code == 302, callback_resp.text
        mcp_location = callback_resp.headers["location"]
        assert mcp_location.startswith(f"{MCP_REDIRECT_URI}?")
        mcp_query = parse_qs(urlparse(mcp_location).query)
        assert mcp_query["state"] == ["client-state-1"]
        mcp_code = mcp_query["code"][0]

        # Keycloak's token endpoint was actually called, with the broker's
        # own PKCE verifier and confidential-client secret.
        assert len(fake_client.token_calls) == 1
        sent = fake_client.token_calls[0]["data"]
        assert sent["client_id"] == LOGIN_CLIENT_ID
        assert sent["client_secret"] == LOGIN_CLIENT_SECRET
        assert sent["code"] == "keycloak-auth-code-1"

        token_resp: Any = client.post(
            "/v1/oauth/token",
            data={
                "grant_type": "authorization_code",
                "code": mcp_code,
                "redirect_uri": MCP_REDIRECT_URI,
                "client_id": MCP_CLIENT_ID,
                "code_verifier": mcp_verifier,
            },
        )
        assert token_resp.status_code == 200, token_resp.text
        token_body = token_resp.json()
        assert token_body["token_type"] == "Bearer"
        pat = token_body["access_token"]
        assert pat.startswith("mcp_pat_")

        # The PAT authenticates against /mcp (no 401 for a missing/invalid
        # bearer this time -- AsgiAuthMiddleware recognizes the mcp_pat_
        # prefix and resolves it via the PAT store + principal cache).
        mcp_resp: Any = client.post(
            "/mcp/",
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "t", "version": "0"},
                },
            },
            headers={
                "Accept": "application/json, text/event-stream",
                "Content-Type": "application/json",
                "Authorization": f"Bearer {pat}",
            },
        )
        assert mcp_resp.status_code != 401, mcp_resp.text

        # The PAT appears in GET /v1/tokens (still gated by the fixture's
        # keycloak_dependency override -- this checks the *listing*, not the
        # bearer used to reach it) with a sensible name derived from the
        # MCP client's CIMD client_name. The override always answers with
        # state["principal"], so point it at the bootstrap principal to list
        # *their* tokens rather than the fixture's unrelated default.
        state["principal"] = make_principal(subject=principal_sub)
        listing: Any = client.get("/v1/tokens")
        assert listing.status_code == 200, listing.text
        names = [row["name"] for row in listing.json()]
        assert "Test MCP Client" in names

        # A PAT minted via bootstrap must still be rejected on /v1 --
        # restore real keycloak_dependency validation for this one check
        # (the fixture otherwise overrides it to always succeed).
        from af_mcp_broker.app import app
        from af_mcp_broker.identity import keycloak_dependency

        app.dependency_overrides.pop(keycloak_dependency, None)
        v1_resp: Any = client.get(
            "/v1/tokens", headers={"Authorization": f"Bearer {pat}"}
        )
        assert v1_resp.status_code == 401, v1_resp.text


# ---------------------------------------------------------------------------
# The mcp-gateway audience gate on the Keycloak callback (issue #245)
# ---------------------------------------------------------------------------


def _drive_bootstrap_callback(client: Any) -> Any:
    """Drive /v1/oauth/authorize through the Keycloak callback and return the callback response.

    Shared plumbing for the entitlement-gate tests below -- assumes the test
    already configured the env (``_configure_env``) and monkeypatched
    ``get_http_client`` with a ``_FakeMcpOAuthHttpClient``.
    """
    _, mcp_challenge = generate_pkce_pair()
    authorize_resp: Any = client.get(
        "/v1/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": MCP_CLIENT_ID,
            "redirect_uri": MCP_REDIRECT_URI,
            "state": "client-state-1",
            "code_challenge": mcp_challenge,
            "code_challenge_method": "S256",
        },
        follow_redirects=False,
    )
    assert authorize_resp.status_code == 302, authorize_resp.text
    broker_state = parse_qs(urlparse(authorize_resp.headers["location"]).query)[
        "state"
    ][0]
    # Same Secure-cookie workaround as the round-trip test above.
    nonce_cookie = authorize_resp.cookies.get("mcp_oauth_state_nonce")
    assert nonce_cookie is not None
    client.cookies.set(
        "mcp_oauth_state_nonce",
        nonce_cookie,
        path="/v1/oauth/keycloak-login/callback",
    )
    return client.get(
        "/v1/oauth/keycloak-login/callback",
        params={"code": "keycloak-auth-code-1", "state": broker_state},
        follow_redirects=False,
    )


def _assert_bootstrap_denied(callback_resp: Any, client: Any) -> None:
    """Assert the callback refused the login: ``access_denied`` redirect back to the MCP client, no authorization code stored, nonce cookie cleared."""
    assert callback_resp.status_code == 302, callback_resp.text
    location = callback_resp.headers["location"]
    assert location.startswith(f"{MCP_REDIRECT_URI}?")
    query = parse_qs(urlparse(location).query)
    assert query["error"] == ["access_denied"]
    assert query["state"] == ["client-state-1"]
    assert "code" not in query
    # No auth code stored means no PAT can ever be redeemed from this login.
    assert client.app.state.mcp_auth_code_store._entries == {}
    set_cookie = callback_resp.headers.get("set-cookie", "")
    assert "mcp_oauth_state_nonce=" in set_cookie
    assert "Max-Age=0" in set_cookie


def _valid_login_id_token(sig_key: RsaKey) -> str:
    """Return an id_token that passes ``_verify_keycloak_id_token`` -- the denial tests pair it with a *failing* access token, so a pass would prove the gate leaks regardless of check ordering."""
    now = int(time.time())
    return sig_key.sign(
        {
            "sub": "kc-sub-unentitled",
            "iss": ISSUER,
            "aud": LOGIN_CLIENT_ID,
            "iat": now,
            "exp": now + 300,
        }
    )


def test_keycloak_callback_denies_access_token_without_gateway_audience(
    monkeypatch: pytest.MonkeyPatch,
    app_client_factory: Callable[..., Any],
    sig_key: RsaKey,
    prime_jwks: Callable[[list[dict[str, Any]]], None],
) -> None:
    """A real login by a user Keycloak won't mint `mcp-gateway` for: the access token is valid in every respect except the audience."""
    _configure_env(monkeypatch, Fernet.generate_key().decode())
    prime_jwks([sig_key.jwk])
    now = int(time.time())
    access_token = sig_key.sign(
        {
            "sub": "kc-sub-unentitled",
            "iss": ISSUER,
            "aud": "account",
            "iat": now,
            "exp": now + 300,
        }
    )
    fake_client = _FakeMcpOAuthHttpClient(
        _cimd_doc(), _valid_login_id_token(sig_key), access_token=access_token
    )
    monkeypatch.setattr(
        "af_mcp_broker.api.mcp_oauth.get_http_client", lambda: fake_client
    )

    with app_client_factory() as (client, _):
        callback_resp = _drive_bootstrap_callback(client)
        _assert_bootstrap_denied(callback_resp, client)


def test_keycloak_callback_denies_missing_access_token(
    monkeypatch: pytest.MonkeyPatch,
    app_client_factory: Callable[..., Any],
    sig_key: RsaKey,
    prime_jwks: Callable[[list[dict[str, Any]]], None],
) -> None:
    """Fail closed: a token response with no access_token at all is a denial, not a pass."""
    _configure_env(monkeypatch, Fernet.generate_key().decode())
    prime_jwks([sig_key.jwk])
    fake_client = _FakeMcpOAuthHttpClient(
        _cimd_doc(), _valid_login_id_token(sig_key), access_token=None
    )
    monkeypatch.setattr(
        "af_mcp_broker.api.mcp_oauth.get_http_client", lambda: fake_client
    )

    with app_client_factory() as (client, _):
        callback_resp = _drive_bootstrap_callback(client)
        _assert_bootstrap_denied(callback_resp, client)


def test_keycloak_callback_denies_garbage_access_token(
    monkeypatch: pytest.MonkeyPatch,
    app_client_factory: Callable[..., Any],
    sig_key: RsaKey,
    prime_jwks: Callable[[list[dict[str, Any]]], None],
) -> None:
    _configure_env(monkeypatch, Fernet.generate_key().decode())
    prime_jwks([sig_key.jwk])
    fake_client = _FakeMcpOAuthHttpClient(
        _cimd_doc(), _valid_login_id_token(sig_key), access_token="not-a-jwt"
    )
    monkeypatch.setattr(
        "af_mcp_broker.api.mcp_oauth.get_http_client", lambda: fake_client
    )

    with app_client_factory() as (client, _):
        callback_resp = _drive_bootstrap_callback(client)
        _assert_bootstrap_denied(callback_resp, client)


def test_keycloak_callback_denies_expired_access_token(
    monkeypatch: pytest.MonkeyPatch,
    app_client_factory: Callable[..., Any],
    sig_key: RsaKey,
    prime_jwks: Callable[[list[dict[str, Any]]], None],
) -> None:
    """Even with the right audience, an expired access token is refused -- the gate is the full /v1 bearer verification, not an aud-claim peek."""
    _configure_env(monkeypatch, Fernet.generate_key().decode())
    prime_jwks([sig_key.jwk])
    now = int(time.time())
    access_token = sig_key.sign(
        {
            "sub": "kc-sub-unentitled",
            "iss": ISSUER,
            "aud": GATEWAY_AUDIENCE,
            "iat": now - 600,
            "exp": now - 300,
        }
    )
    fake_client = _FakeMcpOAuthHttpClient(
        _cimd_doc(), _valid_login_id_token(sig_key), access_token=access_token
    )
    monkeypatch.setattr(
        "af_mcp_broker.api.mcp_oauth.get_http_client", lambda: fake_client
    )

    with app_client_factory() as (client, _):
        callback_resp = _drive_bootstrap_callback(client)
        _assert_bootstrap_denied(callback_resp, client)


# ---------------------------------------------------------------------------
# PKCE / state tamper and replay rejection
# ---------------------------------------------------------------------------


def test_authorize_rejects_unregistered_redirect_uri(
    monkeypatch: pytest.MonkeyPatch, app_client_factory: Callable[..., Any]
) -> None:
    _configure_env(monkeypatch, Fernet.generate_key().decode())
    fake_client = _FakeMcpOAuthHttpClient(_cimd_doc(), "unused")
    monkeypatch.setattr(
        "af_mcp_broker.api.mcp_oauth.get_http_client", lambda: fake_client
    )
    _, mcp_challenge = generate_pkce_pair()

    with app_client_factory() as (client, _):
        resp: Any = client.get(
            "/v1/oauth/authorize",
            params={
                "response_type": "code",
                "client_id": MCP_CLIENT_ID,
                "redirect_uri": "http://localhost:1/not-registered",
                "state": "s",
                "code_challenge": mcp_challenge,
                "code_challenge_method": "S256",
            },
        )

    assert resp.status_code == 400


def test_authorize_rejects_missing_pkce(
    monkeypatch: pytest.MonkeyPatch, app_client_factory: Callable[..., Any]
) -> None:
    _configure_env(monkeypatch, Fernet.generate_key().decode())
    fake_client = _FakeMcpOAuthHttpClient(_cimd_doc(), "unused")
    monkeypatch.setattr(
        "af_mcp_broker.api.mcp_oauth.get_http_client", lambda: fake_client
    )

    with app_client_factory() as (client, _):
        resp: Any = client.get(
            "/v1/oauth/authorize",
            params={
                "response_type": "code",
                "client_id": MCP_CLIENT_ID,
                "redirect_uri": MCP_REDIRECT_URI,
                "state": "s",
                # code_challenge deliberately omitted
                "code_challenge_method": "S256",
            },
            follow_redirects=False,
        )

    assert resp.status_code == 302
    query = parse_qs(urlparse(resp.headers["location"]).query)
    assert query["error"] == ["invalid_request"]


def test_keycloak_callback_rejects_tampered_state(
    monkeypatch: pytest.MonkeyPatch, app_client_factory: Callable[..., Any]
) -> None:
    _configure_env(monkeypatch, Fernet.generate_key().decode())

    with app_client_factory() as (client, _):
        resp: Any = client.get(
            "/v1/oauth/keycloak-login/callback",
            params={"code": "some-code", "state": "not-a-real-state-token"},
        )

    assert resp.status_code == 400


def test_keycloak_callback_rejects_replayed_state_after_expiry(
    monkeypatch: pytest.MonkeyPatch, app_client_factory: Callable[..., Any]
) -> None:
    fernet_key = Fernet.generate_key().decode()
    _configure_env(monkeypatch, fernet_key)
    cipher = Fernet(fernet_key.encode())
    now = int(time.time())
    payload = {
        "iss": BROKER_ORIGIN,
        "aud": BROKER_ORIGIN,
        "pkce_verifier": "v",
        "mcp_client_id": MCP_CLIENT_ID,
        "mcp_redirect_uri": MCP_REDIRECT_URI,
        "mcp_state": "s",
        "mcp_code_challenge": "c",
        "mcp_client_name": "",
        "nonce": "n",
        "iat": now - 400,
        "exp": now - 100,
    }
    expired_state = cipher.encrypt_at_time(
        json.dumps(payload).encode(), now - 400
    ).decode()

    with app_client_factory() as (client, _):
        client.cookies.set(
            "mcp_oauth_state_nonce", "n", path="/v1/oauth/keycloak-login/callback"
        )
        resp: Any = client.get(
            "/v1/oauth/keycloak-login/callback",
            params={"code": "some-code", "state": expired_state},
        )

    assert resp.status_code == 400


def test_keycloak_callback_rejects_nonce_cookie_mismatch(
    monkeypatch: pytest.MonkeyPatch,
    app_client_factory: Callable[..., Any],
) -> None:
    fernet_key = Fernet.generate_key().decode()
    _configure_env(monkeypatch, fernet_key)
    cipher = Fernet(fernet_key.encode())
    state = build_mcp_authorize_state(
        cipher,
        iss=BROKER_ORIGIN,
        pkce_verifier="v",
        mcp_client_id=MCP_CLIENT_ID,
        mcp_redirect_uri=MCP_REDIRECT_URI,
        mcp_state="s",
        mcp_code_challenge="c",
        mcp_client_name="",
        nonce="real-nonce",
    )

    with app_client_factory() as (client, _):
        client.cookies.set(
            "mcp_oauth_state_nonce",
            "wrong-nonce",
            path="/v1/oauth/keycloak-login/callback",
        )
        resp: Any = client.get(
            "/v1/oauth/keycloak-login/callback",
            params={"code": "some-code", "state": state},
        )

    assert resp.status_code == 400


def test_token_rejects_pkce_mismatch(
    monkeypatch: pytest.MonkeyPatch, app_client_factory: Callable[..., Any]
) -> None:
    _configure_env(monkeypatch, Fernet.generate_key().decode())

    with app_client_factory() as (client, _):
        store = client.app.state.mcp_auth_code_store
        code = store.put(
            McpAuthCodeRecord(
                principal_id="sub-1",
                client_id=MCP_CLIENT_ID,
                redirect_uri=MCP_REDIRECT_URI,
                code_challenge="expected-challenge",
                client_name=None,
            )
        )
        resp: Any = client.post(
            "/v1/oauth/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": MCP_REDIRECT_URI,
                "client_id": MCP_CLIENT_ID,
                "code_verifier": "wrong-verifier",
            },
        )

    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_grant"


def test_token_rejects_reused_code() -> None:
    store = McpAuthCodeStore()
    code = store.put(
        McpAuthCodeRecord(
            principal_id="sub-1",
            client_id=MCP_CLIENT_ID,
            redirect_uri=MCP_REDIRECT_URI,
            code_challenge="c",
            client_name=None,
        )
    )
    assert store.consume(code) is not None
    assert store.consume(code) is None


def test_keycloak_endpoints_split_front_and_back_channel() -> None:
    """With oidc_internal_url set, the code-for-token exchange (a server-side
    POST from the broker) must go to the internal URL, while the
    authorization endpoint (a browser redirect) must stay on the
    externally-advertised issuer."""
    internal = "http://keycloak.svc.test:8080/realms/connect"
    settings = Settings(oidc_issuer=ISSUER, oidc_internal_url=internal)

    assert (
        _keycloak_token_endpoint(settings)
        == f"{internal}/protocol/openid-connect/token"
    )
    assert (
        _keycloak_authorization_endpoint(settings)
        == f"{ISSUER}/protocol/openid-connect/auth"
    )
