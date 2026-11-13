"""/v1's HTTP response for each identity failure ``get_principal`` raises.

``get_principal`` raises domain exceptions (``TokenExpiredError``,
``TokenAudienceError``, ``PrincipalDirectoryUnavailableError``); ``app.py``'s
exception handlers turn them into the status, headers and body /v1 callers
receive. These tests drive the real app with the real ``get_principal`` in
place of ``keycloak_dependency`` so the whole path is exercised.
"""

from __future__ import annotations

import time
from typing import Annotated

import pytest
from conftest import make_claims
from fastapi import Header

from af_mcp_broker.app import app
from af_mcp_broker.identity import get_principal, keycloak_dependency

URL = "/v1/identities"


@pytest.fixture
def v1_client(
    app_client_factory, settings, sig_key, prime_jwks, static_principal_cache
):
    """A client whose requests authenticate through the real ``get_principal``.

    Yields ``(client, directory, sign)`` where ``sign(**claims)`` returns the
    ``Authorization`` header for a token signed by the primed JWKS key.
    """
    cache, directory = static_principal_cache
    prime_jwks([sig_key.jwk])

    async def _authenticate(authorization: Annotated[str, Header()]):
        return await get_principal(
            authorization.removeprefix("Bearer "), settings, cache
        )

    def _sign(**claims):
        return {"Authorization": f"Bearer {sig_key.sign(make_claims(**claims))}"}

    with app_client_factory() as (client, _state):
        app.dependency_overrides[keycloak_dependency] = _authenticate
        yield client, directory, _sign


def test_expired_token_is_401_with_bearer_challenge(v1_client):
    client, _directory, sign = v1_client
    now = int(time.time())

    resp = client.get(URL, headers=sign(iat=now - 600, exp=now - 300))

    assert resp.status_code == 401
    assert resp.headers["WWW-Authenticate"] == "Bearer"
    assert resp.json() == {"detail": "Invalid or expired token"}


def test_wrong_audience_is_401_with_structured_detail(v1_client):
    client, _directory, sign = v1_client

    resp = client.get(URL, headers=sign(aud="some-other-service"))

    assert resp.status_code == 401
    assert resp.headers["WWW-Authenticate"] == "Bearer"
    detail = resp.json()["detail"]
    assert detail["error"] == "insufficient_scope"
    assert detail["correlation_id"] in detail["message"]


def test_unavailable_directory_is_503_with_correlation_id(v1_client):
    client, directory, sign = v1_client
    directory.unavailable_subjects.add("user-123")

    resp = client.get(URL, headers=sign())

    assert resp.status_code == 503
    assert "WWW-Authenticate" not in resp.headers
    body = resp.json()
    assert "authorization directory is temporarily unavailable" in body["detail"]
    assert body["correlation_id"]


def test_other_invalid_token_is_still_a_plain_401(v1_client):
    client, _directory, _sign = v1_client

    resp = client.get(URL, headers={"Authorization": "Bearer not-a-jwt"})

    assert resp.status_code == 401
    assert resp.headers["WWW-Authenticate"] == "Bearer"
    assert resp.json() == {"detail": "Invalid or expired token"}
