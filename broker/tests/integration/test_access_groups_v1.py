"""/v1 refuses a principal outside ``Settings.access_groups`` before any route runs.

Drives the real app with the real ``get_principal`` in place of
``keycloak_dependency`` (as ``test_identity_http_translation`` does), so the
membership check is exercised on every authenticated route, including
``POST /v1/tokens``, which only requires an authenticated JWT.
"""

from __future__ import annotations

from typing import Annotated

import httpx2
import pytest
from conftest import make_claims
from fastapi import Header

from af_mcp_broker.api.auth import keycloak_dependency
from af_mcp_broker.app import app
from af_mcp_broker.identity import get_principal

_GROUP = "/example/af"
_DENIED = {
    "error": "not_a_platform_member",
    "message": (
        "You don't have access to this platform. It requires membership "
        f"in one of: {_GROUP}. Ask to join one of these groups."
    ),
}


@pytest.fixture
def gated_client(
    app_client_factory, settings, sig_key, prime_jwks, static_principal_cache
):
    """Yields ``(client, directory, headers)``; the settings require ``_GROUP``."""
    cache, directory = static_principal_cache
    prime_jwks([sig_key.jwk])
    http_client = httpx2.AsyncClient()  # the primed JWKS cache means it never sends
    gated = settings.model_copy(update={"access_groups": [_GROUP]})

    async def _authenticate(authorization: Annotated[str, Header()]):
        return await get_principal(
            authorization.removeprefix("Bearer "), gated, cache, http_client
        )

    headers = {"Authorization": f"Bearer {sig_key.sign(make_claims())}"}
    with app_client_factory() as (client, _state):
        app.dependency_overrides[keycloak_dependency] = _authenticate
        yield client, directory, headers


@pytest.mark.parametrize(
    ("method", "url"),
    [
        pytest.param("GET", "/v1/identities", id="identities"),
        pytest.param("POST", "/v1/tokens", id="mint-pat"),
    ],
)
def test_non_member_is_403_on_authenticated_routes(gated_client, method, url):
    client, directory, headers = gated_client
    directory.groups_by_subject["user-123"] = ["/example/other"]

    resp = client.request(method, url, headers=headers, json={"name": "t"})

    assert resp.status_code == 403
    assert "WWW-Authenticate" not in resp.headers
    assert resp.json()["detail"] == _DENIED


def test_member_without_any_permission_is_admitted(gated_client):
    client, directory, headers = gated_client
    directory.groups_by_subject["user-123"] = [_GROUP]

    resp = client.get("/v1/identities", headers=headers)

    assert resp.status_code != 403


@pytest.mark.parametrize(
    "url", ["/v1/healthz", "/openapi.json", "/.well-known/jwks.json"]
)
def test_unauthenticated_routes_stay_open_to_everyone(gated_client, url):
    client, _directory, _headers = gated_client

    resp = client.get(url)

    assert resp.status_code != 403
