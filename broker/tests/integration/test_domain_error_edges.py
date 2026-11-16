"""What each edge sends for a failure raised below it.

Credential providers, the maintenance gate and the identity helpers raise
their failures from below the HTTP edge. ``/v1`` (``app.py``'s exception
handlers) and ``/mcp`` (the aggregator's tool error, the ASGI middleware's
error response) turn them into the status, headers, body and message a caller
sees. Each test here captures the exception the real code raises, so the
expectations hold whichever exception type carries the failure.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

import pytest
from conftest import make_claims
from domain_error_edges_support import (  # noqa: F401
    _CONDOR_RATE_LIMITED_DETAIL,
    _CREDENTIAL_FAILURES,
    _IDS,
    _OAUTH21_EXPIRED,
    _OAUTH21_NOT_STORED,
    _OAUTH21_REFRESH_FAILED,
    _OAUTH21_REJECTED,
    _OIDC_401,
    _OIDC_403,
    _OIDC_404,
    _POSIX_REQUIRED_BROKER_ISSUED,
    _POSIX_REQUIRED_CONDOR,
    _RATE_LIMITED_RESPONSES,
    _broker_issued_no_posix,
    _condor_exchange_producer,
    _condor_no_posix,
    _condor_provider,
    _KeycloakStatusClient,
    _oauth21_expired_without_refresh,
    _oauth21_not_stored,
    _oauth21_refresh_rejected,
    _oauth21_rejected,
    _oidc_producer,
    _raised,
    _UnreachableJwksClient,
    unreachable_jwks_fixture,
)
from mcp_aggregator_support import _FakeProvider
from rate_limited_helpers import assert_rate_limited_shape

from af_mcp_broker.api.auth import keycloak_dependency
from af_mcp_broker.app import app
from af_mcp_broker.identity import get_principal
from af_mcp_broker.maintenance import MaintenanceState

if TYPE_CHECKING:
    from af_mcp_broker.principal import Principal

_TARGET = "edge-target"


@pytest.mark.parametrize(
    ("producer", "status_code", "detail", "headers"),
    [row[1:] for row in _CREDENTIAL_FAILURES],
    ids=_IDS,
)
async def test_v1_edge_sends_the_credential_failure_status_detail_and_headers(
    producer,
    status_code,
    detail,
    headers,
    make_principal,
    app_client_factory,
    monkeypatch,
) -> None:
    exc = await producer(make_principal)
    with app_client_factory() as (client, _state):
        client.app.state.broker.credential_registry.register(
            _TARGET,
            _FakeProvider(http_error=exc),  # type: ignore[arg-type]
        )
        resp = client.post("/v1/credential", json={"target": _TARGET})

    assert resp.status_code == status_code
    body = resp.json()
    assert body["detail"] == detail
    if status_code >= 500:
        assert body["request_id"]
    else:
        assert set(body) == {"detail"}
    for name, value in headers.items():
        assert resp.headers[name] == value
    if "Retry-After" not in headers:
        assert "Retry-After" not in resp.headers


@pytest.mark.parametrize(("response", "retry_after"), _RATE_LIMITED_RESPONSES)
async def test_v1_edge_gives_a_credential_429_the_one_rate_limited_shape(
    response, retry_after, make_principal, app_client_factory
) -> None:
    exc = await _condor_exchange_producer(response)(make_principal)
    with app_client_factory() as (client, _state):
        client.app.state.broker.credential_registry.register(
            _TARGET,
            _FakeProvider(http_error=exc),  # type: ignore[arg-type]
        )
        resp = client.post("/v1/credential", json={"target": _TARGET})

    body = assert_rate_limited_shape(resp, retry_after=retry_after)
    assert body["detail"] == _CONDOR_RATE_LIMITED_DETAIL


def test_v1_edge_sends_502_with_request_id_when_the_jwks_is_unreachable(
    app_client_factory, settings, sig_key, static_principal_cache, unreachable_jwks
) -> None:
    cache, _directory = static_principal_cache
    token = sig_key.sign(make_claims())

    async def _authenticate() -> Principal:
        return await get_principal(token, settings, cache, unreachable_jwks)

    with app_client_factory() as (client, _state):
        app.dependency_overrides[keycloak_dependency] = _authenticate
        resp = client.get("/v1/identities")

    assert resp.status_code == 502
    body = resp.json()
    assert body["detail"] == f"Unable to reach JWKS endpoint: {settings.oidc_jwks_uri}"
    assert body["request_id"]


def test_v1_edge_sends_401_with_bearer_challenge_when_no_credential_is_presented(
    app_client_factory,
) -> None:
    with app_client_factory() as (client, _state):
        app.dependency_overrides.clear()
        resp = client.get("/v1/identities")

    assert resp.status_code == 401
    assert resp.headers["WWW-Authenticate"] == "Bearer"
    assert resp.json() == {"detail": "Not authenticated"}


def test_v1_edge_sends_403_to_a_non_admin_on_an_admin_route(
    app_client_factory,
) -> None:
    with app_client_factory() as (client, _state):
        resp = client.post("/v1/admin/maintenance", json={"enabled": True})

    assert resp.status_code == 403
    assert resp.json() == {
        "detail": "This action requires membership in the admin group."
    }


# ---------------------------------------------------------------------------
# Maintenance mode.
# ---------------------------------------------------------------------------


def test_v1_edge_sends_503_with_the_maintenance_reason_and_a_request_id(
    app_client_factory,
) -> None:
    with app_client_factory() as (client, _state):
        store = client.app.state.broker.maintenance_mode_store
        asyncio.run(
            store.set(
                MaintenanceState(
                    enabled=True,
                    reason="down for updates",
                    enabled_by="a",
                    enabled_at=1.0,
                )
            )
        )
        resp = client.get("/v1/identities")

    assert resp.status_code == 503
    body = resp.json()
    assert (
        body["detail"] == "The broker is in maintenance mode. Reason: down for updates"
    )
    assert body["request_id"]
