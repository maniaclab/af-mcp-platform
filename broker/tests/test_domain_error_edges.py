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
import json
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

import httpx2
import pytest
from broker_state_helpers import asgi_auth_middleware
from conftest import make_claims
from fastmcp.exceptions import ToolError
from test_broker_issued import _make_rsa_key, _private_pem
from test_condor_token import SERVICE_URL, _FakeCondorClient
from test_mcp_aggregator import _OPEN_POLICY, _FakeProvider, _patch_context, _spec
from test_mcp_middleware_identity import (
    _header,
    _http_scope,
    _InnerApp,
    _run,
    _status,
)
from test_oauth21 import (
    ALIAS,
    SUBJECT,
    _FakeTokenClient,
    _make_cred,
    _make_provider,
)

from af_mcp_broker import identity as identity_module
from af_mcp_broker.app import app
from af_mcp_broker.config import Settings
from af_mcp_broker.credentials import (
    BrokerIssuedProvider,
    BrokerIssuedTokenOptions,
    BrokerTokenIssuer,
    CredentialCache,
    CredentialRegistry,
    OAuth21Provider,
)
from af_mcp_broker.credentials import oidc as oidc_module
from af_mcp_broker.credentials.condor import CondorTokenProvider
from af_mcp_broker.credentials.oauth21 import InMemoryTokenStore
from af_mcp_broker.identity import get_principal, keycloak_dependency
from af_mcp_broker.maintenance import MaintenanceState
from af_mcp_broker.mcp.aggregator import _make_client_factory

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from af_mcp_broker.principal import Principal

_TARGET = "edge-target"

_POSIX_REQUIRED_CONDOR = (
    "Service 'condor-mcp' requires a POSIX identity "
    "(uid/gid/unixname) — HTCondor IDTOKENs are minted for "
    "your unix account, which your account does not have. "
    "Contact your Analysis Facility operator to request a "
    "POSIX identity."
)
_POSIX_REQUIRED_BROKER_ISSUED = (
    "Service 'condor-token-service' requires POSIX identity claims "
    "(uid/gid/unixname) in its AF Broker Identity Token, "
    "which your account does not have. Contact your "
    "Analysis Facility operator to request a POSIX "
    "identity."
)
_OIDC_401 = (
    "Your Keycloak session has expired or the ATLAS IAM "
    "identity link is invalid. Please re-authenticate and "
    "reconnect your ATLAS account from the portal's "
    "Identities page."
)
_OIDC_403 = (
    "Your account isn't authorized to retrieve a stored "
    "ATLAS IAM token. Contact the platform team to be "
    "granted access, then link (or re-link) your ATLAS "
    "account from the portal's Identities page."
)
_OIDC_404 = (
    "No ATLAS IAM token stored for your account. "
    "Link your ATLAS account from the portal's Identities page."
)
_OAUTH21_NOT_STORED = (
    f"No OAuth 2.1 token stored for alias {ALIAS!r}. "
    "Link this account from the portal's Identities page."
)
_OAUTH21_REJECTED = (
    f"OAuth 2.1 token for alias {ALIAS!r} was rejected "
    "by the service. Please re-link this account from the "
    "portal's Identities page."
)
_OAUTH21_EXPIRED = (
    f"OAuth 2.1 token for alias {ALIAS!r} has expired "
    "and no refresh token is available. Please re-link this "
    "account from the portal's Identities page."
)
_OAUTH21_REFRESH_FAILED = (
    f"OAuth 2.1 token for alias {ALIAS!r} could not be "
    "refreshed; please re-link this account from the "
    "portal's Identities page."
)


async def _raised(awaitable: Awaitable[Any]) -> BaseException:
    """Return the exception *awaitable* raises, failing when it raises none."""
    try:
        await awaitable
    except Exception as exc:  # noqa: BLE001 -- the caller asserts on whichever type was raised
        return exc
    raise AssertionError("expected the awaitable to raise")


# ---------------------------------------------------------------------------
# Producers: the exception the real code raises for each failure.
# ---------------------------------------------------------------------------


async def _oauth21_not_stored(make_principal) -> BaseException:
    provider = _make_provider(InMemoryTokenStore())
    return await _raised(provider.issue(make_principal(subject=SUBJECT), ALIAS))


async def _oauth21_rejected(make_principal) -> BaseException:
    store = InMemoryTokenStore()
    await store.write_cas(
        SUBJECT,
        ALIAS,
        _make_cred(rejected_at=datetime.now(UTC)),
        expected_version=None,
    )
    return await _raised(
        _make_provider(store).issue(make_principal(subject=SUBJECT), ALIAS)
    )


async def _oauth21_expired_without_refresh(make_principal) -> BaseException:
    store = InMemoryTokenStore()
    await store.write_cas(
        SUBJECT,
        ALIAS,
        _make_cred(
            refresh_token=None, expires_at=datetime.now(UTC) - timedelta(seconds=10)
        ),
        expected_version=None,
    )
    return await _raised(
        _make_provider(store).issue(make_principal(subject=SUBJECT), ALIAS)
    )


async def _oauth21_refresh_rejected(make_principal) -> BaseException:
    store = InMemoryTokenStore()
    await store.write_cas(
        SUBJECT,
        ALIAS,
        _make_cred(expires_at=datetime.now(UTC) + timedelta(seconds=10)),
        expected_version=None,
    )
    provider: OAuth21Provider = _make_provider(
        store,
        http_client=_FakeTokenClient(
            status_code=400, json_body={"error": "invalid_grant"}
        ),
    )
    return await _raised(provider.issue(make_principal(subject=SUBJECT), ALIAS))


class _KeycloakStatusClient:
    """Answers Keycloak's brokered-token endpoint with a fixed status."""

    def __init__(self, status_code: int) -> None:
        self._status_code = status_code

    async def get(self, url: str, **kwargs: Any) -> httpx2.Response:
        return httpx2.Response(self._status_code, request=httpx2.Request("GET", url))


def _oidc_producer(status_code: int):
    async def _produce(make_principal) -> BaseException:
        provider = oidc_module.OIDCProvider(
            settings=Settings(oidc_issuer="https://keycloak.test/realms/connect"),
            cache=CredentialCache(),
            alias="atlas-oidc",
            http_client=_KeycloakStatusClient(status_code),
        )
        return await _raised(provider._fetch_brokered_token(make_principal()))

    return _produce


def _condor_provider(http_client: Any) -> CondorTokenProvider:
    return CondorTokenProvider(
        issuer=BrokerTokenIssuer(
            private_key_pem=_private_pem(_make_rsa_key()),
            issuer="https://broker.test",
            ttl_seconds=600,
        ),
        cache=CredentialCache(),
        alias="condor",
        targets=frozenset({"condor-mcp"}),
        service_url=SERVICE_URL,
        audience="condor-token-service",
        http_client=http_client,
    )


async def _condor_no_posix(make_principal) -> BaseException:
    return await _raised(
        _condor_provider(httpx2.AsyncClient()).issue(
            make_principal(uid=None, gid=None, unixname=None), "condor-mcp"
        )
    )


def _condor_exchange_producer(response: httpx2.Response | Exception):
    async def _produce(make_principal) -> BaseException:
        if isinstance(response, Exception):

            class _FailingClient:
                async def post(self, *args: Any, **kwargs: Any) -> httpx2.Response:
                    raise response

            client: Any = _FailingClient()
        else:
            client = _FakeCondorClient([response])
        return await _raised(
            _condor_provider(client).issue(make_principal(), "condor-mcp")
        )

    return _produce


async def _broker_issued_no_posix(make_principal) -> BaseException:
    provider = BrokerIssuedProvider(
        issuer=BrokerTokenIssuer(
            private_key_pem=_private_pem(_make_rsa_key()),
            issuer="https://broker.test",
            ttl_seconds=600,
        ),
        cache=CredentialCache(),
        alias="af-native",
        targets=frozenset({"condor-token-service"}),
        token_options={
            "condor-token-service": BrokerIssuedTokenOptions(
                audience="condor-token-service", requires_posix=True
            )
        },
    )
    return await _raised(
        provider.issue(
            make_principal(uid=None, gid=None, unixname=None), "condor-token-service"
        )
    )


# (id, producer, HTTP status, detail, response headers)
_CREDENTIAL_FAILURES: list[
    tuple[str, Callable[..., Awaitable[BaseException]], int, str, dict[str, str]]
] = [
    ("oauth21-not-stored", _oauth21_not_stored, 404, _OAUTH21_NOT_STORED, {}),
    ("oauth21-rejected", _oauth21_rejected, 401, _OAUTH21_REJECTED, {}),
    (
        "oauth21-expired",
        _oauth21_expired_without_refresh,
        401,
        _OAUTH21_EXPIRED,
        {},
    ),
    (
        "oauth21-refresh-rejected",
        _oauth21_refresh_rejected,
        401,
        _OAUTH21_REFRESH_FAILED,
        {},
    ),
    ("oidc-401", _oidc_producer(401), 401, _OIDC_401, {}),
    ("oidc-403", _oidc_producer(403), 403, _OIDC_403, {}),
    ("oidc-404", _oidc_producer(404), 404, _OIDC_404, {}),
    ("condor-no-posix", _condor_no_posix, 404, _POSIX_REQUIRED_CONDOR, {}),
    (
        "condor-unreachable",
        _condor_exchange_producer(httpx2.ConnectError("boom")),
        502,
        "The HTCondor credential service could not be reached.",
        {},
    ),
    (
        "condor-rate-limited",
        _condor_exchange_producer(httpx2.Response(429, headers={"Retry-After": "17"})),
        429,
        "The HTCondor credential service rate-limited this request. Retry later.",
        {"Retry-After": "17"},
    ),
    (
        "condor-rate-limited-without-retry-after",
        _condor_exchange_producer(httpx2.Response(429)),
        429,
        "The HTCondor credential service rate-limited this request. Retry later.",
        {},
    ),
    (
        "condor-upstream-failed",
        _condor_exchange_producer(httpx2.Response(500)),
        502,
        "HTCondor credential issuance failed.",
        {},
    ),
    (
        "broker-issued-no-posix",
        _broker_issued_no_posix,
        404,
        _POSIX_REQUIRED_BROKER_ISSUED,
        {},
    ),
]

_IDS = [row[0] for row in _CREDENTIAL_FAILURES]


@pytest.mark.parametrize(
    ("producer", "status_code", "detail", "headers"),
    [row[1:] for row in _CREDENTIAL_FAILURES],
    ids=_IDS,
)
async def test_mcp_edge_surfaces_the_credential_failure_detail_as_a_tool_error(
    producer, status_code, detail, headers, make_principal, settings, monkeypatch
) -> None:
    exc = await producer(make_principal)
    _patch_context(monkeypatch, make_principal())
    spec = _spec(auth_type="bearer")
    registry = CredentialRegistry()
    registry.register(spec.name, _FakeProvider(http_error=exc))  # type: ignore[arg-type]

    with pytest.raises(ToolError) as excinfo:
        await _make_client_factory(spec, registry, settings, _OPEN_POLICY)()

    assert str(excinfo.value) == detail


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
        assert body["correlation_id"]
    else:
        assert set(body) == {"detail"}
    for name, value in headers.items():
        assert resp.headers[name] == value
    if "Retry-After" not in headers:
        assert "Retry-After" not in resp.headers


# ---------------------------------------------------------------------------
# Identity: JWKS unreachable, no credential presented, not an admin.
# ---------------------------------------------------------------------------


class _UnreachableJwksClient:
    async def get(self, url: str, **kwargs: Any) -> httpx2.Response:
        raise httpx2.ConnectError("jwks down")


@pytest.fixture
def unreachable_jwks(settings: Settings) -> _UnreachableJwksClient:
    """A client that cannot reach the JWKS endpoint, with nothing cached for it."""
    identity_module._jwks_cache.pop(settings.oidc_jwks_uri, None)
    return _UnreachableJwksClient()


def test_v1_edge_sends_502_with_correlation_id_when_the_jwks_is_unreachable(
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
    assert body["correlation_id"]


async def test_mcp_edge_collapses_an_unreachable_jwks_into_the_vague_401(
    settings, sig_key, unreachable_jwks
) -> None:
    token = sig_key.sign(make_claims())
    inner = _InnerApp()
    middleware = asgi_auth_middleware(inner, settings, http_client=unreachable_jwks)

    messages = await _run(middleware, _http_scope({"authorization": f"Bearer {token}"}))

    assert not inner.called
    assert _status(messages) == 401
    assert _header(messages, "www-authenticate") == "Bearer"
    body = json.loads(
        b"".join(m["body"] for m in messages if m["type"] == "http.response.body")
    )
    assert body["detail"] == "Invalid bearer token"


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


def test_v1_edge_sends_503_with_the_maintenance_reason_and_a_correlation_id(
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
    assert body["correlation_id"]
