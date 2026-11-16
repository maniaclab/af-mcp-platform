"""Fixtures and helpers shared by the unit and integration tests of ``test_domain_error_edges``."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

import httpx2
import pytest
from condor_token_support import SERVICE_URL, _FakeCondorClient
from oauth21_support import (
    ALIAS,
    SUBJECT,
    _FakeTokenClient,
    _make_cred,
    _make_provider,
)
from signing_keys import private_pem, shared_rsa_key

from af_mcp_broker import identity as identity_module
from af_mcp_broker.config import Settings
from af_mcp_broker.credentials import (
    BrokerIssuedProvider,
    BrokerIssuedTokenOptions,
    BrokerTokenIssuer,
    CredentialCache,
    OAuth21Provider,
)
from af_mcp_broker.credentials import oidc as oidc_module
from af_mcp_broker.credentials.condor import CondorTokenProvider
from af_mcp_broker.credentials.oauth21 import InMemoryTokenStore
from af_mcp_broker.retry_after import DEFAULT_RETRY_AFTER_SECONDS

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable


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
            private_key_pem=private_pem(shared_rsa_key()),
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
            private_key_pem=private_pem(shared_rsa_key()),
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


# ---------------------------------------------------------------------------
# A credential service's 429: one shape on /v1, the wait in the message on /mcp.
# ---------------------------------------------------------------------------

_CONDOR_RATE_LIMITED_DETAIL = (
    "The HTCondor credential service rate-limited this request. Retry later."
)
_RATE_LIMITED_RESPONSES = [
    pytest.param(httpx2.Response(429, headers={"Retry-After": "17"}), 17, id="header"),
    pytest.param(
        httpx2.Response(429), DEFAULT_RETRY_AFTER_SECONDS, id="no-retry-after"
    ),
    pytest.param(
        httpx2.Response(429, headers={"Retry-After": "Wed, 21 Oct 2026 07:28:00 GMT"}),
        DEFAULT_RETRY_AFTER_SECONDS,
        id="http-date",
    ),
]


# ---------------------------------------------------------------------------
# Identity: JWKS unreachable, no credential presented, not an admin.
# ---------------------------------------------------------------------------


class _UnreachableJwksClient:
    async def get(self, url: str, **kwargs: Any) -> httpx2.Response:
        raise httpx2.ConnectError("jwks down")


@pytest.fixture(name="unreachable_jwks")
def unreachable_jwks_fixture(settings: Settings) -> _UnreachableJwksClient:
    """A client that cannot reach the JWKS endpoint, with nothing cached for it."""
    identity_module._jwks_cache.pop(settings.oidc_jwks_uri, None)
    return _UnreachableJwksClient()
