"""Tests for CondorTokenProvider (issue #169).

Covers the provider unit surface with condor-token-service stubbed at the
HTTP boundary: the happy path (broker identity token minted with
``aud=condor-token-service`` + POSIX claims, exchanged for an IDTOKEN,
cached with expiry = the service's ``expires_at``), cache hits skipping
HTTP entirely, single-flighting, the POSIX-identity point-of-use 404, and
the service error mappings (401/403/502 -> 502 with generic detail, 429
passed through with Retry-After). App-level wiring (startup fail-closed,
registration from config) lives in test_condor_token_app.py.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import jwt
import pytest
from fastapi import HTTPException
from test_broker_issued import (
    ISSUER_URL,
    _make_rsa_key,
    _private_pem,
    verify_against_jwks,
)

from af_mcp_broker.credentials import CredentialKind, ExecutionModel
from af_mcp_broker.credentials import condor as condor_module
from af_mcp_broker.credentials.broker_issued import BrokerTokenIssuer
from af_mcp_broker.credentials.cache import CredentialCache
from af_mcp_broker.credentials.condor import CondorTokenProvider

SERVICE_URL = "http://condor-token-service.test"
IDTOKEN = "fake-htcondor-idtoken"

# Internals the service must never leak to the broker's callers -- assertions
# check these strings are absent from client-visible HTTPException detail.
_UPSTREAM_DETAIL = "condor_token_create exploded: /etc/condor/passwords.d/POOL"


def _token_response(
    *, expires_in_seconds: int = 3600, token: str = IDTOKEN
) -> dict[str, Any]:
    expires_at = datetime.now(UTC) + timedelta(seconds=expires_in_seconds)
    return {
        "token": token,
        "identity": "auser@af.uchicago.edu",
        "expires_at": expires_at.isoformat(),
    }


class _FakeCondorClient:
    """Fake httpx client for the condor-token-service exchange.

    Records every POST (url + headers) so tests can assert the broker
    identity token actually presented, and returns a configurable
    ``httpx.Response`` per call.
    """

    def __init__(self, responses: list[httpx.Response] | None = None) -> None:
        self.responses = responses or [httpx.Response(200, json=_token_response())]
        self.calls: list[tuple[str, dict[str, str]]] = []

    async def post(
        self, url: str, headers: dict[str, str], **kwargs: Any
    ) -> httpx.Response:
        self.calls.append((url, dict(headers)))
        return self.responses[min(len(self.calls) - 1, len(self.responses) - 1)]


@pytest.fixture
def issuer() -> BrokerTokenIssuer:
    return BrokerTokenIssuer(
        private_key_pem=_private_pem(_make_rsa_key()),
        issuer=ISSUER_URL,
        ttl_seconds=600,
    )


@pytest.fixture
def provider_factory(issuer: BrokerTokenIssuer):
    def _make(
        *, audience: str = "condor-token-service", service_url: str = SERVICE_URL
    ) -> tuple[CondorTokenProvider, CredentialCache]:
        cache = CredentialCache()
        provider = CondorTokenProvider(
            issuer=issuer,
            cache=cache,
            alias="condor",
            targets=frozenset({"condor-mcp"}),
            service_url=service_url,
            audience=audience,
        )
        return provider, cache

    return _make


@pytest.fixture
def fake_client(monkeypatch: pytest.MonkeyPatch) -> _FakeCondorClient:
    client = _FakeCondorClient()
    monkeypatch.setattr(condor_module, "get_http_client", lambda: client)
    return client


def _install_client(
    monkeypatch: pytest.MonkeyPatch, responses: list[httpx.Response]
) -> _FakeCondorClient:
    client = _FakeCondorClient(responses)
    monkeypatch.setattr(condor_module, "get_http_client", lambda: client)
    return client


# ---------------------------------------------------------------------------
# is_linked / happy path
# ---------------------------------------------------------------------------


async def test_provider_is_always_linked(provider_factory, make_principal) -> None:
    provider, _ = provider_factory()

    assert await provider.is_linked(make_principal()) is True


async def test_issue_returns_bearer_idtoken(
    provider_factory, make_principal, fake_client
) -> None:
    provider, _ = provider_factory()

    cred = await provider.issue(make_principal(), "condor-mcp")

    assert cred.cred_class == "condor_token"
    assert cred.kind == CredentialKind.BEARER
    assert cred.execution_model == ExecutionModel.DELEGATED
    assert cred.target == "condor-mcp"
    assert cred.payload["access_token"] == IDTOKEN
    assert cred.payload["token_type"] == "Bearer"


async def test_issue_posts_to_the_service_token_endpoint(
    provider_factory, make_principal, fake_client
) -> None:
    provider, _ = provider_factory()

    await provider.issue(make_principal(), "condor-mcp")

    (url, _headers) = fake_client.calls[0]
    assert url == f"{SERVICE_URL}/v1/token"


async def test_issue_expires_at_comes_from_the_service_response(
    provider_factory, make_principal, monkeypatch: pytest.MonkeyPatch
) -> None:
    body = _token_response(expires_in_seconds=1800)
    _install_client(monkeypatch, [httpx.Response(200, json=body)])
    provider, _ = provider_factory()

    cred = await provider.issue(make_principal(), "condor-mcp")

    expected = datetime.fromisoformat(body["expires_at"]).timestamp()
    assert cred.expires_at == pytest.approx(expected)


async def test_issue_presented_broker_token_has_condor_audience_and_posix_claims(
    provider_factory, make_principal, fake_client, issuer: BrokerTokenIssuer
) -> None:
    """The Authorization header carries a freshly-minted AF Broker Identity
    Token verifiable against the broker's own JWKS, aud exactly the
    configured audience, with the principal's POSIX claims -- the
    condor-token-service contract."""
    provider, _ = provider_factory()
    principal = make_principal(subject="sub-abc", uid=50123, gid=5000, unixname="auser")

    await provider.issue(principal, "condor-mcp")

    (_url, headers) = fake_client.calls[0]
    broker_token = headers["Authorization"].removeprefix("Bearer ")
    claims = verify_against_jwks(
        broker_token, issuer.jwks(), audience="condor-token-service"
    )
    assert claims["sub"] == "sub-abc"
    assert claims["uid"] == 50123
    assert claims["gid"] == 5000
    assert claims["unixname"] == "auser"


async def test_issue_audience_is_configurable(
    provider_factory, make_principal, fake_client
) -> None:
    provider, _ = provider_factory(audience="condor-token-service-dev")

    await provider.issue(make_principal(), "condor-mcp")

    (_url, headers) = fake_client.calls[0]
    broker_token = headers["Authorization"].removeprefix("Bearer ")
    claims = jwt.decode(broker_token, options={"verify_signature": False})
    assert claims["aud"] == "condor-token-service-dev"


async def test_issue_strips_trailing_slash_from_service_url(
    provider_factory, make_principal, fake_client
) -> None:
    """pydantic's AnyHttpUrl normalizes a bare origin to a trailing-slash
    form; the provider must not POST to //v1/token."""
    provider, _ = provider_factory(service_url=f"{SERVICE_URL}/")

    await provider.issue(make_principal(), "condor-mcp")

    (url, _headers) = fake_client.calls[0]
    assert url == f"{SERVICE_URL}/v1/token"


# ---------------------------------------------------------------------------
# Caching
# ---------------------------------------------------------------------------


async def test_issue_cache_hit_skips_http(
    provider_factory, make_principal, fake_client
) -> None:
    provider, _ = provider_factory()
    principal = make_principal(subject="sub-abc")

    first = await provider.issue(principal, "condor-mcp")
    second = await provider.issue(principal, "condor-mcp")

    assert len(fake_client.calls) == 1
    assert second.payload["access_token"] == first.payload["access_token"]


async def test_issue_remints_when_cached_token_is_below_min_remaining(
    provider_factory, make_principal, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A cached IDTOKEN with fewer than min_remaining seconds left is a
    cache miss (CredentialCache semantics) -- the expiry stored from the
    service's expires_at is what makes this happen."""
    client = _install_client(
        monkeypatch,
        [httpx.Response(200, json=_token_response(expires_in_seconds=100))],
    )
    provider, _ = provider_factory()
    principal = make_principal(subject="sub-abc")

    await provider.issue(principal, "condor-mcp")
    await provider.issue(principal, "condor-mcp")

    assert len(client.calls) == 2


async def test_issue_single_flights_concurrent_misses(
    provider_factory, make_principal, monkeypatch: pytest.MonkeyPatch
) -> None:
    """N concurrent issue() calls for the same (subject, target) must cost
    exactly one service exchange (issue #94's pattern)."""

    class _SlowClient(_FakeCondorClient):
        async def post(
            self, url: str, headers: dict[str, str], **kwargs: Any
        ) -> httpx.Response:
            # Force a real suspension so concurrent callers actually overlap.
            await asyncio.sleep(0.01)
            return await super().post(url, headers=headers, **kwargs)

    client = _SlowClient()
    monkeypatch.setattr(condor_module, "get_http_client", lambda: client)
    provider, _ = provider_factory()
    principal = make_principal(subject="sub-abc")

    results = await asyncio.gather(
        *[provider.issue(principal, "condor-mcp") for _ in range(5)]
    )

    assert len(client.calls) == 1
    assert all(r.payload["access_token"] == IDTOKEN for r in results)


async def test_revoke_drops_cached_credential(
    provider_factory, make_principal, fake_client
) -> None:
    provider, _ = provider_factory()
    principal = make_principal(subject="sub-abc")

    await provider.issue(principal, "condor-mcp")
    await provider.revoke(principal, "condor-mcp")
    await provider.issue(principal, "condor-mcp")

    assert len(fake_client.calls) == 2


# ---------------------------------------------------------------------------
# POSIX identity requirement
# ---------------------------------------------------------------------------


async def test_issue_without_posix_identity_raises_404(
    provider_factory, make_principal, fake_client
) -> None:
    """Same point-of-use shape as BrokerIssuedProvider's requires_posix check
    (and x509's PosixIdentityRequiredError): an HTTPException(404) naming
    the target, raised before any token is minted or any HTTP happens."""
    provider, _ = provider_factory()
    principal = make_principal(uid=None, gid=None, unixname=None)

    with pytest.raises(HTTPException) as excinfo:
        await provider.issue(principal, "condor-mcp")

    assert excinfo.value.status_code == 404
    assert "condor-mcp" in str(excinfo.value.detail)
    assert "POSIX" in str(excinfo.value.detail)
    assert fake_client.calls == []


# ---------------------------------------------------------------------------
# Service error mapping -- generic detail, never upstream internals
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("upstream_status", [401, 403, 502])
async def test_issue_maps_service_failures_to_502_with_generic_detail(
    provider_factory, make_principal, monkeypatch: pytest.MonkeyPatch, upstream_status
) -> None:
    """401 (broker token rejected) and 403 (no unixname claim) are
    broker<->service contract failures, not something the caller can act on;
    502 is minting failed. All map to a generic 502."""
    _install_client(
        monkeypatch,
        [httpx.Response(upstream_status, json={"detail": _UPSTREAM_DETAIL})],
    )
    provider, _ = provider_factory()

    with pytest.raises(HTTPException) as excinfo:
        await provider.issue(make_principal(), "condor-mcp")

    assert excinfo.value.status_code == 502
    assert _UPSTREAM_DETAIL not in str(excinfo.value.detail)


async def test_issue_passes_through_429_with_retry_after(
    provider_factory, make_principal, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install_client(
        monkeypatch,
        [
            httpx.Response(
                429,
                json={"detail": "Rate limit exceeded; retry later."},
                headers={"Retry-After": "17"},
            )
        ],
    )
    provider, _ = provider_factory()

    with pytest.raises(HTTPException) as excinfo:
        await provider.issue(make_principal(), "condor-mcp")

    assert excinfo.value.status_code == 429
    assert excinfo.value.headers == {"Retry-After": "17"}


async def test_issue_maps_network_errors_to_502(
    provider_factory, make_principal, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _FailingClient:
        async def post(self, *args: Any, **kwargs: Any) -> httpx.Response:
            raise httpx.ConnectError("boom")

    monkeypatch.setattr(condor_module, "get_http_client", _FailingClient)
    provider, _ = provider_factory()

    with pytest.raises(HTTPException) as excinfo:
        await provider.issue(make_principal(), "condor-mcp")

    assert excinfo.value.status_code == 502


async def test_issue_failure_does_not_cache(
    provider_factory, make_principal, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A failed exchange must not poison the cache -- the next call retries."""
    client = _install_client(
        monkeypatch,
        [
            httpx.Response(502, json={"detail": "Token minting failed."}),
            httpx.Response(200, json=_token_response()),
        ],
    )
    provider, _ = provider_factory()
    principal = make_principal(subject="sub-abc")

    with pytest.raises(HTTPException):
        await provider.issue(principal, "condor-mcp")
    cred = await provider.issue(principal, "condor-mcp")

    assert len(client.calls) == 2
    assert cred.payload["access_token"] == IDTOKEN


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------


async def test_issue_increments_issued_counter_only_on_actual_mints(
    provider_factory, make_principal, fake_client
) -> None:
    from af_mcp_broker import metrics

    provider, _ = provider_factory()
    counter = metrics.condor_tokens_issued_total.labels(target="condor-mcp")
    before = counter._value.get()

    await provider.issue(make_principal(subject="sub-abc"), "condor-mcp")
    # Second call is a cache hit -- must NOT count as an issuance.
    await provider.issue(make_principal(subject="sub-abc"), "condor-mcp")

    assert counter._value.get() == before + 1
