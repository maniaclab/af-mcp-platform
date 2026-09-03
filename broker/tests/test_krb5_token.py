"""Unit tests for KrbTokenProvider (issue #274).

Covers caching, is_linked() reflecting live cache state (no persisted
linkage exists otherwise), and NeedsUnlock when no fresh username/password
is supplied. The krb5-token-service HTTP exchange itself is covered by
test_krb5_service_client.py -- here the client is a fake double.
"""

from __future__ import annotations

import asyncio
import time

import pytest
from prometheus_client import REGISTRY
from pydantic import SecretBytes, SecretStr

from af_mcp_broker.credentials.base import CredentialKind, NeedsUnlock
from af_mcp_broker.credentials.cache import CredentialCache
from af_mcp_broker.credentials.krb5 import KrbTokenProvider
from af_mcp_broker.credentials.krb5_service import (
    Krb5TokenBadCredentialError,
    MintedTicket,
)
from af_mcp_broker.identity import Principal


def make_principal(subject: str = "user1") -> Principal:
    return Principal(
        subject=subject,
        email="user1@example.org",
        groups=[],
        unixname=None,
        uid=None,
        gid=None,
        raw_token=SecretStr(""),
    )


class _FakeClient:
    def __init__(
        self, ticket: MintedTicket | None = None, error: Exception | None = None
    ):
        self._ticket = ticket
        self._error = error
        self.calls: list[dict] = []

    async def mint(
        self, *, subject, username, password, lifetime=None, renewable_lifetime=None
    ):
        self.calls.append(
            {
                "subject": subject,
                "username": username,
                "password": password.get_secret_value(),
                "lifetime": lifetime,
                "renewable_lifetime": renewable_lifetime,
            }
        )
        if self._error is not None:
            raise self._error
        assert self._ticket is not None
        return self._ticket


def provider_factory(client, targets=("krb5-target",)):
    cache = CredentialCache()
    provider = KrbTokenProvider(
        client=client, cache=cache, alias="krb5", targets=frozenset(targets)
    )
    return provider, cache


def _ticket(not_after=None) -> MintedTicket:
    return MintedTicket(
        ccache_b64="ZmFrZQ==",
        principal="alice@CERN.CH",
        realm="CERN.CH",
        not_after=not_after if not_after is not None else time.time() + 3600,
        renew_until=None,
    )


async def test_issue_without_credentials_raises_needs_unlock():
    provider, _ = provider_factory(_FakeClient())
    with pytest.raises(NeedsUnlock) as exc_info:
        await provider.issue(make_principal(), "krb5-target")
    assert exc_info.value.unlock_endpoint == "/v1/krb5/ticket"


async def test_issue_with_credentials_mints_and_caches():
    client = _FakeClient(ticket=_ticket())
    provider, cache = provider_factory(client)
    principal = make_principal()
    cred = await provider.issue(
        principal,
        "krb5-target",
        passphrase=SecretBytes(b"hunter2"),
        username="alice",
    )
    assert cred.cred_class == "krb5_ticket"
    assert cred.kind == CredentialKind.KRB5_CCACHE
    assert cred.payload["ccache_b64"] == "ZmFrZQ=="
    assert cred.payload["principal"] == "alice@CERN.CH"
    assert client.calls[0]["username"] == "alice"
    assert client.calls[0]["password"] == "hunter2"

    cached = await cache.get(principal.subject, "krb5-target", min_remaining=0)
    assert cached is not None


async def test_issue_returns_cached_credential_without_recontacting_service():
    client = _FakeClient(ticket=_ticket())
    provider, _ = provider_factory(client)
    principal = make_principal()
    await provider.issue(
        principal, "krb5-target", passphrase=SecretBytes(b"hunter2"), username="alice"
    )
    # Second call within validity, no credentials supplied -- must hit cache.
    cred = await provider.issue(principal, "krb5-target")
    assert cred.payload["ccache_b64"] == "ZmFrZQ=="
    assert len(client.calls) == 1


async def test_is_linked_false_with_no_cached_ticket():
    provider, _ = provider_factory(_FakeClient())
    assert await provider.is_linked(make_principal()) is False


async def test_is_linked_true_after_mint():
    client = _FakeClient(ticket=_ticket())
    provider, _ = provider_factory(client)
    principal = make_principal()
    await provider.issue(
        principal, "krb5-target", passphrase=SecretBytes(b"hunter2"), username="alice"
    )
    assert await provider.is_linked(principal) is True


async def test_revoke_drops_cached_ticket():
    client = _FakeClient(ticket=_ticket())
    provider, cache = provider_factory(client)
    principal = make_principal()
    await provider.issue(
        principal, "krb5-target", passphrase=SecretBytes(b"hunter2"), username="alice"
    )
    await provider.revoke(principal, "krb5-target")
    assert await cache.get(principal.subject, "krb5-target", min_remaining=0) is None


async def test_is_linked_true_when_only_one_of_multiple_targets_has_a_ticket():
    """``is_linked()`` loops over all of this entry's configured targets with
    ``any()``, not ``all()`` -- a ticket cached for just one of them must
    still report linked."""
    client = _FakeClient(ticket=_ticket())
    provider, _ = provider_factory(client, targets=("krb5-target-a", "krb5-target-b"))
    principal = make_principal()
    await provider.issue(
        principal,
        "krb5-target-a",
        passphrase=SecretBytes(b"hunter2"),
        username="alice",
    )

    assert await provider.is_linked(principal) is True


async def test_is_linked_does_not_affect_cache_metrics():
    """``is_linked()`` is a live cache-state probe, not a credential-serving
    lookup -- it must not move ``af_mcp_credential_cache_hits_total``/
    ``..._misses_total`` (see ``CredentialCache.peek()``)."""
    client = _FakeClient(ticket=_ticket())
    provider, _ = provider_factory(client)
    principal = make_principal()
    await provider.issue(
        principal, "krb5-target", passphrase=SecretBytes(b"hunter2"), username="alice"
    )

    def _sample(name: str) -> float:
        return REGISTRY.get_sample_value(name, {"target": "krb5-target"}) or 0.0

    before_hits = _sample("af_mcp_credential_cache_hits_total")
    before_misses = _sample("af_mcp_credential_cache_misses_total")

    for _ in range(3):
        assert await provider.is_linked(principal) is True

    assert _sample("af_mcp_credential_cache_hits_total") == before_hits
    assert _sample("af_mcp_credential_cache_misses_total") == before_misses


async def test_issue_mint_failure_propagates_and_does_not_cache():
    """A failed mint must propagate uncaught, and must not poison the cache
    -- mirrors test_condor_token.py's equivalent service-failure coverage."""
    client = _FakeClient(error=Krb5TokenBadCredentialError())
    provider, cache = provider_factory(client)
    principal = make_principal()

    with pytest.raises(Krb5TokenBadCredentialError):
        await provider.issue(
            principal,
            "krb5-target",
            passphrase=SecretBytes(b"hunter2"),
            username="alice",
        )

    assert await cache.get(principal.subject, "krb5-target", min_remaining=0) is None


async def test_issue_single_flights_concurrent_misses():
    """N concurrent issue() calls for the same (subject, target) must cost
    exactly one krb5-token-service mint call (issue #94's pattern, mirrored
    from test_condor_token.py's test_issue_single_flights_concurrent_misses)."""

    class _SlowClient(_FakeClient):
        async def mint(self, **kwargs):
            # Force a real suspension so concurrent callers actually overlap.
            await asyncio.sleep(0.01)
            return await super().mint(**kwargs)

    client = _SlowClient(ticket=_ticket())
    provider, _ = provider_factory(client)
    principal = make_principal()

    results = await asyncio.gather(
        *[
            provider.issue(
                principal,
                "krb5-target",
                passphrase=SecretBytes(b"hunter2"),
                username="alice",
            )
            for _ in range(5)
        ]
    )

    assert len(client.calls) == 1
    assert all(r.payload["ccache_b64"] == "ZmFrZQ==" for r in results)
