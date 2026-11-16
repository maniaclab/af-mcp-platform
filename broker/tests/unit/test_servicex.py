"""Tests for ``ServiceXProvider`` (issue #295).

When constructed with a ``ServiceXTokenServiceClient`` and a
``VaultServiceXStore``, the provider redeems via the service and persists
everything in Vault: ``link()`` verifies with one redeem before storing the
refresh token + access token, ``is_linked()`` asks Vault, ``issue()`` serves
the Vault access token and — when it's expired or near expiry — REDEEMS
hands-free with the stored refresh token. A bad-refresh-token failure on
redeem unlinks and surfaces ``NeedsUnlockError`` so the portal prompts a
re-paste; infra failures do neither. Unlike ``X509Provider`` there is no
POSIX-dependent path and no POSIX identity requirement at all -- every principal,
linked or not, is eligible.

The Vault store here is a lightweight in-memory fake implementing the
``VaultServiceXStore`` API (its Vault wire behavior is covered by
test_servicex_vault.py); the servicex-token-service client is a recording
fake with a scriptable outcome.
"""

from __future__ import annotations

import asyncio
import time

import pytest
from pydantic import SecretStr
from servicex_support import (
    _ACCESS_TOKEN,
    FakeServiceXClient,
    FakeServiceXStore,
)

from af_mcp_broker.credentials.base import CredentialKind
from af_mcp_broker.credentials.cache import CredentialCache
from af_mcp_broker.credentials.errors import (
    NeedsUnlockError,
    ServiceXBadRefreshTokenError,
    ServiceXServiceMintError,
)
from af_mcp_broker.credentials.servicex import ServiceXProvider
from af_mcp_broker.principal import Principal

_REFRESH_TOKEN = "stored-refresh-token"


def _make_provider(
    servicex_client: FakeServiceXClient | None = None,
    store: FakeServiceXStore | None = None,
    cache: CredentialCache | None = None,
) -> tuple[ServiceXProvider, FakeServiceXClient, FakeServiceXStore, CredentialCache]:
    servicex_client = (
        servicex_client if servicex_client is not None else FakeServiceXClient()
    )
    store = store if store is not None else FakeServiceXStore()
    cache = cache if cache is not None else CredentialCache()
    provider = ServiceXProvider(
        servicex_client=servicex_client,  # type: ignore[arg-type]
        vault_store=store,  # type: ignore[arg-type]
        cache=cache,
    )
    return provider, servicex_client, store, cache


async def _seed_link(store: FakeServiceXStore, subject: str = "user-123") -> None:
    await store.store_link(subject, refresh_token=SecretStr(_REFRESH_TOKEN))


def _principal(subject: str = "user-123") -> Principal:
    return Principal(
        subject=subject,
        email="user@example.org",
        uid=None,
        gid=None,
        unixname=None,
        groups=["af-atlas-users"],
        raw_token=SecretStr("fake-token"),
    )


# ---------------------------------------------------------------------------
# is_linked
# ---------------------------------------------------------------------------


class TestIsLinked:
    async def test_true_when_vault_holds_a_link(self) -> None:
        provider, _, store, _ = _make_provider()
        await _seed_link(store)
        assert await provider.is_linked(_principal()) is True

    async def test_false_when_vault_has_no_link(self) -> None:
        provider, _, _, _ = _make_provider()
        assert await provider.is_linked(_principal()) is False


# ---------------------------------------------------------------------------
# link
# ---------------------------------------------------------------------------


class TestLinkFlow:
    async def test_redeems_via_service_and_stores_link_and_token(self) -> None:
        provider, servicex_client, store, _ = _make_provider()

        await provider.link("user-123", SecretStr(_REFRESH_TOKEN))

        assert len(servicex_client.calls) == 1
        link = await store.get_link("user-123")
        assert link is not None
        assert link.refresh_token is not None
        assert link.refresh_token.get_secret_value() == _REFRESH_TOKEN
        token = await store.get_token("user-123")
        assert token is not None
        assert token.access_token is not None
        assert token.access_token.get_secret_value() == _ACCESS_TOKEN

    async def test_bad_refresh_token_stores_nothing(self) -> None:
        provider, _, store, _ = _make_provider(
            servicex_client=FakeServiceXClient(ServiceXBadRefreshTokenError())
        )

        with pytest.raises(ServiceXBadRefreshTokenError):
            await provider.link("user-123", SecretStr("bad-token"))

        assert await store.get_link("user-123") is None

    async def test_infra_failure_stores_nothing(self) -> None:
        provider, _, store, _ = _make_provider(
            servicex_client=FakeServiceXClient(ServiceXServiceMintError("down"))
        )

        with pytest.raises(ServiceXServiceMintError):
            await provider.link("user-123", SecretStr(_REFRESH_TOKEN))

        assert await store.get_link("user-123") is None

    async def test_relink_replaces_stored_refresh_token(self) -> None:
        provider, _, store, _ = _make_provider()
        await provider.link("user-123", SecretStr(_REFRESH_TOKEN))

        await provider.link("user-123", SecretStr("new-token"))

        link = await store.get_link("user-123")
        assert link is not None
        assert link.refresh_token is not None
        assert link.refresh_token.get_secret_value() == "new-token"

    async def test_concurrent_issue_calls_single_flight_one_service_redeem(
        self,
    ) -> None:
        """N concurrent issue() calls hitting an expired stored token must
        produce exactly one service redeem (issue #94's pattern)."""
        servicex_client = FakeServiceXClient(delay=0.01)
        provider, _, store, _ = _make_provider(servicex_client=servicex_client)
        await _seed_link(store)
        await store.store_token(
            "user-123", access_token="OLD", expires_at=time.time() - 10
        )

        results = await asyncio.gather(
            *[provider.issue(_principal(), "servicex") for _ in range(5)]
        )

        assert len(servicex_client.calls) == 1
        assert all(r.payload["delivery"] == "redeem" for r in results)


# ---------------------------------------------------------------------------
# issue(): stored token / hands-free renewal
# ---------------------------------------------------------------------------


class TestStoredTokenAndRenewal:
    async def test_valid_vault_token_is_served_without_calling_the_service(
        self,
    ) -> None:
        provider, servicex_client, store, _ = _make_provider()
        await _seed_link(store)
        await store.store_token(
            "user-123", access_token=_ACCESS_TOKEN, expires_at=time.time() + 3600
        )

        cred = await provider.issue(_principal(), "servicex")

        assert servicex_client.calls == []
        assert cred.kind == CredentialKind.SERVICEX_ACCESS_TOKEN_REDEEM
        assert cred.payload == {"delivery": "redeem"}

    async def test_expired_token_with_stored_link_renews_hands_free(self) -> None:
        provider, servicex_client, store, _ = _make_provider()
        await _seed_link(store)
        await store.store_token(
            "user-123", access_token="OLD", expires_at=time.time() - 10
        )

        cred = await provider.issue(_principal(), "servicex")

        assert len(servicex_client.calls) == 1
        call = servicex_client.calls[0]
        assert call["subject"] == "user-123"
        assert call["refresh_token"].get_secret_value() == _REFRESH_TOKEN
        record = await store.get_token("user-123")
        assert record is not None
        assert record.access_token is not None
        assert record.access_token.get_secret_value() == _ACCESS_TOKEN
        assert cred.kind == CredentialKind.SERVICEX_ACCESS_TOKEN_REDEEM

    async def test_renewal_bad_refresh_token_unlinks_and_raises_needs_unlock(
        self,
    ) -> None:
        """The refresh token was revoked/expired: the stored value is dead
        weight. Unlink so the portal prompts a re-paste."""
        provider, _, store, _ = _make_provider(
            servicex_client=FakeServiceXClient(ServiceXBadRefreshTokenError())
        )
        await _seed_link(store)

        with pytest.raises(NeedsUnlockError):
            await provider.issue(_principal(), "servicex")

        assert store.deleted == ["user-123"]
        assert await store.get_link("user-123") is None

    async def test_renewal_infra_failure_neither_unlinks_nor_needs_unlock(
        self,
    ) -> None:
        provider, _, store, _ = _make_provider(
            servicex_client=FakeServiceXClient(ServiceXServiceMintError("down"))
        )
        await _seed_link(store)

        with pytest.raises(ServiceXServiceMintError):
            await provider.issue(_principal(), "servicex")

        assert store.deleted == []
        assert await store.get_link("user-123") is not None

    async def test_no_link_raises_needs_unlock(self) -> None:
        provider, servicex_client, _, _ = _make_provider()

        with pytest.raises(NeedsUnlockError) as excinfo:
            await provider.issue(_principal(), "servicex")

        assert excinfo.value.unlock_endpoint == "/v1/servicex/link"
        assert servicex_client.calls == []

    async def test_second_issue_hits_the_in_memory_vault_record(self) -> None:
        provider, servicex_client, _, _ = _make_provider()
        await provider.link("user-123", SecretStr(_REFRESH_TOKEN))

        cred = await provider.issue(_principal(), "servicex")

        assert len(servicex_client.calls) == 1  # only the link() redeem
        assert cred.kind == CredentialKind.SERVICEX_ACCESS_TOKEN_REDEEM


# ---------------------------------------------------------------------------
# redeem_from_link (backend-token subject path, no live Principal)
# ---------------------------------------------------------------------------


class TestRedeemFromLink:
    async def test_no_link_raises_needs_unlock(self) -> None:
        provider, _, _, _ = _make_provider()

        with pytest.raises(NeedsUnlockError) as excinfo:
            await provider.redeem_from_link("user-123", "servicex")

        assert excinfo.value.reason == "not_linked"

    async def test_bad_refresh_token_unlinks_and_raises_needs_unlock(self) -> None:
        provider, _, store, _ = _make_provider(
            servicex_client=FakeServiceXClient(ServiceXBadRefreshTokenError())
        )
        await _seed_link(store)

        with pytest.raises(NeedsUnlockError) as excinfo:
            await provider.redeem_from_link("user-123", "servicex")

        assert excinfo.value.reason == "stored_refresh_token_rejected"
        assert store.deleted == ["user-123"]


# ---------------------------------------------------------------------------
# revoke
# ---------------------------------------------------------------------------


class TestRevoke:
    async def test_revoke_clears_token_but_keeps_link(self) -> None:
        provider, _, store, _ = _make_provider()
        await provider.link("user-123", SecretStr(_REFRESH_TOKEN))

        await provider.revoke(_principal(), "servicex")

        assert await store.get_token("user-123") is None
        assert await store.get_link("user-123") is not None


# ---------------------------------------------------------------------------
# unlink
# ---------------------------------------------------------------------------


class TestUnlink:
    async def test_unlink_deletes_link_and_token(self) -> None:
        provider, _, store, _ = _make_provider()
        await provider.link("user-123", SecretStr(_REFRESH_TOKEN))

        await provider.unlink(_principal())

        assert store.deleted == ["user-123"]
        assert await store.get_link("user-123") is None
        assert await store.get_token("user-123") is None
