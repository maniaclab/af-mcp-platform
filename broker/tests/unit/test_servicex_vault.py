"""Tests for the Vault/OpenBao-backed ServiceX credential store (issue #295).

``VaultServiceXStore`` persists, per subject, a link half (refresh token,
durable) and a token half (last-redeemed access token + expiry, written on
every redeem) -- one KV-v2 record at ``{prefix}/{subject}/servicex`` over
the shared ``VaultKV`` transport, mirroring ``credentials/x509_vault.py``'s
``VaultX509Store``/``krb5_vault.py``'s ``Krb5VaultStore`` layout and CAS
conventions. A fake Vault HTTP API is built with ``httpx2.MockTransport``
(same harness shape as ``test_x509_vault.py``/``test_krb5_vault.py``).
"""

from __future__ import annotations

import asyncio
import time
from typing import TYPE_CHECKING

import pytest
from pydantic import SecretStr
from vault_fakes import FakeVault, make_vault_kv

from af_mcp_broker.credentials.servicex_vault import VaultServiceXStore

if TYPE_CHECKING:
    from pathlib import Path

KV_PATH_PREFIX = "mcp/servicex"

SUBJECT = "kc-subject-123"

_REFRESH_TOKEN = "a-servicex-refresh-token"
_ACCESS_TOKEN = "a-servicex-access-token"


@pytest.fixture
def fake_vault() -> FakeVault:
    return FakeVault(key_prefix=KV_PATH_PREFIX)


@pytest.fixture
def store(fake_vault: FakeVault, sa_token_path: Path) -> VaultServiceXStore:
    vault_kv = make_vault_kv(fake_vault, sa_token_path)
    return VaultServiceXStore(vault_kv=vault_kv, kv_path_prefix=KV_PATH_PREFIX)


async def _link(store: VaultServiceXStore, subject: str = SUBJECT) -> None:
    await store.store_link(subject, refresh_token=SecretStr(_REFRESH_TOKEN))


async def _store_token(
    store: VaultServiceXStore,
    subject: str = SUBJECT,
    *,
    remaining: float = 3600.0,
) -> float:
    expires_at = time.time() + remaining
    await store.store_token(subject, access_token=_ACCESS_TOKEN, expires_at=expires_at)
    return expires_at


# ---------------------------------------------------------------------------
# Link half: store_link / get_link / path layout
# ---------------------------------------------------------------------------


class TestLink:
    async def test_get_link_returns_none_when_never_linked(self, store) -> None:
        assert await store.get_link(SUBJECT) is None

    async def test_store_link_roundtrips_refresh_token(self, store) -> None:
        await _link(store)
        link = await store.get_link(SUBJECT)
        assert link is not None
        assert link.refresh_token is not None
        assert link.refresh_token.get_secret_value() == _REFRESH_TOKEN

    async def test_record_lives_at_prefix_subject_servicex(
        self, store, fake_vault
    ) -> None:
        await _link(store)
        assert f"{SUBJECT}/servicex" in fake_vault.entries

    async def test_relink_replaces_previous_refresh_token(self, store) -> None:
        await _link(store)
        await store.store_link(SUBJECT, refresh_token=SecretStr("new-token"))
        link = await store.get_link(SUBJECT)
        assert link is not None
        assert link.refresh_token is not None
        assert link.refresh_token.get_secret_value() == "new-token"

    async def test_relink_clears_previously_stored_token(self, store) -> None:
        await _link(store)
        await _store_token(store)
        await store.store_link(SUBJECT, refresh_token=SecretStr("new-token"))
        assert await store.get_token(SUBJECT) is None


# ---------------------------------------------------------------------------
# Token half: store_token / get_token
# ---------------------------------------------------------------------------


class TestToken:
    async def test_get_token_returns_none_when_never_stored(self, store) -> None:
        assert await store.get_token(SUBJECT) is None

    async def test_store_token_roundtrips(self, store) -> None:
        await _link(store)
        expires_at = await _store_token(store)
        record = await store.get_token(SUBJECT)
        assert record is not None
        assert record.access_token is not None
        assert record.access_token.get_secret_value() == _ACCESS_TOKEN
        assert record.expires_at == pytest.approx(expires_at)

    async def test_store_token_preserves_link_half(self, store) -> None:
        await _link(store)
        await _store_token(store)
        link = await store.get_link(SUBJECT)
        assert link is not None
        assert link.refresh_token is not None
        assert link.refresh_token.get_secret_value() == _REFRESH_TOKEN

    async def test_get_token_respects_min_remaining(self, store) -> None:
        await _link(store)
        await _store_token(store, remaining=100.0)
        assert await store.get_token(SUBJECT, min_remaining=50.0) is not None
        assert await store.get_token(SUBJECT, min_remaining=200.0) is None

    async def test_expired_token_reads_as_absent(self, store) -> None:
        await _link(store)
        await _store_token(store, remaining=-10.0)
        assert await store.get_token(SUBJECT) is None

    async def test_clear_token_removes_token_but_keeps_link(self, store) -> None:
        await _link(store)
        await _store_token(store)
        await store.clear_token(SUBJECT)
        assert await store.get_token(SUBJECT) is None
        link = await store.get_link(SUBJECT)
        assert link is not None
        assert link.refresh_token is not None

    async def test_clear_token_on_unlinked_subject_is_a_noop(self, store) -> None:
        await store.clear_token(SUBJECT)  # must not raise
        assert await store.get_link(SUBJECT) is None


# ---------------------------------------------------------------------------
# delete / unlink
# ---------------------------------------------------------------------------


class TestDelete:
    async def test_delete_removes_link_and_token(self, store) -> None:
        await _link(store)
        await _store_token(store)
        await store.delete(SUBJECT)
        assert await store.get_link(SUBJECT) is None
        assert await store.get_token(SUBJECT) is None

    async def test_delete_on_unlinked_subject_is_a_noop(self, store) -> None:
        await store.delete(SUBJECT)

        assert await store.get_link(SUBJECT) is None


# ---------------------------------------------------------------------------
# CAS conflict retry
# ---------------------------------------------------------------------------


class TestCasRetry:
    async def test_concurrent_store_token_calls_both_succeed(self, store) -> None:
        """CAS write-modify-read retries absorb a version race rather than propagating it."""
        await _link(store)
        await asyncio.gather(
            _store_token(store, remaining=100.0),
            _store_token(store, remaining=200.0),
        )
        record = await store.get_token(SUBJECT, min_remaining=0.0)
        assert record is not None
