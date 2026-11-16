"""Tests for the Vault-backed ``TokenStore`` (issue #66 PR3).

A fake Vault HTTP API is built with ``httpx2.MockTransport`` -- no real Vault
process, no ``hvac``. Covers KV-v2 CAS read/write/delete semantics, the
``SecretStr`` round trip through storage, and error mapping. The
Kubernetes auth login/re-auth flow this store's ``VaultKV`` uses is covered
by ``test_vault_kv.py`` instead -- that behavior lives in
``VaultKV``, not ``VaultTokenStore`` itself.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

import pytest
from pydantic import SecretStr
from vault_fakes import FakeVault, make_vault_kv

from af_mcp_broker.credentials.errors import VersionConflictError
from af_mcp_broker.credentials.oauth21 import StoredOAuthCredential
from af_mcp_broker.credentials.vault import VaultTokenStore
from af_mcp_broker.vault_kv import VaultError

if TYPE_CHECKING:
    from pathlib import Path

KV_PATH_PREFIX = "mcp/tokens"

SUBJECT = "kc-subject-123"
ALIAS = "rucio-mcp-atlas"


def _make_cred(**overrides: Any) -> StoredOAuthCredential:
    now = datetime.now(UTC)
    defaults: dict[str, Any] = {
        "alias": ALIAS,
        "subject": SUBJECT,
        "access_token": SecretStr("access-token-1"),
        "refresh_token": SecretStr("refresh-token-1"),
        "expires_at": now + timedelta(hours=1),
        "refresh_expires_at": now + timedelta(days=30),
        "scope": ["openid", "profile"],
        "issuer": "https://backend-as.example",
        "token_endpoint": "https://backend-as.example/token",
    }
    defaults.update(overrides)
    return StoredOAuthCredential(**defaults)


def _make_store(fake: FakeVault, sa_token_path: Path) -> VaultTokenStore:
    vault_kv = make_vault_kv(fake, sa_token_path)
    return VaultTokenStore(vault_kv=vault_kv, kv_path_prefix=KV_PATH_PREFIX)


@pytest.fixture(autouse=True)
def _broker_signing_key(
    monkeypatch: pytest.MonkeyPatch, broker_signing_key_file: Path
) -> None:
    """The shipped "ami" service (covered by the x509 entry below) needs the broker signing key to boot."""
    monkeypatch.setenv("BROKER_SIGNING_KEY_FILE", str(broker_signing_key_file))
    monkeypatch.setenv("BROKER_PUBLIC_ORIGIN", "https://mcp.example.com")


# ---------------------------------------------------------------------------
# get
# ---------------------------------------------------------------------------


async def test_get_returns_none_on_404(sa_token_path: Path) -> None:
    fake = FakeVault(key_prefix=KV_PATH_PREFIX)
    store = _make_store(fake, sa_token_path)

    assert await store.get(SUBJECT, ALIAS) is None


async def test_get_round_trips_secret_str_values(sa_token_path: Path) -> None:
    fake = FakeVault(key_prefix=KV_PATH_PREFIX)
    store = _make_store(fake, sa_token_path)
    cred = _make_cred()

    await store.write_cas(SUBJECT, ALIAS, cred, expected_version=None)
    got = await store.get(SUBJECT, ALIAS)

    assert got is not None
    got_cred, version = got
    assert version == 1
    assert got_cred.access_token.get_secret_value() == "access-token-1"
    assert got_cred.refresh_token is not None
    assert got_cred.refresh_token.get_secret_value() == "refresh-token-1"
    assert got_cred.alias == ALIAS
    assert got_cred.subject == SUBJECT

    # The wire payload must never carry pydantic's masked SecretStr rendering.
    stored_data = fake.entries[f"{SUBJECT}/{ALIAS}"]["data"]
    assert stored_data["access_token"] == "access-token-1"
    assert stored_data["refresh_token"] == "refresh-token-1"


async def test_get_round_trips_credential_without_expiry(sa_token_path: Path) -> None:
    fake = FakeVault(key_prefix=KV_PATH_PREFIX)
    store = _make_store(fake, sa_token_path)

    await store.write_cas(
        SUBJECT,
        ALIAS,
        _make_cred(refresh_token=None, expires_at=None, refresh_expires_at=None),
        expected_version=None,
    )
    got = await store.get(SUBJECT, ALIAS)

    assert got is not None
    assert got[0].expires_at is None


async def test_get_reads_a_record_stored_without_rejected_at(
    sa_token_path: Path,
) -> None:
    """Records linked before ``rejected_at`` existed must still load, as not
    rejected -- otherwise every existing link would break on upgrade."""
    fake = FakeVault(key_prefix=KV_PATH_PREFIX)
    store = _make_store(fake, sa_token_path)
    await store.write_cas(SUBJECT, ALIAS, _make_cred(), expected_version=None)
    fake.entries[f"{SUBJECT}/{ALIAS}"]["data"].pop("rejected_at")

    got = await store.get(SUBJECT, ALIAS)

    assert got is not None
    assert got[0].rejected_at is None


# ---------------------------------------------------------------------------
# write_cas() CAS semantics
# ---------------------------------------------------------------------------


async def test_write_cas_none_creates_when_missing(sa_token_path: Path) -> None:
    fake = FakeVault(key_prefix=KV_PATH_PREFIX)
    store = _make_store(fake, sa_token_path)

    version = await store.write_cas(SUBJECT, ALIAS, _make_cred(), expected_version=None)

    assert version == 1


async def test_write_cas_none_conflicts_when_existing(sa_token_path: Path) -> None:
    fake = FakeVault(key_prefix=KV_PATH_PREFIX)
    store = _make_store(fake, sa_token_path)
    await store.write_cas(SUBJECT, ALIAS, _make_cred(), expected_version=None)

    with pytest.raises(VersionConflictError):
        await store.write_cas(SUBJECT, ALIAS, _make_cred(), expected_version=None)


async def test_write_cas_with_matching_version_succeeds(sa_token_path: Path) -> None:
    fake = FakeVault(key_prefix=KV_PATH_PREFIX)
    store = _make_store(fake, sa_token_path)
    await store.write_cas(SUBJECT, ALIAS, _make_cred(), expected_version=None)  # v1

    version = await store.write_cas(
        SUBJECT,
        ALIAS,
        _make_cred(access_token=SecretStr("access-token-2")),
        expected_version=1,
    )

    assert version == 2


async def test_write_cas_with_stale_version_conflicts(sa_token_path: Path) -> None:
    fake = FakeVault(key_prefix=KV_PATH_PREFIX)
    store = _make_store(fake, sa_token_path)
    await store.write_cas(SUBJECT, ALIAS, _make_cred(), expected_version=None)  # v1
    await store.write_cas(SUBJECT, ALIAS, _make_cred(), expected_version=1)  # v2

    with pytest.raises(VersionConflictError):
        await store.write_cas(SUBJECT, ALIAS, _make_cred(), expected_version=1)


# ---------------------------------------------------------------------------
# delete
# ---------------------------------------------------------------------------


async def test_delete_existing_then_get_returns_none(sa_token_path: Path) -> None:
    fake = FakeVault(key_prefix=KV_PATH_PREFIX)
    store = _make_store(fake, sa_token_path)
    await store.write_cas(SUBJECT, ALIAS, _make_cred(), expected_version=None)

    await store.delete(SUBJECT, ALIAS)

    assert await store.get(SUBJECT, ALIAS) is None


async def test_delete_then_write_cas_none_succeeds_again(sa_token_path: Path) -> None:
    """The metadata-endpoint delete must fully reset the version counter, or
    a subsequent create (``expected_version=None`` -> ``cas=0``) would fail
    forever against Vault's soft-delete semantics.
    """
    fake = FakeVault(key_prefix=KV_PATH_PREFIX)
    store = _make_store(fake, sa_token_path)
    await store.write_cas(SUBJECT, ALIAS, _make_cred(), expected_version=None)
    await store.delete(SUBJECT, ALIAS)

    version = await store.write_cas(SUBJECT, ALIAS, _make_cred(), expected_version=None)

    assert version == 1


async def test_delete_nonexistent_is_idempotent(sa_token_path: Path) -> None:
    fake = FakeVault(key_prefix=KV_PATH_PREFIX)
    store = _make_store(fake, sa_token_path)

    await store.delete(SUBJECT, ALIAS)

    assert await store.get(SUBJECT, ALIAS) is None
    assert fake.entries == {}


# ---------------------------------------------------------------------------
# Error mapping
# ---------------------------------------------------------------------------


async def test_get_raises_vault_error_on_5xx(sa_token_path: Path) -> None:
    fake = FakeVault(key_prefix=KV_PATH_PREFIX, kv_status=500)
    store = _make_store(fake, sa_token_path)

    with pytest.raises(VaultError, match="vault"):
        await store.get(SUBJECT, ALIAS)


async def test_write_cas_raises_vault_error_on_5xx(sa_token_path: Path) -> None:
    fake = FakeVault(key_prefix=KV_PATH_PREFIX, kv_status=500)
    store = _make_store(fake, sa_token_path)

    with pytest.raises(VaultError, match="vault"):
        await store.write_cas(SUBJECT, ALIAS, _make_cred(), expected_version=None)


async def test_delete_raises_vault_error_on_5xx(sa_token_path: Path) -> None:
    fake = FakeVault(key_prefix=KV_PATH_PREFIX, kv_status=500)
    store = _make_store(fake, sa_token_path)

    with pytest.raises(VaultError, match="vault"):
        await store.delete(SUBJECT, ALIAS)
