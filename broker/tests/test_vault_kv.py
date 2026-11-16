"""Tests for ``VaultKV``, the shared Vault/OpenBao KV-v2 transport client.

A fake Vault HTTP API is built with ``httpx2.MockTransport`` -- no real Vault
process, no ``hvac``. Covers the Kubernetes auth login/re-auth flow (caching,
safety margin, single-flight lock) and the four KV verbs' error mapping,
independent of any consumer's path layout or record shape -- see
``test_oauth21_vault.py`` and ``test_token_registry.py`` for the consumers
built on top of this.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

import httpx2
import pytest
from vault_fakes import ADDR, AUTH_MOUNT, AUTH_ROLE, KV_MOUNT, FakeVault

from af_mcp_broker.vault_config import VaultConfig
from af_mcp_broker.vault_kv import (
    CasConflictError,
    VaultConnections,
    VaultError,
    VaultKV,
)

if TYPE_CHECKING:
    from pathlib import Path


PATH = "some/prefix/entry"


def _make_vault_kv(fake: FakeVault, sa_token_path: Path, **overrides: Any) -> VaultKV:
    kwargs: dict[str, Any] = {
        "addr": ADDR,
        "auth_mount": AUTH_MOUNT,
        "auth_role": AUTH_ROLE,
        "kv_mount": KV_MOUNT,
        "sa_token_path": str(sa_token_path),
        "http_client": httpx2.AsyncClient(transport=httpx2.MockTransport(fake.handle)),
    }
    kwargs.update(overrides)
    return VaultKV(**kwargs)


# ---------------------------------------------------------------------------
# K8s auth: login, caching, re-authentication
# ---------------------------------------------------------------------------


async def test_authenticate_reads_sa_jwt_and_logs_in(sa_token_path: Path) -> None:
    fake = FakeVault()
    vault_kv = _make_vault_kv(fake, sa_token_path)

    token = await vault_kv._authenticate()

    assert token == "vault-test-token"
    assert len(fake.login_calls) == 1
    assert fake.login_calls[0] == {"role": AUTH_ROLE, "jwt": "fake-sa-jwt"}


async def test_authenticate_caches_token_across_calls(sa_token_path: Path) -> None:
    fake = FakeVault()
    vault_kv = _make_vault_kv(fake, sa_token_path)

    await vault_kv._authenticate()
    await vault_kv._authenticate()

    assert len(fake.login_calls) == 1


async def test_authenticate_reauthenticates_when_near_expiry(
    sa_token_path: Path,
) -> None:
    fake = FakeVault()
    vault_kv = _make_vault_kv(fake, sa_token_path)

    await vault_kv._authenticate()
    assert len(fake.login_calls) == 1

    # Force the cached token to look like it's within the safety margin of
    # expiry (or already past it) without needing to sleep in the test.
    vault_kv._expires_at = datetime.now(UTC) - timedelta(seconds=1)

    await vault_kv._authenticate()
    assert len(fake.login_calls) == 2


async def test_authenticate_concurrent_callers_login_once(
    sa_token_path: Path,
) -> None:
    """The asyncio.Lock around re-authentication must prevent a login storm
    when multiple coroutines race to authenticate with no cached token yet.
    """
    fake = FakeVault()
    vault_kv = _make_vault_kv(fake, sa_token_path)

    await asyncio.gather(*(vault_kv._authenticate() for _ in range(5)))

    assert len(fake.login_calls) == 1


# ---------------------------------------------------------------------------
# get
# ---------------------------------------------------------------------------


async def test_get_returns_none_on_404(sa_token_path: Path) -> None:
    fake = FakeVault()
    vault_kv = _make_vault_kv(fake, sa_token_path)

    assert await vault_kv.get(PATH) is None


async def test_get_returns_data_and_version(sa_token_path: Path) -> None:
    fake = FakeVault()
    vault_kv = _make_vault_kv(fake, sa_token_path)
    await vault_kv.write_cas(PATH, {"foo": "bar"}, expected_version=None)

    got = await vault_kv.get(PATH)

    assert got is not None
    data, version = got
    assert data == {"foo": "bar"}
    assert version == 1


async def test_get_raises_vault_error_on_5xx(sa_token_path: Path) -> None:
    fake = FakeVault(kv_status=500)
    vault_kv = _make_vault_kv(fake, sa_token_path)

    with pytest.raises(VaultError, match="vault"):
        await vault_kv.get(PATH)


# ---------------------------------------------------------------------------
# write_cas() CAS semantics
# ---------------------------------------------------------------------------


async def test_write_cas_none_creates_when_missing(sa_token_path: Path) -> None:
    fake = FakeVault()
    vault_kv = _make_vault_kv(fake, sa_token_path)

    version = await vault_kv.write_cas(PATH, {"foo": "bar"}, expected_version=None)

    assert version == 1


async def test_write_cas_none_conflicts_when_existing(sa_token_path: Path) -> None:
    fake = FakeVault()
    vault_kv = _make_vault_kv(fake, sa_token_path)
    await vault_kv.write_cas(PATH, {"foo": "bar"}, expected_version=None)

    with pytest.raises(CasConflictError):
        await vault_kv.write_cas(PATH, {"foo": "baz"}, expected_version=None)


async def test_write_cas_with_matching_version_succeeds(sa_token_path: Path) -> None:
    fake = FakeVault()
    vault_kv = _make_vault_kv(fake, sa_token_path)
    await vault_kv.write_cas(PATH, {"foo": "bar"}, expected_version=None)  # v1

    version = await vault_kv.write_cas(PATH, {"foo": "baz"}, expected_version=1)

    assert version == 2


async def test_write_cas_with_stale_version_conflicts(sa_token_path: Path) -> None:
    fake = FakeVault()
    vault_kv = _make_vault_kv(fake, sa_token_path)
    await vault_kv.write_cas(PATH, {"foo": "bar"}, expected_version=None)  # v1
    await vault_kv.write_cas(PATH, {"foo": "baz"}, expected_version=1)  # v2

    with pytest.raises(CasConflictError):
        await vault_kv.write_cas(PATH, {"foo": "qux"}, expected_version=1)


async def test_write_cas_raises_vault_error_on_5xx(sa_token_path: Path) -> None:
    fake = FakeVault(kv_status=500)
    vault_kv = _make_vault_kv(fake, sa_token_path)

    with pytest.raises(VaultError, match="vault"):
        await vault_kv.write_cas(PATH, {"foo": "bar"}, expected_version=None)


# ---------------------------------------------------------------------------
# list
# ---------------------------------------------------------------------------


async def test_list_returns_empty_on_404(sa_token_path: Path) -> None:
    fake = FakeVault()
    vault_kv = _make_vault_kv(fake, sa_token_path)

    assert await vault_kv.list("some/prefix") == []


async def test_list_returns_child_keys(sa_token_path: Path) -> None:
    fake = FakeVault()
    vault_kv = _make_vault_kv(fake, sa_token_path)
    await vault_kv.write_cas("some/prefix/one", {}, expected_version=None)
    await vault_kv.write_cas("some/prefix/two", {}, expected_version=None)

    keys = await vault_kv.list("some/prefix")

    assert sorted(keys) == ["one", "two"]


async def test_list_raises_vault_error_on_5xx(sa_token_path: Path) -> None:
    fake = FakeVault(kv_status=500)
    vault_kv = _make_vault_kv(fake, sa_token_path)

    with pytest.raises(VaultError, match="vault"):
        await vault_kv.list("some/prefix")


# ---------------------------------------------------------------------------
# delete_metadata
# ---------------------------------------------------------------------------


async def test_delete_metadata_existing_then_get_returns_none(
    sa_token_path: Path,
) -> None:
    fake = FakeVault()
    vault_kv = _make_vault_kv(fake, sa_token_path)
    await vault_kv.write_cas(PATH, {"foo": "bar"}, expected_version=None)

    await vault_kv.delete_metadata(PATH)

    assert await vault_kv.get(PATH) is None


async def test_delete_metadata_then_write_cas_none_succeeds_again(
    sa_token_path: Path,
) -> None:
    """The metadata-endpoint delete must fully reset the version counter, or
    a subsequent create (``expected_version=None`` -> ``cas=0``) would fail
    forever against Vault's soft-delete semantics.
    """
    fake = FakeVault()
    vault_kv = _make_vault_kv(fake, sa_token_path)
    await vault_kv.write_cas(PATH, {"foo": "bar"}, expected_version=None)
    await vault_kv.delete_metadata(PATH)

    version = await vault_kv.write_cas(PATH, {"foo": "bar"}, expected_version=None)

    assert version == 1


async def test_delete_metadata_nonexistent_is_idempotent(sa_token_path: Path) -> None:
    fake = FakeVault()
    vault_kv = _make_vault_kv(fake, sa_token_path)

    await vault_kv.delete_metadata(PATH)

    assert await vault_kv.get(PATH) is None
    assert fake.entries == {}


async def test_delete_metadata_raises_vault_error_on_5xx(sa_token_path: Path) -> None:
    fake = FakeVault(kv_status=500)
    vault_kv = _make_vault_kv(fake, sa_token_path)

    with pytest.raises(VaultError, match="vault"):
        await vault_kv.delete_metadata(PATH)


def _vault_config(**overrides: Any) -> VaultConfig:
    fields: dict[str, Any] = {
        "addr": ADDR,
        "auth_mount": AUTH_MOUNT,
        "auth_role": AUTH_ROLE,
        "kv_mount": KV_MOUNT,
        "sa_token_path": "/sa/token",
    }
    return VaultConfig(**{**fields, **overrides})


def test_connections_share_one_client_per_vault_config() -> None:
    connections = VaultConnections(httpx2.AsyncClient())

    assert connections.connect(_vault_config()) is connections.connect(_vault_config())


def test_connections_keep_distinct_vaults_apart() -> None:
    connections = VaultConnections(httpx2.AsyncClient())

    first = connections.connect(_vault_config())
    second = connections.connect(_vault_config(kv_mount="other"))

    assert first is not second
