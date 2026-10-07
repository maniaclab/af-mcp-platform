"""Tests for the credmon's Vault-backed pieces: subject enumeration (``VaultSubjectSource``).

Every per-user credential store keys records at ``{prefix}/{subject}/{kind}``
(credentials/x509_vault.py, krb5_vault.py, servicex_vault.py), so a KV LIST
of ``{prefix}`` enumerates the subjects that may hold that kind.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from _credmon_fake_vault import FakeVault, make_vault_kv

from af_mcp_broker.credmon.vault import VaultCredmonSyncState, VaultSubjectSource

if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture
def fake_vault() -> FakeVault:
    return FakeVault()


async def test_lists_subjects_holding_a_record_of_the_kind(
    fake_vault: FakeVault, tmp_path: Path
) -> None:
    fake_vault.entries["mcp/krb5/sub-a/krb5"] = {"data": {}, "version": 1}
    fake_vault.entries["mcp/krb5/sub-b/krb5"] = {"data": {}, "version": 1}
    source = VaultSubjectSource(
        make_vault_kv(fake_vault, tmp_path), prefixes={"krb5": "mcp/krb5"}
    )

    assert sorted(await source.list_subjects("krb5")) == ["sub-a", "sub-b"]


async def test_kind_with_no_records_lists_nothing(
    fake_vault: FakeVault, tmp_path: Path
) -> None:
    source = VaultSubjectSource(
        make_vault_kv(fake_vault, tmp_path), prefixes={"krb5": "mcp/krb5"}
    )

    assert await source.list_subjects("krb5") == []


async def test_unconfigured_kind_lists_nothing(
    fake_vault: FakeVault, tmp_path: Path
) -> None:
    """x509 in legacy (k8s-Job) mode has no Vault store -- nothing to enumerate."""
    fake_vault.entries["mcp/krb5/sub-a/krb5"] = {"data": {}, "version": 1}
    source = VaultSubjectSource(
        make_vault_kv(fake_vault, tmp_path), prefixes={"krb5": "mcp/krb5"}
    )

    assert await source.list_subjects("x509") == []


async def test_ignores_leaf_keys_directly_under_the_prefix(
    fake_vault: FakeVault, tmp_path: Path
) -> None:
    """Only ``{subject}/`` folders are subjects; a stray leaf key is not."""
    fake_vault.entries["mcp/krb5/stray"] = {"data": {}, "version": 1}
    fake_vault.entries["mcp/krb5/sub-a/krb5"] = {"data": {}, "version": 1}
    source = VaultSubjectSource(
        make_vault_kv(fake_vault, tmp_path), prefixes={"krb5": "mcp/krb5"}
    )

    assert await source.list_subjects("krb5") == ["sub-a"]


# ---------------------------------------------------------------------------
# VaultCredmonSyncState: the cross-replica lease + last-run status record
# ---------------------------------------------------------------------------


def _state(fake_vault: FakeVault, tmp_path: Path) -> VaultCredmonSyncState:
    return VaultCredmonSyncState(
        make_vault_kv(fake_vault, tmp_path), kv_path_prefix="mcp/credmon"
    )


async def test_lease_is_granted_when_nobody_holds_it(
    fake_vault: FakeVault, tmp_path: Path
) -> None:
    state = _state(fake_vault, tmp_path)

    assert await state.try_acquire_lease("pod-a", ttl_seconds=60, now=1000.0)
    assert fake_vault.entries["mcp/credmon/lease"]["data"]["holder"] == "pod-a"


async def test_lease_is_refused_while_another_holder_is_unexpired(
    fake_vault: FakeVault, tmp_path: Path
) -> None:
    state = _state(fake_vault, tmp_path)
    await state.try_acquire_lease("pod-a", ttl_seconds=60, now=1000.0)

    assert not await state.try_acquire_lease("pod-b", ttl_seconds=60, now=1030.0)


async def test_expired_lease_can_be_taken_over(
    fake_vault: FakeVault, tmp_path: Path
) -> None:
    state = _state(fake_vault, tmp_path)
    await state.try_acquire_lease("pod-a", ttl_seconds=60, now=1000.0)

    assert await state.try_acquire_lease("pod-b", ttl_seconds=60, now=1061.0)
    assert fake_vault.entries["mcp/credmon/lease"]["data"]["holder"] == "pod-b"


async def test_holder_can_renew_its_own_lease(
    fake_vault: FakeVault, tmp_path: Path
) -> None:
    state = _state(fake_vault, tmp_path)
    await state.try_acquire_lease("pod-a", ttl_seconds=60, now=1000.0)

    assert await state.try_acquire_lease("pod-a", ttl_seconds=60, now=1030.0)


async def test_concurrent_acquire_loses_on_cas_conflict(
    fake_vault: FakeVault, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Two replicas read the same free lease; only the first CAS write wins."""
    state_a = _state(fake_vault, tmp_path)
    state_b = _state(fake_vault, tmp_path)
    original_get = state_b._vault_kv.get

    async def _get_then_race(path: str):  # type: ignore[no-untyped-def]
        result = await original_get(path)
        # pod-a sneaks its write in between pod-b's read and write.
        await state_a.try_acquire_lease("pod-a", ttl_seconds=60, now=1000.0)
        return result

    monkeypatch.setattr(state_b._vault_kv, "get", _get_then_race)

    assert not await state_b.try_acquire_lease("pod-b", ttl_seconds=60, now=1000.0)
    assert fake_vault.entries["mcp/credmon/lease"]["data"]["holder"] == "pod-a"


async def test_status_round_trips(fake_vault: FakeVault, tmp_path: Path) -> None:
    state = _state(fake_vault, tmp_path)
    assert await state.read_status() is None

    await state.write_status({"outcome": "success", "stored": {"krb5": 2}})
    await state.write_status({"outcome": "failed", "stored": {}})

    assert await state.read_status() == {"outcome": "failed", "stored": {}}
