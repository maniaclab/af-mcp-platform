"""Tests for the credmon's Vault-backed pieces: subject enumeration (``VaultSubjectSource``).

Every per-user credential store keys records at ``{prefix}/{subject}/{kind}``
(credentials/x509_vault.py, krb5_vault.py, servicex_vault.py), so a KV LIST
of ``{prefix}`` enumerates the subjects that may hold that kind.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from _credmon_fake_vault import FakeVault, make_vault_kv

from af_mcp_broker.credmon.vault import VaultSubjectSource

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
