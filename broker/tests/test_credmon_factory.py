"""Tests for ``build_credmon_sync``'s fail-fast refusals (docs/credmon.md).

Each refusal stands in for a cycle that could never succeed; refusing at
boot keeps the broker from reporting healthy with a dead sync loop.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest
from _credmon_fake_vault import FakeVault, make_vault_kv
from test_broker_issued import ISSUER_URL, _make_rsa_key, _private_pem

from af_mcp_broker.config import Settings
from af_mcp_broker.credentials.base import CredentialRegistry
from af_mcp_broker.credentials.broker_issued import BrokerTokenIssuer
from af_mcp_broker.credmon.factory import build_credmon_sync

if TYPE_CHECKING:
    from pathlib import Path


def _settings(tmp_path: Path, **overrides: Any) -> Settings:
    token_file = tmp_path / "token"
    token_file.write_text("storer-idtoken\n")
    return Settings(
        credmon_enabled=True,
        credmon_htcondor_api_url="https://htcondor-api.example",
        credmon_htcondor_api_token_file=str(token_file),
        **overrides,
    )


@pytest.fixture
def issuer() -> BrokerTokenIssuer:
    return BrokerTokenIssuer(
        private_key_pem=_private_pem(_make_rsa_key()), issuer=ISSUER_URL
    )


async def test_refuses_without_signing_key(
    tmp_path: Path, static_principal_cache
) -> None:
    cache, _ = static_principal_cache
    with pytest.raises(RuntimeError, match="BROKER_SIGNING_KEY_FILE"):
        await build_credmon_sync(
            _settings(tmp_path),
            issuer=None,
            credential_registry=CredentialRegistry(),
            targets_by_kind={},
            store_prefixes={},
            vault_kv=make_vault_kv(FakeVault(), tmp_path),
            principal_cache=cache,
        )


async def test_refuses_without_vault(
    tmp_path: Path, issuer, static_principal_cache
) -> None:
    cache, _ = static_principal_cache
    with pytest.raises(RuntimeError, match="requires Vault"):
        await build_credmon_sync(
            _settings(tmp_path),
            issuer=issuer,
            credential_registry=CredentialRegistry(),
            targets_by_kind={},
            store_prefixes={},
            vault_kv=None,
            principal_cache=cache,
        )


async def test_refuses_without_principal_directory(tmp_path: Path, issuer) -> None:
    with pytest.raises(RuntimeError, match="principal directory"):
        await build_credmon_sync(
            _settings(tmp_path),
            issuer=issuer,
            credential_registry=CredentialRegistry(),
            targets_by_kind={},
            store_prefixes={},
            vault_kv=make_vault_kv(FakeVault(), tmp_path),
            principal_cache=None,
        )


async def test_refuses_unreadable_token_file(
    tmp_path: Path, issuer, static_principal_cache
) -> None:
    cache, _ = static_principal_cache
    settings = _settings(tmp_path)
    settings.credmon_htcondor_api_token_file = str(tmp_path / "missing")
    with pytest.raises(RuntimeError, match="CREDMON_HTCONDOR_API_TOKEN_FILE"):
        await build_credmon_sync(
            settings,
            issuer=issuer,
            credential_registry=CredentialRegistry(),
            targets_by_kind={},
            store_prefixes={},
            vault_kv=make_vault_kv(FakeVault(), tmp_path),
            principal_cache=cache,
        )


async def test_kinds_without_targets_are_skipped(
    tmp_path: Path, issuer, static_principal_cache
) -> None:
    cache, _ = static_principal_cache
    sync = await build_credmon_sync(
        _settings(tmp_path),
        issuer=issuer,
        credential_registry=CredentialRegistry(),
        targets_by_kind={"x509": [], "krb5": [], "servicex": []},
        store_prefixes={},
        vault_kv=make_vault_kv(FakeVault(), tmp_path),
        principal_cache=cache,
    )

    assert sync.kinds == []
