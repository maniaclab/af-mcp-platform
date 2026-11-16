"""Tests for ``build_credmon_sync``'s fail-fast refusals (docs/credmon.md).

Each refusal stands in for a cycle that could never succeed; refusing at
boot keeps the broker from reporting healthy with a dead sync loop.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import httpx2
import pytest
from test_broker_issued import ISSUER_URL
from vault_fakes import ADDR, AUTH_MOUNT, AUTH_ROLE, KV_MOUNT, FakeVault

from af_mcp_broker.config import Settings
from af_mcp_broker.credentials.base import CredentialRegistry
from af_mcp_broker.credentials.broker_issued import BrokerTokenIssuer
from af_mcp_broker.credmon.factory import build_credmon_sync
from af_mcp_broker.vault_kv import VaultConnections

if TYPE_CHECKING:
    from pathlib import Path

    from af_mcp_broker.config import CredmonApiConfig


def _vaults() -> VaultConnections:
    return VaultConnections(
        httpx2.AsyncClient(transport=httpx2.MockTransport(FakeVault().handle))
    )


def _settings_and_api(
    tmp_path: Path, sa_token_path: Path, **overrides: Any
) -> tuple[Settings, CredmonApiConfig]:
    token_file = tmp_path / "token"
    token_file.write_text("storer-idtoken\n")
    settings = Settings(
        **{
            "credmon_enabled": True,
            "credmon_htcondor_api_url": "https://htcondor-api.example",
            "credmon_htcondor_api_token_file": str(token_file),
            "credmon_user_domain": "af.example.org",
            "vault_addr": ADDR,
            "vault_auth_mount": AUTH_MOUNT,
            "vault_auth_role": AUTH_ROLE,
            "vault_kv_mount": KV_MOUNT,
            "vault_kv_root": "mcp",
            "vault_sa_token_path": str(sa_token_path),
            "token_store_backend": "vault",
            **overrides,
        }
    )
    api = settings.credmon_api
    assert api is not None
    return settings, api


@pytest.fixture
def issuer(broker_signing_key_pem: bytes) -> BrokerTokenIssuer:
    return BrokerTokenIssuer(private_key_pem=broker_signing_key_pem, issuer=ISSUER_URL)


async def test_refuses_without_signing_key(
    tmp_path: Path, static_principal_cache, sa_token_path: Path
) -> None:
    cache, _ = static_principal_cache
    with pytest.raises(RuntimeError, match="BROKER_SIGNING_KEY_FILE"):
        await build_credmon_sync(
            *_settings_and_api(tmp_path, sa_token_path),
            issuer=None,
            credential_registry=CredentialRegistry(),
            targets_by_kind={},
            store_prefixes={},
            vaults=_vaults(),
            principal_cache=cache,
            http_client=httpx2.AsyncClient(),
        )


async def test_refuses_without_principal_directory(
    tmp_path: Path, issuer, sa_token_path: Path
) -> None:
    with pytest.raises(RuntimeError, match="principal directory"):
        await build_credmon_sync(
            *_settings_and_api(tmp_path, sa_token_path),
            issuer=issuer,
            credential_registry=CredentialRegistry(),
            targets_by_kind={},
            store_prefixes={},
            vaults=_vaults(),
            principal_cache=None,
            http_client=httpx2.AsyncClient(),
        )


async def test_refuses_unreadable_token_file(
    tmp_path: Path, issuer, static_principal_cache, sa_token_path: Path
) -> None:
    cache, _ = static_principal_cache
    with pytest.raises(RuntimeError, match="CREDMON_HTCONDOR_API_TOKEN_FILE"):
        await build_credmon_sync(
            *_settings_and_api(
                tmp_path,
                sa_token_path,
                credmon_htcondor_api_token_file=str(tmp_path / "missing"),
            ),
            issuer=issuer,
            credential_registry=CredentialRegistry(),
            targets_by_kind={},
            store_prefixes={},
            vaults=_vaults(),
            principal_cache=cache,
            http_client=httpx2.AsyncClient(),
        )


async def test_kinds_without_targets_are_skipped(
    tmp_path: Path, issuer, static_principal_cache, sa_token_path: Path
) -> None:
    cache, _ = static_principal_cache
    sync = await build_credmon_sync(
        *_settings_and_api(tmp_path, sa_token_path),
        issuer=issuer,
        credential_registry=CredentialRegistry(),
        targets_by_kind={"x509": [], "krb5": [], "servicex": []},
        store_prefixes={},
        vaults=_vaults(),
        principal_cache=cache,
        http_client=httpx2.AsyncClient(),
    )

    assert sync.kinds == []
