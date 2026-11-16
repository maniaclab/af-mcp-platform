"""Builders shared by the tests of ``test_token_registry``."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path
from vault_fakes import FakeVault, make_vault_kv

from af_mcp_broker.token_registry import (
    VaultTokenRegistryBackend,
)

KV_PATH_PREFIX = "mcp/token-registry"


def _make_vault_backend(
    fake: FakeVault, sa_token_path: Path
) -> VaultTokenRegistryBackend:
    vault_kv = make_vault_kv(fake, sa_token_path)
    return VaultTokenRegistryBackend(vault_kv=vault_kv, kv_path_prefix=KV_PATH_PREFIX)
