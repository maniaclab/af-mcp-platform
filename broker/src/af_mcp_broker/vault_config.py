"""Connection settings of the Vault/OpenBao transport."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class VaultConfig(BaseModel):
    """Connection settings of the Vault/OpenBao transport, shared by every Vault-backed store."""

    model_config = ConfigDict(frozen=True)

    addr: str = Field(min_length=1)
    auth_mount: str
    auth_role: str = Field(min_length=1)
    kv_mount: str
    sa_token_path: str
