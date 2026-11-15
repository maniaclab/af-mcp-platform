"""Builder for the process-wide Vault/OpenBao transport."""

from __future__ import annotations

from typing import TYPE_CHECKING

import structlog

from af_mcp_broker.vault_kv import VaultKV

if TYPE_CHECKING:
    import httpx2

    from af_mcp_broker.config import Settings

logger = structlog.get_logger(__name__)


async def build_vault_kv(
    settings: Settings, http_client: httpx2.AsyncClient
) -> VaultKV | None:
    """Return the authenticated Vault client, or None when no configured subsystem uses Vault (``Settings.uses_vault``).

    One VaultKV instance (one K8s auth login per process) is shared by every
    Vault-backed store -- the oauth21 token store, the token registry, the
    principal cache, the maintenance-mode store, and the x509, krb5 and
    ServiceX link stores -- whichever of them are configured; see
    vault_kv.py's module docstring for the transport/domain split.
    ``Settings._validate_vault_config`` already refused to construct
    *settings* without the connection settings whenever ``uses_vault``
    holds.
    """
    if not settings.uses_vault:
        return None
    vault_kv = VaultKV(
        addr=settings.vault_addr,
        auth_mount=settings.vault_auth_mount,
        auth_role=settings.vault_auth_role,
        kv_mount=settings.vault_kv_mount,
        sa_token_path=settings.vault_sa_token_path,
        http_client=http_client,
    )
    # Trial authentication only -- proves the K8s auth flow works (SA JWT
    # readable, Vault reachable, role accepted) without touching any
    # stored credential or token-registry entry. A misconfigured Vault
    # backend is a security-sensitive state; refusing to start is safer
    # than silently degrading to a broker that can't persist state.
    try:
        await vault_kv._authenticate()
    except Exception as exc:
        logger.exception("vault_auth.failed")
        raise RuntimeError(f"Vault K8s auth failed at startup: {exc}") from exc
    logger.info("vault_auth.ok", vault_addr=settings.vault_addr)
    return vault_kv
