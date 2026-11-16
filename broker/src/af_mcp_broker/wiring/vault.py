"""Builder for the process-wide Vault/OpenBao transport."""

from __future__ import annotations

from typing import TYPE_CHECKING

import structlog

from af_mcp_broker.vault_kv import VaultConnections

if TYPE_CHECKING:
    import httpx2

    from af_mcp_broker.config import Settings

logger = structlog.get_logger(__name__)


async def build_vault_connections(
    settings: Settings, http_client: httpx2.AsyncClient
) -> VaultConnections:
    """Return the process's Vault clients, trial-authenticating the deployment's Vault when a configured subsystem uses it (``Settings.uses_vault``).

    One VaultKV instance (one K8s auth login per process) is shared by every
    Vault-backed store -- the oauth21 token store, the token registry, the
    principal cache, the maintenance-mode store, and the x509, krb5 and
    ServiceX link stores -- whichever of them are configured; see
    vault_kv.py's module docstring for the transport/domain split.
    ``Settings._validate_vault_config`` already refused to construct
    *settings* without the connection settings whenever ``uses_vault``
    holds.
    """
    connections = VaultConnections(http_client)
    vault = settings.vault
    if vault is None:
        return connections
    vault_kv = connections.connect(vault)
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
    logger.info("vault_auth.ok", vault_addr=vault.addr)
    return connections
