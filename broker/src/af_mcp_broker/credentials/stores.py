"""Builders for the credential stores selected by ``Settings``.

``build_token_store`` picks the OAuth 2.1 token store from
``settings.token_store_backend``; ``build_vault_link_stores`` builds the three
per-user Vault link stores (x509, krb5, servicex) that exist whenever an
``identity_providers`` entry of that type is configured, with no backend
setting of their own.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, assert_never

import structlog

from af_mcp_broker.credentials.krb5_vault import Krb5VaultStore
from af_mcp_broker.credentials.oauth21 import InMemoryTokenStore
from af_mcp_broker.credentials.servicex_vault import VaultServiceXStore
from af_mcp_broker.credentials.vault import VaultTokenStore
from af_mcp_broker.credentials.x509_vault import VaultX509Store
from af_mcp_broker.errors import require

if TYPE_CHECKING:
    from af_mcp_broker.config import Settings
    from af_mcp_broker.vault_kv import VaultKV

logger = structlog.get_logger(__name__)


def build_token_store(
    settings: Settings, vault_kv: VaultKV | None
) -> InMemoryTokenStore | VaultTokenStore:
    """Build the OAuth 2.1 token store selected by ``settings.token_store_backend``.

    *vault_kv* is the process-wide Vault transport, present whenever
    ``Settings.uses_vault`` holds (which the ``vault`` backend implies). The
    ``match`` is exhaustive over the config Literal: ``assert_never`` makes
    mypy fail when a backend name is added without a branch here.
    """
    backend = settings.token_store_backend
    match backend:
        case "in_memory":
            return InMemoryTokenStore()
        case "vault":
            return VaultTokenStore(
                vault_kv=require(
                    vault_kv, "token_store_backend=vault requires a Vault client"
                ),
                kv_path_prefix=settings.vault_kv_path_prefix,
            )
        case _:
            assert_never(backend)


@dataclass(frozen=True)
class VaultLinkStores:
    """The per-user Vault link stores, each present only when an ``identity_providers`` entry of its type is configured.

    One KV record per subject regardless of how many entries of a type exist:
    the link is per user, not per service (issue #112's custodianship model).
    """

    x509: VaultX509Store | None = None
    krb5: Krb5VaultStore | None = None
    servicex: VaultServiceXStore | None = None


def build_vault_link_stores(settings: Settings, vault_kv: VaultKV) -> VaultLinkStores:
    """Build the Vault link store of every credential kind *settings* configures an entry for.

    Each store is implied by its entry unconditionally (x509 proxies and
    passphrases, krb5 tickets and keytabs, ServiceX refresh tokens have no
    in-memory fallback), which is why ``Settings._validate_vault_config``
    already refused to construct *settings* without the Vault connection
    settings and *vault_kv* is non-optional here.
    """
    entry_types = {cfg.type for cfg in settings.identity_providers}
    x509_store: VaultX509Store | None = None
    krb5_store: Krb5VaultStore | None = None
    servicex_store: VaultServiceXStore | None = None
    if "x509" in entry_types:
        x509_store = VaultX509Store(
            vault_kv=vault_kv, kv_path_prefix=settings.x509_kv_path_prefix
        )
        logger.info(
            "x509_voms_service_mode",
            kv_path_prefix=settings.x509_kv_path_prefix,
        )
    if "krb5-token" in entry_types:
        krb5_store = Krb5VaultStore(
            vault_kv=vault_kv, kv_path_prefix=settings.krb5_kv_path_prefix
        )
        logger.info(
            "krb5_vault_store_wired",
            kv_path_prefix=settings.krb5_kv_path_prefix,
        )
    if "servicex-token" in entry_types:
        servicex_store = VaultServiceXStore(
            vault_kv=vault_kv, kv_path_prefix=settings.servicex_kv_path_prefix
        )
        logger.info(
            "servicex_vault_store_wired",
            kv_path_prefix=settings.servicex_kv_path_prefix,
        )
    return VaultLinkStores(x509=x509_store, krb5=krb5_store, servicex=servicex_store)
