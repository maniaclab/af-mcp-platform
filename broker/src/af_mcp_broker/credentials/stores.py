"""Builders for the credential stores selected by ``Settings``.

``build_token_store`` picks the OAuth 2.1 token store from
``settings.token_store_backend``; ``ProviderStores`` builds that store and the
three per-user Vault link stores (x509, krb5, servicex) for the providers that
need them, the link stores existing whenever an ``identity_providers`` entry of
that type is configured, with no backend setting of their own.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, assert_never

import structlog

from af_mcp_broker.config import InMemoryBackendConfig, VaultBackendConfig
from af_mcp_broker.credentials.krb5_vault import Krb5VaultStore
from af_mcp_broker.credentials.oauth21 import InMemoryTokenStore
from af_mcp_broker.credentials.servicex_vault import VaultServiceXStore
from af_mcp_broker.credentials.vault import VaultTokenStore
from af_mcp_broker.credentials.x509_vault import VaultX509Store

if TYPE_CHECKING:
    from af_mcp_broker.config import Settings
    from af_mcp_broker.vault_kv import VaultConnections, VaultKV

logger = structlog.get_logger(__name__)


def build_token_store(
    settings: Settings, vaults: VaultConnections
) -> InMemoryTokenStore | VaultTokenStore:
    """Build the OAuth 2.1 token store selected by ``settings.token_store_backend``.

    *vaults* hands out the process-wide Vault transport for the
    ``VaultConfig`` the selected backend carries. The ``match`` is exhaustive
    over the config union: ``assert_never`` makes
    mypy fail when a backend name is added without a branch here.
    """
    backend = settings.token_store
    match backend:
        case InMemoryBackendConfig():
            return InMemoryTokenStore()
        case VaultBackendConfig(vault=vault):
            return VaultTokenStore(
                vault_kv=vaults.connect(vault),
                kv_path_prefix=settings.vault_kv_paths.tokens,
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


class ProviderStores:
    """The stores the credential providers share, each built the first time a provider of its kind asks for it.

    A store is built from the Vault connection settings (``Settings.vault_connection``)
    only when an ``identity_providers`` entry that persists in it is
    configured, which is why ``Settings._validate_vault_config`` already
    refused to construct *settings* without them. The x509, krb5 and ServiceX
    link stores are implied unconditionally by their entry types (x509
    proxies and passphrases, krb5 tickets and keytabs, ServiceX refresh tokens
    have no in-memory fallback). Each is one KV record per subject regardless
    of how many entries of a type exist: the link is per user, not per
    service (issue #112's custodianship model).
    """

    def __init__(self, settings: Settings, vaults: VaultConnections) -> None:
        self._settings = settings
        self._vaults = vaults
        self._token_store: InMemoryTokenStore | VaultTokenStore | None = None
        self._x509: VaultX509Store | None = None
        self._krb5: Krb5VaultStore | None = None
        self._servicex: VaultServiceXStore | None = None

    def _vault_kv(self) -> VaultKV:
        return self._vaults.connect(self._settings.vault_connection)

    def token_store(self) -> InMemoryTokenStore | VaultTokenStore:
        """Return the OAuth 2.1 token store the oauth21-direct providers share."""
        if self._token_store is None:
            self._token_store = build_token_store(self._settings, self._vaults)
        return self._token_store

    def x509(self) -> VaultX509Store:
        """Return the x509 proxy and link store."""
        if self._x509 is None:
            prefix = self._settings.vault_kv_paths.x509
            self._x509 = VaultX509Store(
                vault_kv=self._vault_kv(), kv_path_prefix=prefix
            )
            logger.info("x509_voms_service_mode", kv_path_prefix=prefix)
        return self._x509

    def krb5(self) -> Krb5VaultStore:
        """Return the krb5 ticket and link store."""
        if self._krb5 is None:
            prefix = self._settings.vault_kv_paths.krb5
            self._krb5 = Krb5VaultStore(
                vault_kv=self._vault_kv(), kv_path_prefix=prefix
            )
            logger.info("krb5_vault_store_wired", kv_path_prefix=prefix)
        return self._krb5

    def servicex(self) -> VaultServiceXStore:
        """Return the ServiceX refresh-token link store."""
        if self._servicex is None:
            prefix = self._settings.vault_kv_paths.servicex
            self._servicex = VaultServiceXStore(
                vault_kv=self._vault_kv(), kv_path_prefix=prefix
            )
            logger.info("servicex_vault_store_wired", kv_path_prefix=prefix)
        return self._servicex

    @property
    def token_store_built(self) -> InMemoryTokenStore | VaultTokenStore | None:
        """Return the OAuth 2.1 token store, or None when no oauth21-direct provider asked for one."""
        return self._token_store

    def link_stores(self) -> VaultLinkStores:
        """Return the link stores built so far."""
        return VaultLinkStores(
            x509=self._x509, krb5=self._krb5, servicex=self._servicex
        )
