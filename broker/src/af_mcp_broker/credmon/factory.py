"""Build the credmon sync service from Settings and the broker's already-wired subsystems (called from app.py's lifespan)."""

from __future__ import annotations

import os
import socket
from pathlib import Path
from typing import TYPE_CHECKING

import structlog
from pydantic import SecretStr

from af_mcp_broker.credmon.htcondor_api import HTCondorApiCredentialStore
from af_mcp_broker.credmon.storer import CredmonKind, CredmonStorer
from af_mcp_broker.credmon.sync import CredmonSyncService
from af_mcp_broker.credmon.vault import VaultCredmonSyncState, VaultSubjectSource

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from af_mcp_broker.config import Settings
    from af_mcp_broker.credentials.base import CredentialRegistry
    from af_mcp_broker.credentials.broker_issued import BrokerTokenIssuer
    from af_mcp_broker.principal_cache import PrincipalCache
    from af_mcp_broker.vault_kv import VaultKV

log = structlog.get_logger(__name__)

# The per-cycle lease only has to outlive one cycle; a crashed holder frees
# it for the next replica within this window.
_LEASE_TTL_SECONDS = 600.0
# How often each replica checks whether a timer cycle is due.
_POLL_SECONDS = 60.0


async def build_credmon_sync(
    settings: Settings,
    *,
    issuer: BrokerTokenIssuer | None,
    credential_registry: CredentialRegistry,
    targets_by_kind: Mapping[str, Sequence[str]],
    store_prefixes: Mapping[str, str],
    vault_kv: VaultKV | None,
    principal_cache: PrincipalCache | None,
) -> CredmonSyncService:
    """Wire a ``CredmonSyncService`` for every requested kind that has an identity provider configured.

    *targets_by_kind* is each kind's configured targets (app.py's
    ``x509_targets``/``krb5_targets``/``servicex_targets``); the first one
    supplies the provider whose ``is_linked`` the storer asks -- the same
    default the redeem endpoints map the credmon audience to. *store_prefixes*
    holds the Vault KV prefix of each kind's per-user store that is actually
    wired (legacy-mode x509 has none and so is never enumerated).

    Raises RuntimeError on anything that would make every cycle fail, so the
    broker refuses to boot instead of reporting healthy with a dead sync.
    """
    if issuer is None:
        raise RuntimeError(
            "CREDMON_ENABLED requires BROKER_SIGNING_KEY_FILE: credmon top "
            "tokens are AF Broker Identity Tokens."
        )
    if vault_kv is None:
        raise RuntimeError(
            "CREDMON_ENABLED requires Vault: the storer enumerates linked users "
            "from the Vault-backed identity stores and coordinates replicas "
            "through a Vault lease."
        )
    if principal_cache is None:
        raise RuntimeError(
            "CREDMON_ENABLED requires the Keycloak principal directory: credd "
            "stores credentials per POSIX unixname, resolved from it."
        )
    assert settings.credmon_htcondor_api_url is not None  # Settings validator
    assert settings.credmon_htcondor_api_token_file is not None  # Settings validator
    try:
        api_token = Path(settings.credmon_htcondor_api_token_file).read_text().strip()
    except OSError as exc:
        raise RuntimeError(
            "CREDMON_HTCONDOR_API_TOKEN_FILE could not be read: "
            f"{settings.credmon_htcondor_api_token_file}"
        ) from exc

    kinds: list[CredmonKind] = []
    for kind in settings.credmon_kinds:
        targets = targets_by_kind.get(kind, ())
        if not targets:
            log.warning("credmon.kind_not_configured", kind=kind)
            continue
        provider = await credential_registry.resolve(targets[0])
        kinds.append(CredmonKind(kind, provider.is_linked))

    storer = CredmonStorer(
        issuer=issuer,
        kinds=kinds,
        subjects=VaultSubjectSource(vault_kv, prefixes=store_prefixes),
        principal_cache=principal_cache,
        client=HTCondorApiCredentialStore(
            api_url=str(settings.credmon_htcondor_api_url),
            token=SecretStr(api_token),
        ),
        audience_prefix=settings.credmon_audience_prefix,
        service_prefix=settings.credmon_service_prefix,
        top_token_ttl_seconds=settings.credmon_top_token_ttl_seconds,
    )
    log.info(
        "credmon.wired",
        kinds=[k.name for k in kinds],
        interval_seconds=settings.credmon_sync_interval_seconds,
    )
    return CredmonSyncService(
        storer=storer,
        state=VaultCredmonSyncState(
            vault_kv, kv_path_prefix=settings.credmon_state_kv_path_prefix
        ),
        holder=f"{socket.gethostname()}:{os.getpid()}",
        interval_seconds=float(settings.credmon_sync_interval_seconds),
        lease_ttl_seconds=_LEASE_TTL_SECONDS,
        poll_seconds=_POLL_SECONDS,
    )
