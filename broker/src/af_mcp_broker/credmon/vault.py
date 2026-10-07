"""Vault-backed credmon pieces: subject enumeration over the per-user credential stores, and the cross-replica sync lease/status."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from af_mcp_broker.credmon.state import CredmonSyncState
from af_mcp_broker.credmon.storer import SubjectSource
from af_mcp_broker.vault_kv import CasConflict

if TYPE_CHECKING:
    from collections.abc import Mapping

    from af_mcp_broker.vault_kv import VaultKV


class VaultSubjectSource(SubjectSource):
    """Enumerates subjects by KV LIST of each kind's store prefix.

    Every per-user store keys its records at ``{prefix}/{subject}/{kind}``
    (credentials/x509_vault.py, krb5_vault.py, servicex_vault.py), so the
    folder children of ``{prefix}`` are exactly the subjects with a record.
    A kind with no configured prefix (e.g. legacy-mode x509, which has no
    Vault store) enumerates nothing.
    """

    def __init__(self, vault_kv: VaultKV, *, prefixes: Mapping[str, str]) -> None:
        self._vault_kv = vault_kv
        self._prefixes = {kind: prefix.strip("/") for kind, prefix in prefixes.items()}

    async def list_subjects(self, kind: str) -> list[str]:
        prefix = self._prefixes.get(kind)
        if prefix is None:
            return []
        keys = await self._vault_kv.list(prefix)
        # Folder children carry a trailing "/"; a bare leaf directly under
        # the prefix is not a subject record.
        return [key.rstrip("/") for key in keys if key.endswith("/")]


class VaultCredmonSyncState(CredmonSyncState):
    """``CredmonSyncState`` in Vault KV-v2: ``{prefix}/lease`` and ``{prefix}/status``.

    The lease is a check-and-set write against the version just read, so of
    two replicas that both see a free (or expired) lease, exactly one write
    lands and the other gets ``CasConflict`` -> not acquired. Clock skew
    between replicas only shifts when an expired lease becomes takeable; it
    cannot let two holders both win the same version.
    """

    def __init__(self, vault_kv: VaultKV, *, kv_path_prefix: str) -> None:
        self._vault_kv = vault_kv
        prefix = kv_path_prefix.strip("/")
        self._lease_path = f"{prefix}/lease"
        self._status_path = f"{prefix}/status"

    async def try_acquire_lease(
        self, holder: str, *, ttl_seconds: float, now: float
    ) -> bool:
        current = await self._vault_kv.get(self._lease_path)
        version: int | None = None
        if current is not None:
            data, version = current
            if data.get("holder") != holder and float(data.get("expires_at", 0)) > now:
                return False
        try:
            await self._vault_kv.write_cas(
                self._lease_path,
                {"holder": holder, "expires_at": now + ttl_seconds},
                expected_version=version,
            )
        except CasConflict:
            return False
        return True

    async def write_status(self, status: dict[str, Any]) -> None:
        # Only the lease holder writes, so a conflict here means a stale
        # read raced our own previous write -- re-read once and retry.
        for _ in range(2):
            current = await self._vault_kv.get(self._status_path)
            try:
                await self._vault_kv.write_cas(
                    self._status_path,
                    status,
                    expected_version=current[1] if current is not None else None,
                )
            except CasConflict:
                continue
            return
        raise CasConflict(
            f"credmon status write kept conflicting at {self._status_path!r}"
        )

    async def read_status(self) -> dict[str, Any] | None:
        current = await self._vault_kv.get(self._status_path)
        return current[0] if current is not None else None
