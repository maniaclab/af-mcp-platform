"""Vault-backed credmon pieces: subject enumeration over the per-user credential stores."""

from __future__ import annotations

from typing import TYPE_CHECKING

from af_mcp_broker.credmon.storer import SubjectSource

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
