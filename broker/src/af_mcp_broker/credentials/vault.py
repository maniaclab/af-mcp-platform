"""Vault/OpenBao-backed ``TokenStore`` (issue #66 PR3).

Persists ``StoredOAuthCredential`` entries in a KV-v2 secrets engine, via a
shared ``VaultKV`` transport client (``vault_kv.py``) -- this module owns the
path layout (``{kv_path_prefix}/{subject}/{alias}``), the CAS-conflict ->
``VersionConflict`` translation the ``TokenStore`` protocol promises, and the
``StoredOAuthCredential`` (de)serialization, including the ``SecretStr``
reveal/reload round trip.
"""

from __future__ import annotations

from typing import Any

from af_mcp_broker.credentials.oauth21 import (
    StoredOAuthCredential,
    VersionConflict,
)
from af_mcp_broker.vault_kv import CasConflict, VaultKV


class VaultTokenStore:
    """``TokenStore`` backed by Vault/OpenBao KV-v2 via a shared ``VaultKV``.

    Not thread-safe across processes (Vault's CAS semantics on the KV-v2
    write handle cross-replica races; ``VaultKV`` only guards its own
    in-process re-authentication with an ``asyncio.Lock``).
    """

    def __init__(self, *, vault_kv: VaultKV, kv_path_prefix: str) -> None:
        self._vault_kv = vault_kv
        self._kv_path_prefix = kv_path_prefix.strip("/")

    def _path(self, subject: str, alias: str) -> str:
        return f"{self._kv_path_prefix}/{subject}/{alias}"

    async def get(
        self, subject: str, alias: str
    ) -> tuple[StoredOAuthCredential, int] | None:
        got = await self._vault_kv.get(self._path(subject, alias))
        if got is None:
            return None
        data, version = got
        cred = StoredOAuthCredential.model_validate(data)
        return cred, version

    async def write_cas(
        self,
        subject: str,
        alias: str,
        cred: StoredOAuthCredential,
        expected_version: int | None,
    ) -> int:
        try:
            return await self._vault_kv.write_cas(
                self._path(subject, alias), _reveal_secrets(cred), expected_version
            )
        except CasConflict as exc:
            raise VersionConflict(
                f"vault cas write conflict for subject={subject!r} "
                f"alias={alias!r} expected_version={expected_version!r}"
            ) from exc

    async def delete(self, subject: str, alias: str) -> None:
        await self._vault_kv.delete_metadata(self._path(subject, alias))


def _reveal_secrets(cred: StoredOAuthCredential) -> dict[str, Any]:
    """Serialize *cred* for Vault storage with ``SecretStr`` fields revealed.

    ``StoredOAuthCredential.model_dump(mode="json")`` masks ``SecretStr``
    fields as ``"**********"`` -- pydantic 2's unconditional default for
    that type, verified empirically (no ``context=`` kwarg changes it).
    That's the right behavior for logs but wrong for persistence, so the
    secret values are read back out and substituted in before the payload is
    sent. On read, ``StoredOAuthCredential.model_validate(...)`` re-wraps the
    plain string values Vault hands back into ``SecretStr`` on its own --
    no custom validator needed for that half of the round trip.
    """
    revealed = cred.model_dump(mode="json")
    revealed["access_token"] = cred.access_token.get_secret_value()
    revealed["refresh_token"] = (
        cred.refresh_token.get_secret_value()
        if cred.refresh_token is not None
        else None
    )
    return revealed
