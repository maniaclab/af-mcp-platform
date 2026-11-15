"""Read-modify-write under KV-v2 CAS, shared by the per-user Vault link stores."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from af_mcp_broker.vault_kv import CasConflictError, VaultKV

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

# Read-modify-write attempts before a CAS conflict is allowed to propagate.
# Each retry re-reads the current version, so this only trips if another
# writer keeps winning the race repeatedly.
CAS_ATTEMPTS = 3


async def write_cas_retry[R](
    vault_kv: VaultKV,
    path: str,
    *,
    read: Callable[[], Awaitable[tuple[R, int] | None]],
    build: Callable[[R | None], R],
    reveal: Callable[[R], dict[str, Any]],
) -> None:
    """Read-modify-write the record at *path* under CAS, retrying a bounded number of times on version conflicts.

    *read* returns the current ``(record, version)`` or None; *build* maps
    the current record (or None) to the record to write; *reveal* turns the
    record into the payload sent to Vault. Retrying re-reads the current
    version each attempt, so a concurrent writer's bump is absorbed rather
    than surfaced -- last-writer-wins is correct for the stores using this.
    """
    for attempt in range(CAS_ATTEMPTS):
        got = await read()
        current, version = got if got is not None else (None, None)
        record = build(current)
        try:
            await vault_kv.write_cas(path, reveal(record), version)
        except CasConflictError:
            if attempt == CAS_ATTEMPTS - 1:
                raise
            continue
        return
