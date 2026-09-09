"""Vault/OpenBao-backed ServiceX credential store (issue #295).

Persists, per subject, everything the servicex-token-service redeem path
needs to serve a ServiceX access token with no user interaction:

* the ServiceX personal **refresh token** captured at link time -- the
  custodianship model mirrors ``x509_vault.py``'s stored Globus passphrase:
  the broker holds it so future access tokens can be redeemed hands-free;
* the current **access token** and its expiry, served on redeem until it
  nears expiry.

One KV-v2 record per subject at ``{kv_path_prefix}/{subject}/servicex``,
over the shared ``VaultKV`` transport -- this module owns the path layout,
the record shape, and the ``SecretStr`` reveal/reload round trip, mirroring
``credentials/x509_vault.py``'s ``VaultX509Store``/``krb5_vault.py``'s
``Krb5VaultStore``. Writes are read-modify-write under KV-v2 CAS with a
bounded retry: concurrent redemptions across replicas each produce an
equally-valid access token, so absorbing the version race by re-reading and
retrying is correct (last writer wins).
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, SecretStr

from af_mcp_broker.vault_kv import CasConflict, VaultKV

if TYPE_CHECKING:
    from collections.abc import Callable

# Read-modify-write attempts before a CAS conflict is allowed to propagate.
# Each retry re-reads the current version, so this only trips if another
# writer keeps winning the race repeatedly.
_CAS_ATTEMPTS = 3


class StoredServiceXCredential(BaseModel):
    """The per-subject Vault record: link half (refresh token) plus token half (access token + expiry).

    Either half may be absent: a fresh link has no access token yet, and a
    defensively-written token could exist without a link (though nothing in
    this provider writes one without the other). ``SecretStr`` keeps the
    refresh token and the bearer-equivalent access token out of repr/logs;
    persistence reveals them explicitly (see ``_reveal_secrets``).
    """

    # Link half
    refresh_token: SecretStr | None = None

    # Token half
    access_token: SecretStr | None = None
    expires_at: float | None = None  # epoch seconds (UTC)

    @property
    def has_link(self) -> bool:
        """Whether the link half is complete enough to redeem from: a stored refresh token."""
        return self.refresh_token is not None


class VaultServiceXStore:
    """Per-subject ServiceX link/token store backed by Vault/OpenBao KV-v2.

    Not thread-safe across processes (Vault's CAS semantics on the KV-v2
    write handle cross-replica races; ``VaultKV`` only guards its own
    in-process re-authentication with an ``asyncio.Lock``).
    """

    def __init__(self, *, vault_kv: VaultKV, kv_path_prefix: str) -> None:
        self._vault_kv = vault_kv
        self._kv_path_prefix = kv_path_prefix.strip("/")

    def _path(self, subject: str) -> str:
        return f"{self._kv_path_prefix}/{subject}/servicex"

    async def _read(self, subject: str) -> tuple[StoredServiceXCredential, int] | None:
        got = await self._vault_kv.get(self._path(subject))
        if got is None:
            return None
        data, version = got
        return StoredServiceXCredential.model_validate(data), version

    async def store_link(self, subject: str, *, refresh_token: SecretStr) -> None:
        """Record *subject*'s ServiceX refresh token.

        Writes a fresh record: a (re-)link means a possibly-new refresh
        token (the user generated a new ServiceX personal token), so any
        previously stored access token -- which may no longer be
        redeemable against a changed refresh token -- does not survive it.
        The caller stores the freshly-redeemed access token right after via
        ``store_token``.
        """
        record = StoredServiceXCredential(refresh_token=refresh_token)
        await self._write_cas_retry(subject, lambda _current: record)

    async def get_link(self, subject: str) -> StoredServiceXCredential | None:
        """Return the record when its link half is complete (a stored refresh token), else None."""
        got = await self._read(subject)
        if got is None:
            return None
        record, _version = got
        return record if record.has_link else None

    async def store_token(
        self, subject: str, *, access_token: str, expires_at: float
    ) -> None:
        """Merge a freshly-redeemed access token into *subject*'s record, preserving the link half."""

        def _merge(
            current: StoredServiceXCredential | None,
        ) -> StoredServiceXCredential:
            base = current if current is not None else StoredServiceXCredential()
            return base.model_copy(
                update={
                    "access_token": SecretStr(access_token),
                    "expires_at": expires_at,
                }
            )

        await self._write_cas_retry(subject, _merge)

    async def get_token(
        self, subject: str, min_remaining: float = 0.0
    ) -> StoredServiceXCredential | None:
        """Return the record when it holds an access token with at least *min_remaining* seconds of validity left, else None.

        Expiry-aware by design: an expired (or nearly-expired) access token
        is reported as absent so callers fall through to the redeem path
        instead of serving a credential the recipient cannot use.
        """
        got = await self._read(subject)
        if got is None:
            return None
        record, _version = got
        if record.access_token is None or record.expires_at is None:
            return None
        if record.expires_at - time.time() < min_remaining:
            return None
        return record

    async def clear_token(self, subject: str) -> None:
        """Remove *subject*'s stored access token while keeping the link half.

        Token revocation must not unlink the identity: the refresh token
        stays so the next issue() redeems hands-free. A subject with no
        record at all is a no-op.
        """
        if await self._read(subject) is None:
            return

        def _clear(
            current: StoredServiceXCredential | None,
        ) -> StoredServiceXCredential:
            base = current if current is not None else StoredServiceXCredential()
            return base.model_copy(update={"access_token": None, "expires_at": None})

        await self._write_cas_retry(subject, _clear)

    async def delete(self, subject: str) -> None:
        """Unlink *subject*: destroy the record -- refresh token, access token, and all KV-v2 version history."""
        await self._vault_kv.delete_metadata(self._path(subject))

    async def _write_cas_retry(
        self,
        subject: str,
        build: Callable[[StoredServiceXCredential | None], StoredServiceXCredential],
    ) -> None:
        """Read-modify-write *subject*'s record under CAS, retrying a bounded number of times on version conflicts.

        *build* maps the current record (or None) to the record to write.
        Retrying re-reads the current version each attempt, so a concurrent
        writer's bump is absorbed rather than surfaced -- see the module
        docstring for why last-writer-wins is correct here.
        """
        for attempt in range(_CAS_ATTEMPTS):
            got = await self._read(subject)
            current, version = got if got is not None else (None, None)
            record = build(current)
            try:
                await self._vault_kv.write_cas(
                    self._path(subject), _reveal_secrets(record), version
                )
            except CasConflict:
                if attempt == _CAS_ATTEMPTS - 1:
                    raise
                continue
            return


def _reveal_secrets(record: StoredServiceXCredential) -> dict[str, Any]:
    """Serialize *record* for Vault storage with ``SecretStr`` fields revealed.

    ``model_dump(mode="json")`` masks ``SecretStr`` fields as ``**********``
    -- right for logs, wrong for persistence -- so the secret values are
    read back out and substituted in before the payload is sent. On read,
    ``model_validate`` re-wraps the plain strings into ``SecretStr`` on its
    own (same round trip as ``credentials/x509_vault.py``).
    """
    revealed = record.model_dump(mode="json")
    revealed["refresh_token"] = (
        record.refresh_token.get_secret_value()
        if record.refresh_token is not None
        else None
    )
    revealed["access_token"] = (
        record.access_token.get_secret_value()
        if record.access_token is not None
        else None
    )
    return revealed
