"""Vault/OpenBao-backed krb5 credential store (issue #274 follow-up).

Persists, per subject, everything ``KrbTokenProvider``'s renew/keytab-remint
fallback tiers need to mint a fresh Kerberos ticket with no user interaction:

* the **link half** -- a keytab and its username, captured once via
  ``POST /v1/keytab`` (using the same password already supplied for the
  initial mint) and stored only when the user opts in ("remember"). Unlike
  x509's passphrase, a stored keytab has no bearing on whether an
  already-minted ticket is still good, so a re-link never touches the
  ticket half (see ``store_link``'s docstring).
* the **ticket half** -- the last-minted ccache and its ``not_after`` /
  ``renew_until`` deadlines, written on *every* successful mint regardless
  of "remember". This is what makes renew-without-remember possible: the
  renewal tier needs no stored secret at all, just the ticket's own ccache
  and its own renewable window.

One KV-v2 record per subject at ``{kv_path_prefix}/{subject}/krb5``, over
the shared ``VaultKV`` transport -- this module owns the path layout, the
record shape, and the ``SecretStr`` reveal/reload round trip, mirroring
``credentials/x509_vault.py``'s ``VaultX509Store``. Writes are
read-modify-write under KV-v2 CAS with a bounded retry: concurrent mints
across replicas each produce an equally-valid ticket, so absorbing the
version race by re-reading and retrying is correct (last writer wins), same
reasoning as the x509 store.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Any

from pydantic import SecretStr

from af_mcp_broker.vault_kv import CasConflict, VaultKV

if TYPE_CHECKING:
    from collections.abc import Callable

# Read-modify-write attempts before a CAS conflict is allowed to propagate.
# Each retry re-reads the current version, so this only trips if another
# writer keeps winning the race repeatedly.
_CAS_ATTEMPTS = 3


@dataclass(frozen=True)
class StoredKrb5Credential:
    """A Vault-persisted krb5 record: a link half (keytab, durable, opt-in via 'remember')
    plus a ticket half (last-minted ccache metadata, written on every mint regardless of
    remember -- this is what makes renew-without-remember possible)."""

    username: str | None = None
    keytab_b64: SecretStr | None = None
    ccache_b64: SecretStr | None = None
    principal: str | None = None
    realm: str | None = None
    not_after: float | None = None  # epoch seconds (UTC)
    renew_until: float | None = None  # epoch seconds (UTC)

    @property
    def has_link(self) -> bool:
        return self.username is not None and self.keytab_b64 is not None

    @property
    def has_ticket(self) -> bool:
        return self.ccache_b64 is not None and self.not_after is not None


class Krb5VaultStore:
    """Per-subject krb5 link/ticket store backed by Vault/OpenBao KV-v2.

    Not thread-safe across processes (Vault's CAS semantics on the KV-v2
    write handle cross-replica races; ``VaultKV`` only guards its own
    in-process re-authentication with an ``asyncio.Lock``).
    """

    def __init__(self, *, vault_kv: VaultKV, kv_path_prefix: str) -> None:
        self._vault_kv = vault_kv
        self._kv_path_prefix = kv_path_prefix.strip("/")

    def _path(self, subject: str) -> str:
        return f"{self._kv_path_prefix}/{subject}/krb5"

    async def _read(self, subject: str) -> tuple[StoredKrb5Credential, int] | None:
        got = await self._vault_kv.get(self._path(subject))
        if got is None:
            return None
        data, version = got
        return _record_from_dict(data), version

    async def store_link(
        self, subject: str, *, username: str, keytab_b64: SecretStr
    ) -> None:
        """Record *subject*'s username and keytab, preserving the ticket half.

        Unlike x509's ``store_link`` (which wipes a stale proxy on re-link,
        since a new passphrase may not be able to re-mint the old one), a
        krb5 ticket's validity has nothing to do with which keytab is
        currently on file -- a still-good ticket must survive a (re-)link.
        """

        def _merge(current: StoredKrb5Credential | None) -> StoredKrb5Credential:
            base = current if current is not None else StoredKrb5Credential()
            return replace(base, username=username, keytab_b64=keytab_b64)

        await self._write_cas_retry(subject, _merge)

    async def get_link(self, subject: str) -> StoredKrb5Credential | None:
        """Return the record when its link half is complete (username + keytab), else None."""
        got = await self._read(subject)
        if got is None:
            return None
        record, _version = got
        return record if record.has_link else None

    async def store_ticket(
        self,
        subject: str,
        *,
        ccache_b64: SecretStr,
        principal: str,
        realm: str,
        not_after: float,
        renew_until: float | None,
    ) -> None:
        """Merge a freshly-minted ticket into *subject*'s record, preserving the link half."""

        def _merge(current: StoredKrb5Credential | None) -> StoredKrb5Credential:
            base = current if current is not None else StoredKrb5Credential()
            return replace(
                base,
                ccache_b64=ccache_b64,
                principal=principal,
                realm=realm,
                not_after=not_after,
                renew_until=renew_until,
            )

        await self._write_cas_retry(subject, _merge)

    async def get_ticket(
        self, subject: str, min_remaining: float = 0.0
    ) -> StoredKrb5Credential | None:
        """Return the record when it holds a ticket with at least *min_remaining* seconds of validity left, else None.

        Expiry-aware by design: an expired (or nearly-expired) ticket is
        reported as absent so callers fall through to the renewal/re-mint
        tiers instead of serving a credential the recipient cannot use.
        """
        got = await self._read(subject)
        if got is None:
            return None
        record, _version = got
        if not record.has_ticket:
            return None
        assert record.not_after is not None  # has_ticket guarantees this
        if record.not_after - time.time() < min_remaining:
            return None
        return record

    async def get_renewable_ticket(self, subject: str) -> StoredKrb5Credential | None:
        """Return the record when its ticket half is still within its own ``renew_until`` window, else None.

        Deliberately separate from ``get_ticket``: this answers "is there a
        ccache that ``client.renew()`` can still extend", which stays true
        well past ``not_after`` -- a VOMS proxy has no equivalent second,
        later deadline, so x509 has no analogous accessor.
        """
        got = await self._read(subject)
        if got is None:
            return None
        record, _version = got
        if not record.has_ticket:
            return None
        if record.renew_until is None or record.renew_until <= time.time():
            return None
        return record

    async def clear_ticket(self, subject: str) -> None:
        """Remove *subject*'s stored ticket while keeping the link half.

        A subject with no record at all is a no-op.
        """
        if await self._read(subject) is None:
            return

        def _clear(current: StoredKrb5Credential | None) -> StoredKrb5Credential:
            base = current if current is not None else StoredKrb5Credential()
            return replace(
                base,
                ccache_b64=None,
                principal=None,
                realm=None,
                not_after=None,
                renew_until=None,
            )

        await self._write_cas_retry(subject, _clear)

    async def delete(self, subject: str) -> None:
        """Unlink *subject*: destroy the record -- keytab, ticket, and all KV-v2 version history."""
        await self._vault_kv.delete_metadata(self._path(subject))

    async def _write_cas_retry(
        self,
        subject: str,
        build: Callable[[StoredKrb5Credential | None], StoredKrb5Credential],
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


def _record_from_dict(data: dict[str, Any]) -> StoredKrb5Credential:
    """Reconstruct a ``StoredKrb5Credential`` from a raw Vault-stored payload.

    Mirrors ``StoredX509Credential.model_validate``'s job of re-wrapping
    plain strings into ``SecretStr`` on read -- ``dataclass`` has no
    built-in validation round trip, so this does it explicitly.
    """
    keytab_b64 = data.get("keytab_b64")
    ccache_b64 = data.get("ccache_b64")
    return StoredKrb5Credential(
        username=data.get("username"),
        keytab_b64=SecretStr(keytab_b64) if keytab_b64 is not None else None,
        ccache_b64=SecretStr(ccache_b64) if ccache_b64 is not None else None,
        principal=data.get("principal"),
        realm=data.get("realm"),
        not_after=data.get("not_after"),
        renew_until=data.get("renew_until"),
    )


def _reveal_secrets(record: StoredKrb5Credential) -> dict[str, Any]:
    """Serialize *record* for Vault storage with ``SecretStr`` fields revealed.

    Mirrors ``x509_vault.py``'s ``_reveal_secrets``: the plain values are
    read back out of the ``SecretStr`` wrappers before the payload is sent,
    since persistence needs the real secret, not pydantic's masked repr.
    """
    return {
        "username": record.username,
        "keytab_b64": (
            record.keytab_b64.get_secret_value()
            if record.keytab_b64 is not None
            else None
        ),
        "ccache_b64": (
            record.ccache_b64.get_secret_value()
            if record.ccache_b64 is not None
            else None
        ),
        "principal": record.principal,
        "realm": record.realm,
        "not_after": record.not_after,
        "renew_until": record.renew_until,
    }
