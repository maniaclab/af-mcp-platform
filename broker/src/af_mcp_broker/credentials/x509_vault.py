"""Vault/OpenBao-backed x509 credential store (issue #112 follow-up).

Persists, per subject, everything the voms-token-service mint path needs to
renew a VOMS proxy with no user interaction:

* the Globus key **passphrase** captured at link time — the custodianship
  model chosen in issue #112's design discussion: the broker holds the
  passphrase so future proxies can be minted hands-free, instead of the
  broker (or an ephemeral Job) ever touching the user's home directory;
* the **POSIX identity** (unixname/uid/gid) every mint request asserts —
  captured at link time because renewal paths (the redeem endpoint's
  hands-free re-mint) hold only a broker-token subject, not a live
  ``Principal``;
* the current **proxy PEM** and its dn/voms_attributes/not_after, served on
  redeem until it nears expiry.

One KV-v2 record per subject at ``{kv_path_prefix}/{subject}/x509``, over
the shared ``VaultKV`` transport — this module owns the path layout, the
record shape, and the ``SecretStr`` reveal/reload round trip, mirroring
``credentials/vault.py``'s ``VaultTokenStore``. Writes are read-modify-write
under KV-v2 CAS with a bounded retry: concurrent renewals across replicas
each produce an equally-valid proxy, so absorbing the version race by
re-reading and retrying is correct (last writer wins), unlike the oauth21
store where a lost refresh token makes the conflict caller-visible.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, Field, SecretStr

from af_mcp_broker.vault_kv import CasConflict, VaultKV

if TYPE_CHECKING:
    from collections.abc import Callable

# Read-modify-write attempts before a CAS conflict is allowed to propagate.
# Each retry re-reads the current version, so this only trips if another
# writer keeps winning the race repeatedly.
_CAS_ATTEMPTS = 3


class StoredX509Credential(BaseModel):
    """The per-subject Vault record: link half (passphrase + POSIX identity) plus proxy half (PEM + metadata).

    Either half may be absent: a fresh link has no proxy yet, and a
    defensively-written proxy could exist without a link. ``SecretStr``
    keeps the passphrase and the bearer-equivalent PEM out of repr/logs;
    persistence reveals them explicitly (see ``_reveal_secrets``).
    """

    # Link half
    passphrase: SecretStr | None = None
    unixname: str | None = None
    uid: int | None = None
    gid: int | None = None

    # Proxy half
    proxy_pem: SecretStr | None = None
    dn: str | None = None
    voms_attributes: list[str] = Field(default_factory=list)
    not_after: float | None = None  # epoch seconds (UTC)

    @property
    def has_link(self) -> bool:
        """Whether the link half is complete enough to re-mint from: passphrase plus the full POSIX identity the mint request asserts."""
        return (
            self.passphrase is not None
            and self.unixname is not None
            and self.uid is not None
            and self.gid is not None
        )


class VaultX509Store:
    """Per-subject x509 link/proxy store backed by Vault/OpenBao KV-v2.

    Not thread-safe across processes (Vault's CAS semantics on the KV-v2
    write handle cross-replica races; ``VaultKV`` only guards its own
    in-process re-authentication with an ``asyncio.Lock``).
    """

    def __init__(self, *, vault_kv: VaultKV, kv_path_prefix: str) -> None:
        self._vault_kv = vault_kv
        self._kv_path_prefix = kv_path_prefix.strip("/")

    def _path(self, subject: str) -> str:
        return f"{self._kv_path_prefix}/{subject}/x509"

    async def _read(self, subject: str) -> tuple[StoredX509Credential, int] | None:
        got = await self._vault_kv.get(self._path(subject))
        if got is None:
            return None
        data, version = got
        return StoredX509Credential.model_validate(data), version

    async def store_link(
        self,
        subject: str,
        *,
        passphrase: SecretStr | None,
        unixname: str,
        uid: int,
        gid: int,
    ) -> None:
        """Record *subject*'s Globus passphrase and POSIX identity.

        ``passphrase=None`` is the remember=false custody mode (the user
        declined passphrase storage at link time): the record carries only
        the POSIX identity, so hands-free renewal paths — which key off
        ``get_link`` — never fire, and the identity reads as linked only
        while the stored proxy is valid (see ``X509Provider.link_status``).

        Writes a fresh record: a (re-)link means a possibly-new passphrase
        (the user changed their Globus password) or a deliberate custody
        change, so neither any previously stored proxy — which may no
        longer be re-mintable — nor a previously stored passphrase survives
        it. The caller stores the freshly-minted proxy right after via
        ``store_proxy``.
        """
        record = StoredX509Credential(
            passphrase=passphrase, unixname=unixname, uid=uid, gid=gid
        )
        await self._write_cas_retry(subject, lambda _current: record)

    async def get(self, subject: str) -> StoredX509Credential | None:
        """Return *subject*'s record whatever its halves hold, or None.

        ``get_link``/``get_proxy`` each answer for one half; ``link_status``
        needs the whole record in one read to tell linked-with-renewal
        (passphrase stored) from linked-until-expiry (valid proxy, no
        passphrase) from unlinked.
        """
        got = await self._read(subject)
        if got is None:
            return None
        record, _version = got
        return record

    async def get_link(self, subject: str) -> StoredX509Credential | None:
        """Return the record when its link half is complete (passphrase + POSIX identity), else None."""
        got = await self._read(subject)
        if got is None:
            return None
        record, _version = got
        return record if record.has_link else None

    async def store_proxy(
        self,
        subject: str,
        *,
        pem: str,
        dn: str,
        voms_attributes: list[str],
        not_after: float,
    ) -> None:
        """Merge a freshly-minted proxy into *subject*'s record, preserving the link half."""

        def _merge(current: StoredX509Credential | None) -> StoredX509Credential:
            base = current if current is not None else StoredX509Credential()
            return base.model_copy(
                update={
                    "proxy_pem": SecretStr(pem),
                    "dn": dn,
                    "voms_attributes": list(voms_attributes),
                    "not_after": not_after,
                }
            )

        await self._write_cas_retry(subject, _merge)

    async def get_proxy(
        self, subject: str, min_remaining: float = 0.0
    ) -> StoredX509Credential | None:
        """Return the record when it holds a proxy with at least *min_remaining* seconds of validity left, else None.

        Expiry-aware by design: an expired (or nearly-expired) proxy is
        reported as absent so callers fall through to the hands-free
        renewal path instead of serving a credential the recipient cannot
        use.
        """
        got = await self._read(subject)
        if got is None:
            return None
        record, _version = got
        if record.proxy_pem is None or record.not_after is None:
            return None
        if record.not_after - time.time() < min_remaining:
            return None
        return record

    async def clear_proxy(self, subject: str) -> None:
        """Remove *subject*'s stored proxy while keeping the link half.

        Proxy revocation must not unlink the identity: the passphrase stays
        so the next issue() renews hands-free. A subject with no record at
        all is a no-op.
        """
        if await self._read(subject) is None:
            return

        def _clear(current: StoredX509Credential | None) -> StoredX509Credential:
            base = current if current is not None else StoredX509Credential()
            return base.model_copy(
                update={
                    "proxy_pem": None,
                    "dn": None,
                    "voms_attributes": [],
                    "not_after": None,
                }
            )

        await self._write_cas_retry(subject, _clear)

    async def delete(self, subject: str) -> None:
        """Unlink *subject*: destroy the record — passphrase, proxy, and all KV-v2 version history."""
        await self._vault_kv.delete_metadata(self._path(subject))

    async def _write_cas_retry(
        self,
        subject: str,
        build: Callable[[StoredX509Credential | None], StoredX509Credential],
    ) -> None:
        """Read-modify-write *subject*'s record under CAS, retrying a bounded number of times on version conflicts.

        *build* maps the current record (or None) to the record to write.
        Retrying re-reads the current version each attempt, so a concurrent
        writer's bump is absorbed rather than surfaced — see the module
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


def _reveal_secrets(record: StoredX509Credential) -> dict[str, Any]:
    """Serialize *record* for Vault storage with ``SecretStr`` fields revealed.

    ``model_dump(mode="json")`` masks ``SecretStr`` fields as ``**********``
    — right for logs, wrong for persistence — so the secret values are read
    back out and substituted in before the payload is sent. On read,
    ``model_validate`` re-wraps the plain strings into ``SecretStr`` on its
    own (same round trip as ``credentials/vault.py``).
    """
    revealed = record.model_dump(mode="json")
    revealed["passphrase"] = (
        record.passphrase.get_secret_value() if record.passphrase is not None else None
    )
    revealed["proxy_pem"] = (
        record.proxy_pem.get_secret_value() if record.proxy_pem is not None else None
    )
    return revealed
