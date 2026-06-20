from __future__ import annotations

import asyncio
import os
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import structlog

from af_mcp_broker.credentials.base import CredentialKind, IssuedCredential

if TYPE_CHECKING:
    pass

log = structlog.get_logger(__name__)

# Seconds between janitor sweeps for expired entries
_JANITOR_INTERVAL_SECONDS = 60

# Rate-limit: allow at most this many failed unlock attempts per window
_MAX_FAILED_UNLOCKS = 5
_UNLOCK_WINDOW_SECONDS = 15 * 60  # 15 minutes


@dataclass
class ProxyMeta:
    """Metadata for a live x509 proxy stored on the broker's tmpfs.

    The proxy file itself is stored at *proxy_path*; this struct carries the
    parsed attributes so callers can check validity without reading the file.
    """

    dn: str
    voms_attributes: list[str]  # e.g. ["/atlas/Role=production", "/atlas"]
    not_after: float  # epoch seconds (UTC) — proxy expiry
    proxy_path: str  # absolute path inside broker's tmpfs, e.g. /run/broker/proxies/{uid}/proxy.pem


@dataclass
class _CacheEntry:
    credential: IssuedCredential
    proxy_meta: ProxyMeta | None = None  # populated only for x509 credentials


@dataclass
class _FailedUnlockRecord:
    attempts: int = 0
    window_start: float = field(default_factory=time.monotonic)


class CredentialCache:
    """Per-principal in-memory credential cache.

    Keyed by ``(uid: int, target: str)`` — the numeric UID is authoritative.
    Subject strings are not used as cache keys because they can be spoofed or
    rotated; UIDs are assigned by the provisioning system and are stable.

    Thread-safety: all public methods are coroutine-safe because asyncio is
    single-threaded within a single event loop.  Do not share this instance
    across multiple event loops.
    """

    def __init__(self) -> None:
        # (uid, target) -> _CacheEntry
        self._entries: dict[tuple[int, str], _CacheEntry] = {}
        # uid -> _FailedUnlockRecord (for rate-limiting bad passphrase attempts)
        self._failed_unlocks: dict[int, _FailedUnlockRecord] = defaultdict(
            _FailedUnlockRecord
        )
        self._janitor_task: asyncio.Task | None = None
        self._log = structlog.get_logger(__name__).bind(component="CredentialCache")

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start_janitor(self) -> None:
        """Schedule the background expiry sweep.  Call once at startup."""
        if self._janitor_task is None or self._janitor_task.done():
            self._janitor_task = asyncio.create_task(
                self._janitor_loop(), name="credential-cache-janitor"
            )
            self._log.info("credential_cache.janitor_started")

    async def stop_janitor(self) -> None:
        """Cancel the janitor task gracefully.  Call on shutdown."""
        if self._janitor_task and not self._janitor_task.done():
            self._janitor_task.cancel()
            try:
                await self._janitor_task
            except asyncio.CancelledError:
                pass
            self._log.info("credential_cache.janitor_stopped")

    # ------------------------------------------------------------------
    # Public cache API
    # ------------------------------------------------------------------

    def remaining_seconds(self, entry: _CacheEntry) -> float:
        """Seconds until *entry*'s credential expires (may be negative)."""
        return entry.credential.expires_at - time.time()

    def get(
        self,
        uid: int,
        target: str,
        min_remaining: int = 300,
    ) -> IssuedCredential | None:
        """Return a cached credential if still valid, else None.

        A credential is considered stale when fewer than *min_remaining*
        seconds remain — this prevents handing a credential to a caller that
        will expire before it can use it.
        """
        key = (uid, target)
        entry = self._entries.get(key)
        if entry is None:
            return None
        if self.remaining_seconds(entry) < min_remaining:
            self._log.debug(
                "credential_cache.miss_expired",
                uid=uid,
                target=target,
                remaining=self.remaining_seconds(entry),
            )
            return None
        return entry.credential

    def put(
        self,
        uid: int,
        target: str,
        cred: IssuedCredential,
        proxy_meta: ProxyMeta | None = None,
    ) -> None:
        """Store *cred* in the cache, optionally with *proxy_meta* for x509."""
        key = (uid, target)
        self._entries[key] = _CacheEntry(credential=cred, proxy_meta=proxy_meta)
        self._log.debug(
            "credential_cache.put",
            uid=uid,
            target=target,
            cred_class=cred.cred_class,
            expires_at=cred.expires_at,
        )

    async def revoke(self, uid: int, target: str) -> None:
        """Revoke a single cached credential.

        For x509 credentials, zero-overwrites and unlinks the proxy file on
        the broker's tmpfs before removing the cache entry.  This prevents
        the proxy from being read by another process even briefly after revoke.
        """
        key = (uid, target)
        entry = self._entries.pop(key, None)
        if entry is None:
            return
        if entry.proxy_meta is not None:
            await _secure_delete_proxy(entry.proxy_meta.proxy_path)
        self._log.info(
            "credential_cache.revoked",
            uid=uid,
            target=target,
            cred_class=entry.credential.cred_class,
        )

    async def revoke_all(self, uid: int) -> None:
        """Revoke all cached credentials for *uid* — call on logout."""
        targets = [t for (u, t) in list(self._entries) if u == uid]
        for target in targets:
            await self.revoke(uid, target)
        self._log.info("credential_cache.revoked_all", uid=uid, count=len(targets))

    def get_proxy_meta(self, uid: int, target: str) -> ProxyMeta | None:
        """Return the ProxyMeta for a cached x509 credential, or None."""
        entry = self._entries.get((uid, target))
        if entry is None:
            return None
        return entry.proxy_meta

    # ------------------------------------------------------------------
    # Rate-limiting for bad passphrase attempts
    # ------------------------------------------------------------------

    def record_failed_unlock(self, uid: int) -> None:
        """Increment the failed-unlock counter for *uid*."""
        now = time.monotonic()
        record = self._failed_unlocks[uid]
        # Reset window if it has elapsed
        if now - record.window_start > _UNLOCK_WINDOW_SECONDS:
            record.attempts = 0
            record.window_start = now
        record.attempts += 1
        self._log.warning(
            "credential_cache.failed_unlock",
            uid=uid,
            attempts=record.attempts,
            window_seconds=_UNLOCK_WINDOW_SECONDS,
        )

    def check_unlock_rate_limit(self, uid: int) -> None:
        """Raise ``PermissionError`` if *uid* has exceeded the failed-unlock limit.

        Callers should invoke this *before* attempting to mint a new proxy so
        that a brute-force passphrase attempt is blocked before any credential
        operation begins.
        """
        now = time.monotonic()
        record = self._failed_unlocks.get(uid)
        if record is None:
            return
        if now - record.window_start > _UNLOCK_WINDOW_SECONDS:
            # Window expired — reset and allow
            self._failed_unlocks[uid] = _FailedUnlockRecord()
            return
        if record.attempts >= _MAX_FAILED_UNLOCKS:
            remaining_window = int(
                _UNLOCK_WINDOW_SECONDS - (now - record.window_start)
            )
            raise PermissionError(
                f"Too many failed passphrase attempts for uid={uid}. "
                f"Try again in {remaining_window}s."
            )

    # ------------------------------------------------------------------
    # Background janitor
    # ------------------------------------------------------------------

    async def _janitor_loop(self) -> None:
        """Periodically scan for expired entries and revoke them."""
        while True:
            await asyncio.sleep(_JANITOR_INTERVAL_SECONDS)
            await self._sweep_expired()

    async def _sweep_expired(self) -> None:
        now = time.time()
        expired = [
            (uid, target)
            for (uid, target), entry in list(self._entries.items())
            if entry.credential.expires_at <= now
        ]
        for uid, target in expired:
            self._log.info(
                "credential_cache.janitor_expiring",
                uid=uid,
                target=target,
            )
            await self.revoke(uid, target)


# ------------------------------------------------------------------
# Internal helpers
# ------------------------------------------------------------------


async def _secure_delete_proxy(path: str) -> None:
    """Zero-overwrite *path* then unlink it.

    The goal is to make the proxy bytes unrecoverable from the tmpfs even if
    another process has the path.  We overwrite with NUL bytes first so that
    the file content is gone before the directory entry is removed.
    """
    try:
        size = os.path.getsize(path)
        # Run the blocking I/O on the default executor to avoid stalling the loop
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, _overwrite_and_unlink, path, size)
    except FileNotFoundError:
        pass  # already gone — that is fine
    except OSError as exc:
        log.warning("credential_cache.proxy_delete_error", path=path, error=str(exc))


def _overwrite_and_unlink(path: str, size: int) -> None:
    """Blocking: overwrite *path* with zeros then unlink."""
    try:
        with open(path, "r+b") as fh:
            fh.write(b"\x00" * size)
            fh.flush()
            os.fsync(fh.fileno())
    except OSError:
        pass  # best-effort
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
