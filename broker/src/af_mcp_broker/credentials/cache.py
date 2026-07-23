from __future__ import annotations

import asyncio
import contextlib
import os
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import structlog

from af_mcp_broker.credentials.base import IssuedCredential

log = structlog.get_logger(__name__)

# Seconds between janitor sweeps for expired entries
_JANITOR_INTERVAL_SECONDS = 60

# Default TTL used when expires_at is not supplied to put()
_DEFAULT_TTL_SECONDS = 3600


class RateLimitError(Exception):
    """Raised when a principal exceeds the allowed number of failed cache lookups.

    *retry_after_seconds* is how long until the current fixed window closes
    and the uid is allowed to try again — ``max(0, window_start +
    unlock_window_seconds - now)``. The API layer's exception handler formats
    this into a ``Retry-After`` header and JSON body (see ``app.py``).
    """

    def __init__(self, message: str, *, retry_after_seconds: int) -> None:
        super().__init__(message)
        self.retry_after_seconds = retry_after_seconds


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
    # The stored value — may be an IssuedCredential or any other token/value
    # used by higher-level callers and spike tests.
    credential: Any
    expires_at: float  # epoch seconds (UTC)
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

    Rate-limiting: *max_failed_unlocks* / *unlock_window_seconds* bound how
    many failed cache lookups (misses) or bad passphrase attempts a single
    uid may accrue before ``RateLimitError`` is raised — see ``_record_miss``
    and ``check_unlock_rate_limit``. Production wiring reads these from
    ``Settings.credential_unlock_max_failures`` /
    ``Settings.credential_unlock_window_seconds`` (see ``app.py`` lifespan);
    the defaults here exist only so callers that construct ``CredentialCache``
    without Settings (tests, spikes) keep the pre-existing behaviour.
    """

    def __init__(
        self,
        max_failed_unlocks: int = 5,
        unlock_window_seconds: int = 15 * 60,
    ) -> None:
        # (uid, target) -> _CacheEntry
        self._entries: dict[tuple[int, str], _CacheEntry] = {}
        # uid -> _FailedUnlockRecord (for rate-limiting missed lookups)
        self._failed_unlocks: dict[int, _FailedUnlockRecord] = defaultdict(
            _FailedUnlockRecord
        )
        self._max_failed_unlocks = max_failed_unlocks
        self._unlock_window_seconds = unlock_window_seconds
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
            with contextlib.suppress(asyncio.CancelledError):
                await self._janitor_task
            self._log.info("credential_cache.janitor_stopped")

    # ------------------------------------------------------------------
    # Public cache API
    # ------------------------------------------------------------------

    def remaining_seconds(self, entry: _CacheEntry) -> float:
        """Seconds until *entry* expires (may be negative)."""
        return entry.expires_at - time.time()

    async def get(
        self,
        uid: int,
        target: str,
        min_remaining: int = 300,
    ) -> Any | None:
        """Return a cached value if still valid, else None.

        A value is considered stale when fewer than *min_remaining* seconds
        remain — this prevents handing a credential to a caller that will
        expire before it can use it.

        Each cache miss is counted against *uid*. After ``max_failed_unlocks``
        misses within ``unlock_window_seconds`` (constructor parameters),
        ``RateLimitError`` is raised to prevent brute-force enumeration.
        """
        key = (uid, target)
        entry = self._entries.get(key)
        if entry is None or self.remaining_seconds(entry) < min_remaining:
            if entry is not None:
                self._log.debug(
                    "credential_cache.miss_expired",
                    uid=uid,
                    target=target,
                    remaining=self.remaining_seconds(entry),
                )
            self._record_miss(uid)
            return None
        return entry.credential

    async def put(
        self,
        uid: int,
        target: str,
        cred: Any,
        *,
        expires_at: float | None = None,
        proxy_meta: ProxyMeta | None = None,
    ) -> None:
        """Store *cred* in the cache.

        *expires_at* is epoch seconds (UTC). When omitted a default TTL of
        ``_DEFAULT_TTL_SECONDS`` is applied.  Pass ``proxy_meta`` for x509
        credentials so ``revoke()`` can zero-overwrite the proxy file.
        """
        if expires_at is None:
            expires_at = time.time() + _DEFAULT_TTL_SECONDS
        key = (uid, target)
        self._entries[key] = _CacheEntry(
            credential=cred, expires_at=expires_at, proxy_meta=proxy_meta
        )
        # A successful put resets the failed-lookup counter for this uid so
        # that legitimate re-authentication after expiry isn't penalised.
        self._failed_unlocks.pop(uid, None)
        self._log.debug(
            "credential_cache.put",
            uid=uid,
            target=target,
            expires_at=expires_at,
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
        cred_class = (
            entry.credential.cred_class
            if isinstance(entry.credential, IssuedCredential)
            else type(entry.credential).__name__
        )
        self._log.info(
            "credential_cache.revoked",
            uid=uid,
            target=target,
            cred_class=cred_class,
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
    # Rate-limiting for missed lookups / bad passphrase attempts
    # ------------------------------------------------------------------

    def _record_miss(self, uid: int) -> None:
        """Increment the miss counter for *uid* and raise RateLimitError when exceeded."""
        now = time.monotonic()
        record = self._failed_unlocks[uid]
        # Reset window if it has elapsed
        if now - record.window_start > self._unlock_window_seconds:
            record.attempts = 0
            record.window_start = now
        record.attempts += 1
        self._log.debug(
            "credential_cache.miss_recorded",
            uid=uid,
            attempts=record.attempts,
            window_seconds=self._unlock_window_seconds,
        )
        if record.attempts > self._max_failed_unlocks:
            remaining_window = max(
                0, int(self._unlock_window_seconds - (now - record.window_start))
            )
            raise RateLimitError(
                f"Too many failed cache lookups for uid={uid}. "
                f"Try again in {remaining_window}s.",
                retry_after_seconds=remaining_window,
            )

    def record_failed_unlock(self, uid: int) -> None:
        """Increment the failed-unlock counter for *uid*.

        Kept for backward-compatibility with callers that track passphrase
        failures separately from cache misses.
        """
        self._record_miss(uid)

    def check_unlock_rate_limit(self, uid: int) -> None:
        """Raise ``RateLimitError`` if *uid* has exceeded the failed-unlock limit.

        Callers should invoke this *before* attempting to mint a new proxy so
        that a brute-force passphrase attempt is blocked before any credential
        operation begins.
        """
        now = time.monotonic()
        record = self._failed_unlocks.get(uid)
        if record is None:
            return
        if now - record.window_start > self._unlock_window_seconds:
            # Window expired — reset and allow
            self._failed_unlocks[uid] = _FailedUnlockRecord()
            return
        if record.attempts > self._max_failed_unlocks:
            remaining_window = max(
                0, int(self._unlock_window_seconds - (now - record.window_start))
            )
            raise RateLimitError(
                f"Too many failed passphrase attempts for uid={uid}. "
                f"Try again in {remaining_window}s.",
                retry_after_seconds=remaining_window,
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
            if entry.expires_at <= now
        ]
        for uid, target in expired:
            self._log.info(
                "credential_cache.janitor_expiring",
                uid=uid,
                target=target,
            )
            await self.revoke(uid, target)

    async def sweep_expired(self) -> None:
        """Public alias for the janitor sweep — useful in tests and admin tooling."""
        await self._sweep_expired()


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
        size = Path(path).stat().st_size
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
        with Path(path).open("r+b") as fh:
            fh.write(b"\x00" * size)
            fh.flush()
            os.fsync(fh.fileno())
    except OSError:
        pass  # best-effort
    with contextlib.suppress(FileNotFoundError):
        Path(path).unlink()
