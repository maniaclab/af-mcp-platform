from __future__ import annotations

import asyncio
import contextlib
import os
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

import structlog

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

from af_mcp_broker import metrics
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
    """Metadata for a live x509 proxy.

    For the legacy mint path the proxy file itself is stored at
    *proxy_path*; this struct carries the parsed attributes so callers can
    check validity without reading the file. In voms-token-service mode the
    PEM persists in Vault instead of any local file, so *proxy_path* is
    None.
    """

    dn: str
    voms_attributes: list[str]  # e.g. ["/atlas/Role=production", "/atlas"]
    not_after: float  # epoch seconds (UTC) — proxy expiry
    # Absolute path inside broker's tmpfs, e.g.
    # /run/broker/proxies/{uid}/proxy.pem; None when the PEM lives in Vault.
    proxy_path: str | None = None


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

    Keyed by ``(subject: str, target: str)`` -- ``principal.subject`` (issue
    #148). Used to be keyed by numeric uid on the reasoning that "subject
    strings can be spoofed or rotated; uids are provisioning-assigned and
    stable" -- but issue #148 made ``Principal.uid`` optional (most
    principals never touch a filesystem and have no POSIX identity at all),
    and this cache is shared by every credential provider (X509Provider,
    OIDCProvider, ...), including ones with no POSIX-identity need of their
    own. Keying by uid in that world means every principal without one
    collides on the same ``(None, target)`` slot -- a real credential-
    isolation bug, not a hypothetical one, since one principal's cached
    bearer token would then be handed to another. ``subject`` is always
    present (a validated JWT's `sub` claim, or a PAT's stored owner id) and
    is exactly as unspoofable as uid ever was -- both are read from a
    source already authenticated before either field is ever consulted --
    so it is the one identifier every caller of this cache can rely on.
    Using one consistent key across every provider also keeps
    ``revoke_all()``/``get_proxy_meta()`` correct: they are called by uid-
    agnostic code (``DELETE /v1/credential``, the identities-unlink route)
    that must reach every provider's entries for a principal, not just
    whichever provider happens to still key by whatever this class used
    internally.

    ``record_failed_unlock``/``check_unlock_rate_limit`` below are the one
    exception: they remain keyed by ``uid: int``, not subject. Only
    ``X509Provider`` ever calls them (passphrase brute-force protection for
    a specific ``~/.globus``), and X509Provider requires POSIX identity to
    be present before it calls anything past this point (see
    ``credentials.x509.PosixIdentityRequiredError``) -- unlike the
    credential-storage methods above, there is no cross-provider sharing
    to keep consistent, so there is no reason to key this half by anything
    other than the uid the rate limit is conceptually protecting.

    Thread-safety: all public methods are coroutine-safe because asyncio is
    single-threaded within a single event loop.  Do not share this instance
    across multiple event loops.

    Rate-limiting: *max_failed_unlocks* / *unlock_window_seconds* bound how
    many actual failed unlock attempts (bad passphrase, or a minting-backend
    failure) a single uid may accrue before ``RateLimitError`` is raised —
    see ``record_failed_unlock`` and ``check_unlock_rate_limit``. Plain cache
    misses from ``get()`` do not count against this budget — see ``get()``'s
    docstring. Production wiring reads these from
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
        # (subject, target) -> _CacheEntry
        self._entries: dict[tuple[str, str], _CacheEntry] = {}
        # uid -> _FailedUnlockRecord (for rate-limiting missed lookups) --
        # deliberately still uid-keyed, see this class's docstring.
        self._failed_unlocks: dict[int, _FailedUnlockRecord] = defaultdict(
            _FailedUnlockRecord
        )
        # (subject, target) -> asyncio.Lock, single-flighting concurrent
        # mints for the same key (see get_or_mint()). Never cleaned up, same
        # as _failed_unlocks above -- the key space is bounded by real
        # authenticated principals and configured backend targets, not
        # attacker-controlled, so leaving idle Locks around is harmless.
        self._mint_locks: dict[tuple[str, str], asyncio.Lock] = defaultdict(
            asyncio.Lock
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

    def _lookup(self, subject: str, target: str, min_remaining: int) -> Any | None:
        """Return a cached value if still valid, else None -- no metrics.

        The actual entry-freshness check, shared by ``get()`` (which records
        the Prometheus hit/miss counters) and ``get_or_mint()``'s internal
        double-check-locking re-read (which must NOT record a second sample
        for what is, from a caller's point of view, still the same single
        cache probe -- see ``get_or_mint()``'s docstring).
        """
        key = (subject, target)
        entry = self._entries.get(key)
        if entry is None or self.remaining_seconds(entry) < min_remaining:
            if entry is not None:
                self._log.debug(
                    "credential_cache.miss_expired",
                    subject=subject,
                    target=target,
                    remaining=self.remaining_seconds(entry),
                )
            return None
        return entry.credential

    async def get(
        self,
        subject: str,
        target: str,
        min_remaining: int = 300,
    ) -> Any | None:
        """Return a cached value if still valid, else None.

        A value is considered stale when fewer than *min_remaining* seconds
        remain — this prevents handing a credential to a caller that will
        expire before it can use it.

        A plain miss (nothing cached, or a stale entry) does *not* count
        against any unlock rate limit — only an actual failed unlock
        attempt does (see ``record_failed_unlock``). Counting misses here
        made every ordinary "not cached yet" probe indistinguishable from a
        bad passphrase attempt, so a handful of routine retries could lock a
        user out of their own next (correct) unlock attempt.

        Records the ``af_mcp_credential_cache_hits_total`` /
        ``..._misses_total`` Prometheus counters, labeled by *target* (a
        configured backend name, not user input). ``get_or_mint()``'s
        internal re-check calls ``_lookup()`` directly instead of this
        method, precisely so it doesn't double-count the same logical probe.
        """
        value = self._lookup(subject, target, min_remaining)
        if value is None:
            metrics.credential_cache_misses_total.labels(target=target).inc()
        else:
            metrics.credential_cache_hits_total.labels(target=target).inc()
        return value

    async def get_or_mint(
        self,
        subject: str,
        target: str,
        min_remaining: int,
        mint: Callable[[], Awaitable[Any]],
    ) -> Any:
        """Single-flight a mint for *(subject, target)*.

        Concurrent callers that each independently miss the cache for the
        same key would otherwise each repeat *mint* — an expensive, real
        -resource operation (a Keycloak round-trip, or a k8s Job) — instead
        of the N-1 redundant callers reusing the one already in flight.
        Callers are expected to have already called ``get()`` and found a
        miss before calling this; it only serializes what happens *after*
        that miss, so a cache hit still short-circuits before ever touching
        the per-key lock.

        Once the per-key lock is acquired, the cache is re-checked — another
        caller may have completed a mint (and called ``put()``) while this
        one was waiting — and *mint* is only invoked if it's still empty.
        *mint* is expected to store its own result via ``put()``, exactly as
        callers already do on the non-single-flighted path. This re-check
        calls ``_lookup()`` (not ``get()``) so it doesn't record a second
        Prometheus sample for the same logical probe the caller's own
        ``get()`` call already counted.
        """
        async with self._mint_locks[(subject, target)]:
            cached = self._lookup(subject, target, min_remaining)
            if cached is not None:
                return cached
            return await mint()

    async def put(
        self,
        subject: str,
        target: str,
        cred: Any,
        *,
        expires_at: float | None = None,
        proxy_meta: ProxyMeta | None = None,
        uid: int | None = None,
    ) -> None:
        """Store *cred* in the cache.

        *expires_at* is epoch seconds (UTC). When omitted a default TTL of
        ``_DEFAULT_TTL_SECONDS`` is applied.  Pass ``proxy_meta`` for x509
        credentials so ``revoke()`` can zero-overwrite the proxy file.

        *uid*, when given, resets that uid's failed-unlock counter -- a
        successful put means a legitimate re-authentication (e.g. a correct
        passphrase) just happened, so it shouldn't count towards a future
        lockout. Only ``X509Provider`` ever passes this (the one caller with
        an unlock rate limit to reset); every other provider omits it, since
        a bearer-token refresh has no passphrase rate limit to reset in the
        first place, and `principal.uid` may not even exist for its caller
        (issue #148).
        """
        if expires_at is None:
            expires_at = time.time() + _DEFAULT_TTL_SECONDS
        key = (subject, target)
        self._entries[key] = _CacheEntry(
            credential=cred, expires_at=expires_at, proxy_meta=proxy_meta
        )
        if uid is not None:
            self._failed_unlocks.pop(uid, None)
        self._log.debug(
            "credential_cache.put",
            subject=subject,
            target=target,
            expires_at=expires_at,
        )

    async def revoke(self, subject: str, target: str) -> None:
        """Revoke a single cached credential.

        For x509 credentials, zero-overwrites and unlinks the proxy file on
        the broker's tmpfs before removing the cache entry.  This prevents
        the proxy from being read by another process even briefly after revoke.
        """
        key = (subject, target)
        entry = self._entries.pop(key, None)
        if entry is None:
            return
        # proxy_path is None for Vault-persisted proxies (no local file to
        # delete; X509Provider.revoke clears the Vault copy itself).
        if entry.proxy_meta is not None and entry.proxy_meta.proxy_path is not None:
            await _secure_delete_proxy(entry.proxy_meta.proxy_path)
        cred_class = (
            entry.credential.cred_class
            if isinstance(entry.credential, IssuedCredential)
            else type(entry.credential).__name__
        )
        self._log.info(
            "credential_cache.revoked",
            subject=subject,
            target=target,
            cred_class=cred_class,
        )

    async def revoke_all(self, subject: str) -> None:
        """Revoke all cached credentials for *subject* — call on logout."""
        targets = [t for (s, t) in list(self._entries) if s == subject]
        for target in targets:
            await self.revoke(subject, target)
        self._log.info(
            "credential_cache.revoked_all", subject=subject, count=len(targets)
        )

    def get_proxy_meta(self, subject: str, target: str) -> ProxyMeta | None:
        """Return the ProxyMeta for a cached x509 credential, or None."""
        entry = self._entries.get((subject, target))
        if entry is None:
            return None
        return entry.proxy_meta

    # ------------------------------------------------------------------
    # Rate-limiting for failed unlock attempts
    # ------------------------------------------------------------------

    def record_failed_unlock(self, uid: int) -> None:
        """Increment the failed-unlock counter for *uid* and raise ``RateLimitError`` when exceeded.

        Callers invoke this only for an unlock attempt that actually failed
        (bad passphrase, or a minting-backend failure) — plain cache misses
        (see ``get()``) do not consume this budget.
        """
        now = time.monotonic()
        record = self._failed_unlocks[uid]
        # Reset window if it has elapsed
        if now - record.window_start > self._unlock_window_seconds:
            record.attempts = 0
            record.window_start = now
        record.attempts += 1
        self._log.debug(
            "credential_cache.failed_unlock_recorded",
            uid=uid,
            attempts=record.attempts,
            window_seconds=self._unlock_window_seconds,
        )
        if record.attempts > self._max_failed_unlocks:
            remaining_window = max(
                0, int(self._unlock_window_seconds - (now - record.window_start))
            )
            raise RateLimitError(
                f"Too many failed unlock attempts for uid={uid}. "
                f"Try again in {remaining_window}s.",
                retry_after_seconds=remaining_window,
            )

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
