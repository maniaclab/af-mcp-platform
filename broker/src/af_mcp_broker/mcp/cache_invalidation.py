"""Cross-replica invalidation of the aggregator's per-subject listing caches.

Linking or revoking a credential drops the handling replica's cached
tools/list entries for that (subject, service) -- a stale "no tools" entry or
a tool list from the old credential would otherwise be served until its TTL
ran out. ``ListCacheInvalidator`` carries that drop to every other replica
over ``SharedState`` publish/subscribe.

Why pub/sub rather than a per-subject generation counter that readers compare
before serving a cached entry: the listing caches sit on the request path of
every ``tools/list`` and every ``tools/call`` that carries arguments, so a
counter read would put a store round trip (up to the 2 s socket timeout while
the store is down) in front of each of them. With pub/sub the hot path stays
local; the store is touched only by a background subscriber and by the rare
link and revoke events.

Delivery is at-most-once, so a replica that was disconnected misses messages.
It therefore drops *every* cached listing when its subscription is
re-established after an outage, which bounds the staleness an outage can
cause to the outage itself. While the store is down the caches fall back to
TTL-only staleness (30 s for a cached failure, ``tools_cache_ttl`` for a
cached success), the same as running without a store.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from typing import TYPE_CHECKING

import structlog

from af_mcp_broker.shared_state import SharedStateUnavailableError

if TYPE_CHECKING:
    import concurrent.futures
    from collections.abc import Callable

    from af_mcp_broker.shared_state import SharedState

LIST_CACHE_INVALIDATION_CHANNEL = "list-cache-invalidation"

# Seconds to wait before resubscribing after the store fails: first retry,
# then doubling up to the cap.
_DEFAULT_RETRY_DELAYS = (1.0, 30.0)

logger = structlog.get_logger(__name__)


def _parse_message(raw: str) -> tuple[str, str, str | None]:
    """Return (origin, subject, target) from a published message, or raise ValueError, KeyError or TypeError."""
    message = json.loads(raw)
    origin = message["origin"]
    subject = message["subject"]
    target = message["target"]
    if not (
        isinstance(origin, str)
        and isinstance(subject, str)
        and (target is None or isinstance(target, str))
    ):
        raise TypeError("origin, subject and target must be strings")
    return origin, subject, target


class ListCacheInvalidator:
    """Drops a subject's cached listings locally and on every other replica.

    *invalidate* drops *subject*'s entries for one service (*target*) or, with
    ``target=None``, every service; *invalidate_all* drops every subject's
    entries. Both are applied to this replica's caches only.
    """

    def __init__(
        self,
        shared_state: SharedState,
        *,
        invalidate: Callable[[str, str | None], None],
        invalidate_all: Callable[[], None],
        retry_delays: tuple[float, float] = _DEFAULT_RETRY_DELAYS,
    ) -> None:
        self._shared_state = shared_state
        self._invalidate = invalidate
        self._invalidate_all = invalidate_all
        self._retry_delays = retry_delays
        # Tells this replica's own messages apart when they come back from the
        # store: it already dropped those entries before publishing.
        self._origin = uuid.uuid4().hex
        self._loop: asyncio.AbstractEventLoop | None = None
        self._subscriber: asyncio.Task[None] | None = None
        self._publishes: set[concurrent.futures.Future[None]] = set()

    def start(self) -> None:
        """Begin listening for other replicas' invalidations. Call once, on the running loop."""
        if self._subscriber is None:
            self._loop = asyncio.get_running_loop()
            self._subscriber = asyncio.create_task(
                self._subscribe_forever(), name="list-cache-invalidation-subscriber"
            )

    async def stop(self) -> None:
        """Stop listening and abandon any publish still in flight."""
        for publish in [*self._publishes]:
            publish.cancel()
        if self._subscriber is not None:
            subscriber, self._subscriber = self._subscriber, None
            subscriber.cancel()
            await asyncio.gather(subscriber, return_exceptions=True)

    def invalidate(self, subject: str, target: str | None = None) -> None:
        """Drop the entries here now, and tell the other replicas to drop theirs.

        Synchronous so it can serve as the credential cache's link and revoke
        hooks. The local drop completes before this returns; the broadcast is
        scheduled on the loop ``start`` ran on (the store client belongs to
        it, whichever thread calls this) and its failure is logged, never
        raised.
        """
        self._invalidate(subject, target)
        if self._loop is None:
            logger.warning(
                "list_cache_invalidation.not_broadcast",
                reason="not started",
                subject=subject,
                target=target,
            )
            return
        publish = asyncio.run_coroutine_threadsafe(
            self._publish(subject, target), self._loop
        )
        self._publishes.add(publish)
        publish.add_done_callback(self._publishes.discard)

    async def _publish(self, subject: str, target: str | None) -> None:
        message = json.dumps(
            {"origin": self._origin, "subject": subject, "target": target}
        )
        try:
            await self._shared_state.publish(LIST_CACHE_INVALIDATION_CHANNEL, message)
        except SharedStateUnavailableError as exc:
            logger.warning(
                "list_cache_invalidation.shared_state_unavailable",
                error=str(exc),
                effect=(
                    "other replicas keep serving cached listings for this "
                    "subject until their TTL expires"
                ),
                subject=subject,
                target=target,
            )

    async def _subscribe_forever(self) -> None:
        min_delay, max_delay = self._retry_delays
        delay = min_delay
        # True once a subscription has failed: messages published while this
        # replica was not subscribed are lost, so the first subscription after
        # a failure must drop every cached listing.
        missed_messages = False
        while True:
            try:
                async with self._shared_state.subscribe(
                    LIST_CACHE_INVALIDATION_CHANNEL
                ) as messages:
                    delay = min_delay
                    if missed_messages:
                        logger.info("list_cache_invalidation.resubscribed")
                        self._invalidate_all()
                        missed_messages = False
                    async for raw in messages:
                        self._apply(raw)
            except SharedStateUnavailableError as exc:
                missed_messages = True
                logger.warning(
                    "list_cache_invalidation.shared_state_unavailable",
                    error=str(exc),
                    effect=(
                        "cached listings on this replica go stale until their "
                        "TTL expires; resubscribing"
                    ),
                    retry_in_seconds=delay,
                )
                await asyncio.sleep(delay)
                delay = min(delay * 2, max_delay)

    def _apply(self, raw: str) -> None:
        try:
            origin, subject, target = _parse_message(raw)
        except (ValueError, KeyError, TypeError) as exc:
            logger.warning("list_cache_invalidation.bad_message", error=str(exc))
            return
        if origin != self._origin:
            self._invalidate(subject, target)
