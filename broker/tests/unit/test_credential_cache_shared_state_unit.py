"""Unit tests for the area ``test_credential_cache_shared_state.py`` covers; the integration tests live in ``integration/test_credential_cache_shared_state.py``."""

from __future__ import annotations

import uuid

import pytest

from af_mcp_broker.credentials.cache import CredentialCache
from af_mcp_broker.credentials.errors import UnlockRateLimitError
from af_mcp_broker.shared_state import RedisSharedState


@pytest.fixture
def uid() -> int:
    # The server outlives each test, so every test gets its own uid.
    return uuid.uuid4().int % 1_000_000_000


async def test_store_outage_falls_back_to_a_per_replica_limit(
    unreachable_shared_state_url: str, uid: int
) -> None:
    store = RedisSharedState(unreachable_shared_state_url)
    cache = CredentialCache(
        max_failed_unlocks=2, unlock_window_seconds=60, shared_state=store
    )
    try:
        # Still limited, per replica, instead of failing open or erroring.
        await cache.record_failed_unlock(uid)
        await cache.record_failed_unlock(uid)
        with pytest.raises(UnlockRateLimitError):
            await cache.record_failed_unlock(uid)
        with pytest.raises(UnlockRateLimitError):
            await cache.check_unlock_rate_limit(uid)

        # A successful unlock still clears the per-replica counter.
        await cache.put("sub", "target", object(), uid=uid)
        await cache.check_unlock_rate_limit(uid)
    finally:
        await store.close()
