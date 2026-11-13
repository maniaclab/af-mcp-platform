"""Integration tests: the unlock limiter's budget is shared across replicas.

Two ``CredentialCache`` instances over one real redis server stand in for two
broker replicas (see the ``shared_state_url`` fixture); nothing is mocked.
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING

import pytest

from af_mcp_broker.credentials.cache import CredentialCache
from af_mcp_broker.credentials.errors import UnlockRateLimitError
from af_mcp_broker.shared_state import RedisSharedState

if TYPE_CHECKING:
    from collections.abc import AsyncIterator


@pytest.fixture
def uid() -> int:
    # The server outlives each test, so every test gets its own uid.
    return uuid.uuid4().int % 1_000_000_000


@pytest.fixture
async def replicas(shared_state_url: str) -> AsyncIterator[list[CredentialCache]]:
    stores = [RedisSharedState(shared_state_url) for _ in range(2)]
    yield [
        CredentialCache(
            max_failed_unlocks=3, unlock_window_seconds=60, shared_state=store
        )
        for store in stores
    ]
    for store in stores:
        await store.close()


async def test_failures_on_different_replicas_share_one_budget(
    replicas: list[CredentialCache], uid: int
) -> None:
    replica_a, replica_b = replicas
    # 3 failures are allowed; alternate replicas so neither sees more than 2.
    await replica_a.record_failed_unlock(uid)
    await replica_b.record_failed_unlock(uid)
    await replica_a.record_failed_unlock(uid)

    with pytest.raises(UnlockRateLimitError) as excinfo:
        await replica_b.record_failed_unlock(uid)

    assert 0 < excinfo.value.retry_after_seconds <= 60


async def test_lockout_is_visible_to_the_other_replicas_precheck(
    replicas: list[CredentialCache], uid: int
) -> None:
    replica_a, replica_b = replicas
    for _ in range(3):
        await replica_a.record_failed_unlock(uid)
    with pytest.raises(UnlockRateLimitError):
        await replica_a.record_failed_unlock(uid)

    with pytest.raises(UnlockRateLimitError) as excinfo:
        await replica_b.check_unlock_rate_limit(uid)

    assert 0 < excinfo.value.retry_after_seconds <= 60


async def test_successful_put_on_one_replica_resets_the_budget_everywhere(
    replicas: list[CredentialCache], uid: int
) -> None:
    replica_a, replica_b = replicas
    for _ in range(3):
        await replica_a.record_failed_unlock(uid)

    await replica_b.put("sub", "target", object(), uid=uid)

    await replica_a.check_unlock_rate_limit(uid)  # no longer locked out
    for _ in range(3):
        await replica_a.record_failed_unlock(uid)  # a fresh full budget


async def test_other_uids_are_unaffected(
    replicas: list[CredentialCache], uid: int
) -> None:
    replica_a, replica_b = replicas
    for _ in range(3):
        await replica_a.record_failed_unlock(uid)
    with pytest.raises(UnlockRateLimitError):
        await replica_a.record_failed_unlock(uid)

    await replica_b.check_unlock_rate_limit(uid + 1)


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
