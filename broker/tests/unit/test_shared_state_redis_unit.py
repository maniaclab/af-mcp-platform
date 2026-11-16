"""Unit tests for the area ``test_shared_state_redis.py`` covers; the integration tests live in ``integration/test_shared_state_redis.py``."""

from __future__ import annotations

import pytest

from af_mcp_broker.shared_state import (
    RedisSharedState,
    SharedStateUnavailableError,
)


async def test_unreachable_store_raises_unavailable(
    unreachable_shared_state_url: str,
) -> None:
    backend = RedisSharedState(unreachable_shared_state_url)
    try:
        for call in (
            backend.incr_window("k", 60),
            backend.get_window("k"),
            backend.delete("k"),
        ):
            with pytest.raises(SharedStateUnavailableError):
                await call
    finally:
        await backend.close()


async def test_unreachable_store_raises_unavailable_for_pubsub(
    unreachable_shared_state_url: str,
) -> None:
    backend = RedisSharedState(unreachable_shared_state_url)
    try:
        with pytest.raises(SharedStateUnavailableError):
            await backend.publish("c", "m")
        with pytest.raises(SharedStateUnavailableError):
            async with backend.subscribe("c"):
                pass
    finally:
        await backend.close()


async def test_unreachable_store_raises_unavailable_for_values(
    unreachable_shared_state_url: str,
) -> None:
    backend = RedisSharedState(unreachable_shared_state_url)
    try:
        with pytest.raises(SharedStateUnavailableError):
            await backend.get("k")
        with pytest.raises(SharedStateUnavailableError):
            await backend.set("k", "v", 60)
    finally:
        await backend.close()
