"""Integration tests for the area ``test_mcp_auth_codes.py`` covers; the unit tests live in ``unit/test_mcp_auth_codes.py``."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from cryptography.fernet import Fernet
from test_mcp_auth_codes import (
    _record,
    _store,
)

from af_mcp_broker.shared_state import (
    RedisSharedState,
    SharedStateUnavailableError,
)

if TYPE_CHECKING:
    from collections.abc import AsyncIterator


@pytest.fixture
def key() -> bytes:
    return Fernet.generate_key()


@pytest.fixture
async def redis_state(shared_state_url: str) -> AsyncIterator[RedisSharedState]:
    backend = RedisSharedState(shared_state_url)
    yield backend
    await backend.close()


@pytest.fixture
async def redis_state_other_replica(
    shared_state_url: str,
) -> AsyncIterator[RedisSharedState]:
    backend = RedisSharedState(shared_state_url)
    yield backend
    await backend.close()


# --- cross-replica (real redis) -------------------------------------------


async def test_code_issued_on_one_replica_redeems_on_another_once(
    key: bytes,
    redis_state: RedisSharedState,
    redis_state_other_replica: RedisSharedState,
) -> None:
    replica_a = _store(key, redis_state)
    replica_b = _store(key, redis_state_other_replica)
    record = _record()
    code = replica_a.put(record)

    assert await replica_b.consume(code) == record
    # Replay on the issuing replica and on the redeeming one both fail.
    assert await replica_a.consume(code) is None
    assert await replica_b.consume(code) is None


async def test_outage_does_not_burn_the_code(
    key: bytes, redis_state: RedisSharedState, unreachable_shared_state_url: str
) -> None:
    down = RedisSharedState(unreachable_shared_state_url)
    try:
        code = _store(key, redis_state).put(_record())
        with pytest.raises(SharedStateUnavailableError):
            await _store(key, down).consume(code)
        # Store back: the same code is still good, exactly once.
        assert await _store(key, redis_state).consume(code) is not None
        assert await _store(key, redis_state).consume(code) is None
    finally:
        await down.close()
