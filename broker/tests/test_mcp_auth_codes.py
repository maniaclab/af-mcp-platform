"""Tests for the self-contained MCP OAuth bootstrap authorization codes (issues #140, #374).

A code is a Fernet token carrying the whole authorization record, so any
replica holding the same ``BROKER_STATE_KEY`` can redeem it; single use is
enforced by a marker in the shared-state store. "Two replicas" below are two
store instances that share only the key and the store URL.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

import pytest
from cryptography.fernet import Fernet

from af_mcp_broker.mcp_auth_codes import McpAuthCodeRecord, McpAuthCodeStore
from af_mcp_broker.oauth_state import build_mcp_authorize_state
from af_mcp_broker.shared_state import (
    InMemorySharedState,
    RedisSharedState,
    SharedState,
    SharedStateUnavailableError,
)

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

ISSUER = "https://mcp.example.test"


class _Clock:
    def __init__(self, now: float = 1_800_000_000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


def _record(**overrides: object) -> McpAuthCodeRecord:
    kwargs: dict[str, object] = {
        "principal_id": "sub-abc",
        "client_id": "https://client.example/.well-known/cimd",
        "redirect_uri": "http://localhost:12345/callback",
        "code_challenge": "challenge-abc",
        "client_name": "Test Client",
    }
    kwargs.update(overrides)
    return McpAuthCodeRecord(**kwargs)  # type: ignore[arg-type]


def _store(
    key: bytes,
    shared_state: SharedState,
    clock: _Clock | None = None,
    issuer: str = ISSUER,
) -> McpAuthCodeStore:
    return McpAuthCodeStore(
        Fernet(key),
        shared_state,
        issuer=issuer,
        clock=clock or time.time,
    )


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


# --- round trip and single use (in-memory, single replica) ---------------


async def test_issue_then_consume_round_trip(key: bytes) -> None:
    store = _store(key, InMemorySharedState())
    record = _record()

    assert await store.consume(store.put(record)) == record


async def test_none_client_name_round_trips(key: bytes) -> None:
    store = _store(key, InMemorySharedState())
    record = _record(client_name=None)

    assert await store.consume(store.put(record)) == record


async def test_consume_is_single_use(key: bytes) -> None:
    store = _store(key, InMemorySharedState())
    code = store.put(_record())

    assert await store.consume(code) is not None
    assert await store.consume(code) is None


async def test_codes_are_unique(key: bytes) -> None:
    store = _store(key, InMemorySharedState())

    assert len({store.put(_record()) for _ in range(50)}) == 50


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


# --- expiry ----------------------------------------------------------------


async def test_code_redeems_just_before_expiry(key: bytes) -> None:
    clock = _Clock()
    store = _store(key, InMemorySharedState(), clock)
    code = store.put(_record())

    clock.now += 119
    assert await store.consume(code) is not None


async def test_code_expires_after_120_seconds(key: bytes) -> None:
    clock = _Clock()
    store = _store(key, InMemorySharedState(), clock)
    code = store.put(_record())

    clock.now += 120
    assert await store.consume(code) is None


async def test_single_use_marker_ttl_is_the_codes_remaining_lifetime(
    key: bytes,
) -> None:
    clock = _Clock()
    state = InMemorySharedState()
    store = _store(key, state, clock)
    code = store.put(_record())
    clock.now += 30

    await store.consume(code)

    windows = state._windows
    (marker_key,) = windows
    assert marker_key.startswith("mcp_auth_code:")
    # incr_window runs on the monotonic clock, so only the width is checkable:
    # 90 s of the code's life were left.
    remaining = windows[marker_key][1] - time.monotonic()
    assert 85 < remaining <= 90


# --- opacity, tamper, wrong key --------------------------------------------


def test_code_does_not_reveal_the_record(key: bytes) -> None:
    code = _store(key, InMemorySharedState()).put(
        _record(principal_id="sub-secret-xyz", code_challenge="pkce-challenge-xyz")
    )

    assert "sub-secret-xyz" not in code
    assert "pkce-challenge-xyz" not in code
    assert "client.example" not in code


@pytest.mark.parametrize("garbage", ["", "never-issued", "gAAAAAB" + "A" * 200, "éè"])
async def test_garbage_code_is_rejected(key: bytes, garbage: str) -> None:
    store = _store(key, InMemorySharedState())

    assert await store.consume(garbage) is None


async def test_tampered_code_is_rejected_without_touching_the_store(
    key: bytes,
) -> None:
    state = InMemorySharedState()
    store = _store(key, state)
    code = store.put(_record())
    middle = len(code) // 2
    flipped = "A" if code[middle] != "A" else "B"
    tampered = code[:middle] + flipped + code[middle + 1 :]

    assert await store.consume(tampered) is None
    assert state._windows == {}
    # The untouched original is still redeemable.
    assert await store.consume(code) is not None


async def test_code_from_another_key_is_rejected(key: bytes) -> None:
    other = _store(Fernet.generate_key(), InMemorySharedState())

    assert (
        await _store(key, InMemorySharedState()).consume(other.put(_record())) is None
    )


async def test_code_minted_for_another_issuer_is_rejected(key: bytes) -> None:
    state = InMemorySharedState()
    foreign = _store(key, state, issuer="https://other.example.test")

    assert await _store(key, state).consume(foreign.put(_record())) is None


async def test_state_token_is_not_redeemable_as_a_code(key: bytes) -> None:
    state_token = build_mcp_authorize_state(
        Fernet(key),
        iss=ISSUER,
        pkce_verifier="v",
        mcp_client_id="c",
        mcp_redirect_uri="http://localhost/cb",
        mcp_state="s",
        mcp_code_challenge="ch",
        mcp_client_name="",
        nonce="n",
    )

    assert await _store(key, InMemorySharedState()).consume(state_token) is None


# --- store outage: fail closed ---------------------------------------------


async def test_store_outage_refuses_redemption(
    key: bytes, unreachable_shared_state_url: str
) -> None:
    down = RedisSharedState(unreachable_shared_state_url)
    try:
        code = _store(key, down).put(_record())
        with pytest.raises(SharedStateUnavailableError):
            await _store(key, down).consume(code)
    finally:
        await down.close()


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
