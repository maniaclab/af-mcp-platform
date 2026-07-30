"""Tests for ``CredentialCache.get_or_mint()`` single-flighting (issue #94).

Neither ``OIDCProvider.issue()`` nor ``X509Provider.issue()`` used to
deduplicate concurrent callers for the same ``(uid, target)``: N concurrent
tool calls needing the same not-yet-cached credential each independently did
the expensive work (N parallel Keycloak fetches, or N parallel ephemeral k8s
Job creations). ``get_or_mint()`` centralizes the fix so both providers share
one mechanism instead of each re-implementing it: concurrent misses for the
same key await one in-flight ``mint`` call rather than each starting their
own.

See test_oidc.py / test_x509.py for the provider-level integration tests
that exercise this through the real ``issue()`` code paths.
"""

from __future__ import annotations

import asyncio

import pytest

from af_mcp_broker.credentials.cache import CredentialCache

TARGET = "rucio"


async def test_concurrent_misses_mint_exactly_once():
    """N concurrent get_or_mint() misses for the same key share one mint call."""
    cache = CredentialCache()
    uid = 1_001
    calls = 0

    async def _mint() -> str:
        nonlocal calls
        calls += 1
        # Force a real suspension so all N callers actually overlap instead
        # of running to completion one at a time before the next starts.
        await asyncio.sleep(0.01)
        await cache.put(uid, TARGET, "minted-value")
        return "minted-value"

    results = await asyncio.gather(
        *[cache.get_or_mint(uid, TARGET, 300, _mint) for _ in range(5)]
    )

    assert calls == 1
    assert results == ["minted-value"] * 5


async def test_cache_hit_never_calls_mint():
    """An already-cached value short-circuits get_or_mint() without minting."""
    cache = CredentialCache()
    uid = 1_002
    await cache.put(uid, TARGET, "cached-value")

    async def _mint() -> str:
        pytest.fail("mint must not be called on a cache hit")

    result = await cache.get_or_mint(uid, TARGET, 300, _mint)
    assert result == "cached-value"


async def test_different_keys_do_not_serialize():
    """Concurrent mints for different (uid, target) keys must not block on
    each other's lock -- only same-key misses single-flight."""
    cache = CredentialCache()
    entered = []
    both_entered = asyncio.Event()

    async def _mint_for(key: tuple[int, str]):
        entered.append(key)
        if len(entered) == 2:
            both_entered.set()
        # Each waits for both to have entered before either proceeds --
        # deadlocks (and the test times out) if the two keys were
        # serialized behind a single shared lock instead of per-key ones.
        await asyncio.wait_for(both_entered.wait(), timeout=2.0)
        return key

    async def _mint(key: tuple[int, str]):
        return await _mint_for(key)

    key_a = (1_003, "rucio")
    key_b = (1_003, "opendata")

    results = await asyncio.wait_for(
        asyncio.gather(
            cache.get_or_mint(*key_a, 300, lambda: _mint(key_a)),
            cache.get_or_mint(*key_b, 300, lambda: _mint(key_b)),
        ),
        timeout=2.0,
    )

    assert set(results) == {key_a, key_b}


async def test_mint_exception_propagates_and_does_not_wedge_the_lock():
    """A failing mint must propagate to its caller, and must not leave the
    per-key lock stuck -- the next caller should be able to retry."""
    cache = CredentialCache()
    uid = 1_004
    attempts = 0

    async def _mint() -> str:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise ValueError("mint failed (fake)")
        await cache.put(uid, TARGET, "minted-on-retry")
        return "minted-on-retry"

    with pytest.raises(ValueError, match="mint failed"):
        await cache.get_or_mint(uid, TARGET, 300, _mint)

    result = await cache.get_or_mint(uid, TARGET, 300, _mint)
    assert result == "minted-on-retry"
    assert attempts == 2
