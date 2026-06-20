"""
Spike: Credential Isolation Under Concurrent Load
Phase 0 Spike #1 — MUST pass before Phase 1.

Imports af_mcp_broker.credentials.cache directly to validate:
  1. No cross-principal credential leakage under concurrent access.
  2. Rate-limit fires after N failed attempts within the window.
  3. Janitor removes expired entries.
"""

from __future__ import annotations

import asyncio
import random
import time
from dataclasses import dataclass, field

import pytest

# ---------------------------------------------------------------------------
# These imports will fail until broker/src/af_mcp_broker/credentials/cache.py
# exists.  That is intentional — this is a failing-first spike.
# ---------------------------------------------------------------------------
from af_mcp_broker.credentials.cache import CredentialCache, RateLimitError

# Deterministic seed for any random-like behaviour in the test.
random.seed(42)

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

TARGET = "rucio"


@dataclass
class FakeCredential:
    uid: int
    token: str = field(init=False)

    def __post_init__(self) -> None:
        self.token = f"cred-for-uid-{self.uid}-{random.randint(100_000, 999_999)}"


# ---------------------------------------------------------------------------
# Scenario 1: cross-principal isolation
# ---------------------------------------------------------------------------

N_PRINCIPALS = [5, 20]


@pytest.mark.anyio
@pytest.mark.parametrize("n", N_PRINCIPALS)
async def test_concurrent_cross_principal_isolation(n: int) -> None:
    """No principal should ever receive another principal's credential."""
    cache: CredentialCache = CredentialCache()

    base_uid = 50_000
    principals = [FakeCredential(uid=base_uid + i) for i in range(n)]

    async def store_and_retrieve(cred: FakeCredential) -> tuple[int, str | None]:
        await cache.put(cred.uid, TARGET, cred.token)
        retrieved = await cache.get(cred.uid, TARGET)
        return cred.uid, retrieved

    results = await asyncio.gather(*(store_and_retrieve(p) for p in principals))

    uid_to_expected = {p.uid: p.token for p in principals}
    for uid, retrieved in results:
        assert retrieved == uid_to_expected[uid], (
            f"uid={uid} got '{retrieved}' but expected '{uid_to_expected[uid]}'"
        )

    # Extra cross-check: each uid returns only its OWN credential, never a neighbour's.
    for cred in principals:
        val = await cache.get(cred.uid, TARGET)
        for other in principals:
            if other.uid != cred.uid:
                assert val != other.token, (
                    f"ISOLATION BREACH: uid={cred.uid} received credential "
                    f"belonging to uid={other.uid}"
                )


# ---------------------------------------------------------------------------
# Scenario 2: rate-limit on repeated failed lookups
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_rate_limit_triggers_after_six_failures() -> None:
    """Six failed cache lookups within the window must raise RateLimitError."""
    cache: CredentialCache = CredentialCache()
    uid = 99_999

    # The key has never been stored, so get() represents a miss / failed lookup.
    # The cache must record each miss against the principal for rate-limiting.
    for attempt in range(1, 6):
        result = await cache.get(uid, TARGET)
        assert result is None, f"Expected None on attempt {attempt}, got {result!r}"

    # The 6th attempt should trip the rate limiter.
    with pytest.raises(RateLimitError):
        await cache.get(uid, TARGET)


# ---------------------------------------------------------------------------
# Scenario 3: janitor sweeps expired entries
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_janitor_removes_expired_entries() -> None:
    """An entry stored with expires_at in the past must be gone after a janitor sweep."""
    cache: CredentialCache = CredentialCache()
    uid = 50_500
    token = "expired-token-abc"

    # Store an entry that is already past its TTL.
    await cache.put(uid, TARGET, token, expires_at=time.time() - 1)

    # Before janitor: the entry may or may not be returned (implementation-defined),
    # but after the sweep it must be gone.
    await cache.sweep_expired()

    result = await cache.get(uid, TARGET)
    assert result is None, (
        f"Expected None after janitor sweep, got {result!r} — "
        "expired credential is still in cache"
    )
