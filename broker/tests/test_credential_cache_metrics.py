"""Tests that ``CredentialCache.get()`` increments the credential-cache
Prometheus counters (issue #84 -- the Grafana dashboard already queries
``af_mcp_credential_cache_hits_total`` / ``af_mcp_credential_cache_misses_total``,
but no broker code incremented them).

Assertions use before/after deltas via ``REGISTRY.get_sample_value`` rather
than resetting the counters, since the counters live on
``prometheus_client``'s process-wide default registry and are shared across
the whole test session -- a delta is order-independent, a reset is not.
"""

from __future__ import annotations

from prometheus_client import REGISTRY

from af_mcp_broker.credentials.cache import CredentialCache

TARGET = "rucio"


def _sample(name: str, labels: dict[str, str]) -> float:
    return REGISTRY.get_sample_value(name, labels) or 0.0


def _hits(target: str) -> float:
    return _sample("af_mcp_credential_cache_hits_total", {"target": target})


def _misses(target: str) -> float:
    return _sample("af_mcp_credential_cache_misses_total", {"target": target})


async def test_get_miss_increments_miss_counter_not_hit_counter():
    cache = CredentialCache()
    before_hits, before_misses = _hits(TARGET), _misses(TARGET)

    result = await cache.get(subject="subject-2001", target=TARGET)

    assert result is None
    assert _hits(TARGET) == before_hits
    assert _misses(TARGET) == before_misses + 1


async def test_get_hit_increments_hit_counter_not_miss_counter():
    cache = CredentialCache()
    uid = 2_002
    await cache.put(uid, TARGET, "cached-value")
    before_hits, before_misses = _hits(TARGET), _misses(TARGET)

    result = await cache.get(uid, TARGET)

    assert result == "cached-value"
    assert _hits(TARGET) == before_hits + 1
    assert _misses(TARGET) == before_misses


async def test_get_stale_entry_counts_as_a_miss():
    """An entry with fewer than min_remaining seconds left is a miss, not a
    hit -- it must count against the miss counter."""
    cache = CredentialCache()
    uid = 2_003
    import time

    await cache.put(uid, TARGET, "expiring-soon", expires_at=time.time() + 5)
    before_hits, before_misses = _hits(TARGET), _misses(TARGET)

    result = await cache.get(uid, TARGET, min_remaining=300)

    assert result is None
    assert _hits(TARGET) == before_hits
    assert _misses(TARGET) == before_misses + 1


async def test_get_or_mint_internal_recheck_does_not_double_count():
    """Real callers (X509Provider.issue(), OIDCProvider.issue()) call
    ``get()`` once for the outer probe, then -- only on a miss -- call
    ``get_or_mint()``, which re-checks the cache itself once it holds the
    per-key lock (in case a concurrent caller already minted). That internal
    re-check must not add a second miss sample on top of the outer get()'s
    -- one logical "credential requested, not cached yet" event must
    produce exactly one miss sample, not two."""
    cache = CredentialCache()
    uid = 2_004
    before_misses = _misses(TARGET)

    outer = await cache.get(uid, TARGET)
    assert outer is None

    async def _mint() -> str:
        await cache.put(uid, TARGET, "minted-value")
        return "minted-value"

    result = await cache.get_or_mint(uid, TARGET, 300, _mint)

    assert result == "minted-value"
    assert _misses(TARGET) == before_misses + 1
