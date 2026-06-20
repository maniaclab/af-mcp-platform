# Spike: Credential Isolation Under Concurrent Load

**Phase 0 Spike #1** — must pass before Phase 1 broker work begins.

## What this validates

The broker's `CredentialCache` is the most security-critical in-process component.
This spike answers one question:

> Under concurrent requests from N distinct AF principals, does the cache EVER
> return principal A's credential to principal B?

Any failure here is a **blocker**. There is no acceptable rate of cross-user
credential leakage.

## What is tested

The test file `test_concurrent_isolation.py` covers three scenarios:

1. **Cross-principal isolation** — 20 concurrent principals each store a unique
   credential for the same target name (`rucio`). After all tasks complete, every
   principal retrieves their own credential and the test asserts it matches exactly
   what they stored. No principal can see another's credential.

2. **Rate-limit lockout** — a single principal making 6 failed credential lookups
   within a 5-second window triggers the rate limiter. Subsequent requests within
   the window are rejected with an appropriate error.

3. **Janitor sweep** — a cache entry stored with `expires_at` in the past is absent
   after the janitor coroutine runs a single sweep. No stale credentials linger.

## How to run

```bash
# From the repo root
pixi run test-spikes
# or directly:
pixi run -e dev pytest spikes/ -v
```

All tests must show `PASSED`. Any `FAILED` or `ERROR` is a blocker.

## Pass / fail criteria

| Scenario | Pass | Fail |
|---|---|---|
| Cross-principal isolation | Every principal gets exactly their own credential | Any principal receives another's credential |
| Rate-limit | 6th attempt raises `RateLimitError` | No error, or raises on attempt < 6 |
| Janitor | Expired entry returns `None` after sweep | Expired entry still returned |

## Dependency

This spike imports directly from `af_mcp_broker.credentials.cache`. The cache
module must exist at `broker/src/af_mcp_broker/credentials/cache.py` before
running this test. The broker skeleton (Phase 0.5) creates that module.
