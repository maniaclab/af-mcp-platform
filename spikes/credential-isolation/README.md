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

`test_concurrent_isolation.py` drives the real cache
(`broker/src/af_mcp_broker/credentials/cache.py`) with real `IssuedCredential`
values and covers three scenarios:

1. **Cross-principal isolation** — 5 and 20 concurrent principals each store a
   distinct credential for the same target (`rucio`). After the concurrent
   burst settles, every principal retrieves its own credential and the test
   asserts field-for-field equality. No principal can see another's credential,
   either during the burst or after it quiesces.

2. **Rate-limit lockout** — five failed cache lookups for a single uid within
   the 15-minute window return `None`; the sixth raises `RateLimitError`. A
   companion test asserts that a successful `put` resets the miss counter so
   legitimate re-authentication after an expiry-driven miss is not penalised.

3. **Janitor sweep** — an entry with `expires_at` in the past is gone after
   `sweep_expired()`; a live entry (`expires_at` in the future) survives the
   same sweep unchanged.

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
| Cross-principal isolation | Every principal retrieves exactly its own `IssuedCredential` | Any principal receives another's credential |
| Rate-limit | Sixth miss within the window raises `RateLimitError`; a successful `put` clears the counter | No error, or raise on attempt < 6, or counter persists across a `put` |
| Janitor | Stale entry gone after `sweep_expired`; live entry preserved | Stale entry lingers, or live entry evicted |

## Dependency

This spike imports directly from `af_mcp_broker.credentials.cache` and
`af_mcp_broker.credentials.base`. Both modules must exist under
`broker/src/af_mcp_broker/credentials/` before running the tests.
