# Krb5 Remember/Keytab Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Give `KrbTokenProvider` a durable "remember" option — mirroring `X509Provider`'s Vault-backed custody model — using krb5-token-service v0.2.0's new `POST /v1/renew` and `POST /v1/keytab` endpoints, plus the "remember" checkbox on the portal's `Krb5IdentityCard.vue`.

**Architecture:** krb5-token-service v0.2.0 (already tagged, PR maniaclab/krb5-token-service#2 merged) adds three capabilities: `POST /v1/renew` (kinit -R on an already-minted ccache — no credential needed, capped at that ticket's own `renew_until`, ~7 days per the shipped `krb5.conf`), `POST /v1/mint` accepting `keytab_b64` as an alternative to `password`, and `POST /v1/keytab` (bootstraps a keytab from a one-time password, never persists it itself). This gives a four-tier fallback, from cheapest/most-ephemeral to most-expensive/most-durable:

1. **Live cache hit** (existing `CredentialCache`, unchanged).
2. **Renew from a stored ccache** (new) — needs no stored secret at all, just the ticket's own `ccache_b64` and its `renew_until`, which `Krb5VaultStore` now persists on *every* successful mint (independent of "remember" — this tier is a pure win with no consent implications, confirmed with Giordon this session).
3. **Re-mint from a stored keytab** (new, gated on "remember") — needs `Krb5VaultStore` to hold a `keytab_b64`, bootstrapped once via `POST /v1/keytab` using the same password already captured for the initial mint.
4. **Fresh username/password mint** (existing `NeedsUnlock` → `POST /v1/krb5/ticket` flow), optionally followed by a keytab bootstrap when `remember=true`.

This exactly mirrors `X509Provider`'s design: Vault (`Krb5VaultStore`, modeled on `VaultX509Store`) is the source of truth for freshness/renewability; `CredentialCache` remains a cheap, short-TTL local mirror repopulated on every Vault-backed hit — **`CredentialCache` cannot retain a payload past its own `expires_at`** (its background janitor deletes entries outright there, confirmed by reading `cache.py`'s `_sweep_expired`/`_lookup`), so renewal decisions must be made against Vault's own `renew_until`, never against the in-process cache.

**Unlink** (per this session's design conversation) lands in this same round: `DELETE /v1/identities/link/krb5` (the existing generic `unlink_identity` route, currently 501 for every non-`oauth21-direct` type) gets a `krb5-token` branch that deletes the full `Krb5VaultStore` record and revokes the cached credential — giving "remember" a real off-switch, unlike x509 (which, per this session's research, has no manual unlink today — only an automatic self-unlink on a rejected stored passphrase). The portal reuses its existing generic `unlinkIdentity()` API function (already used by `IdentityLink.vue`) — no new portal API surface needed for unlink.

**Explicitly in scope:** backend Vault storage/renewal/keytab-remint logic, the unlink branch, the portal "remember" checkbox and a "forget" affordance, tests, docs.

**Explicitly out of scope:** a richer portal display of link mode/expiry for krb5 (the `x509_link_mode`/`proxy_expires_at`-equivalent fields x509's card shows) — the existing `Krb5IdentityCard.vue` already shows a transient post-mint summary; this plan does not add a persistent-across-reload expiry/mode line. That's a reasonable follow-up but adds portal scope beyond what's needed to make "remember" actually work, and isn't part of what was asked for.

**Tech Stack:** Same as the rest of this branch — FastAPI, pydantic v2, httpx, structlog, Vault KV-v2 (via the existing `VaultKV` client), pytest/pytest-asyncio, Vue 3 + Vitest for the portal piece.

---

## Reference material already gathered this session

- **krb5-token-service v0.2.0 API** (from its README, confirmed merged and tagged):
  - `POST /v1/mint` — body now `{"username", "password", "lifetime", "renewable_lifetime"}` **or** `{"username", "keytab_b64", "lifetime", "renewable_lifetime"}`, exactly one of `password`/`keytab_b64` required (422 otherwise, `{"detail": "..."}`). New 400 case: `{"detail": "bad keytab"}`. Response unchanged: `{"ccache_b64", "principal", "realm", "expires_at", "renew_until"}`.
  - `POST /v1/renew` — body `{"ccache_b64": str}`. Runs `kinit -R`; never touches the rate limiter. Same response shape as `/v1/mint`. **422** `{"detail": "invalid ccache_b64"}` / `{"detail": "invalid ccache"}` (malformed input, checked before `kinit` runs). **400** once the ticket is past its own `renew_until` (must mint fresh via `/v1/mint` instead — this is the "fall through to tier 3/4" signal, NOT a credential error). 401/502 as usual.
  - `POST /v1/keytab` — body `{"username", "password"}`. Returns `{"keytab_b64", "principal"}`. Never persists it. Shares the failed-auth rate limiter with `/v1/mint`'s password path (a wrong password here is a real check against the CERN account). 400 `{"detail": "bad password"}`; 422 invalid username; 429; 401/502 as usual.
- **`X509Provider`'s Vault custody pattern** (`broker/src/af_mcp_broker/credentials/x509_vault.py`, `x509.py`) — the template being mirrored:
  - `VaultX509Store`: one KV-v2 record per subject, "link half" (passphrase + POSIX identity — durable, conditional on `remember=true`) + "proxy half" (PEM + metadata — written on every mint regardless of remember). `store_link`/`get_link`/`store_proxy`/`get_proxy(subject, min_remaining)`/`clear_proxy`/`delete`. Read-modify-write under KV-v2 CAS, 3 retries, last-writer-wins. `SecretStr` fields revealed manually before write (`_reveal_secrets`).
  - `X509Provider._issue_via_service`'s control flow: (1) `vault_store.get_proxy(subject, min_remaining)` — Vault's own `not_after` decides freshness, not `CredentialCache`'s TTL; (2) if none + passphrase given → mint + `store_link` + `store_proxy`; (3) if none + no passphrase → `get_link`; if present, `renew_from_stored_link(subject, target)` (mints fresh via stored passphrase, re-persists, and on a **rejected stored passphrase** proactively calls `vault_store.delete(subject)` — password rotated, not a user brute-force attempt); else `NeedsUnlock`.
  - `_cache_stored_record(...)` repopulates `CredentialCache` from whatever Vault record was just consulted, using the record's own `not_after` as the cache entry's `expires_at` — `CredentialCache` is a mirror, never the source of truth, here.
  - **No manual unlink exists for x509** — `vault_store.delete()` is called from exactly one place, the auto-unlink-on-bad-stored-passphrase path. `DELETE /v1/x509/proxy` only clears the proxy half, preserving the link.
- **`unlink_identity`** (`broker/src/af_mcp_broker/api/identities.py`, `DELETE /identities/link/{provider}`): only `oauth21-direct` has real logic (`provider.revoke()` + `credential_cache.revoke()` per target); everything else (including x509, and currently krb5-token) falls to a fixed 501.
- **Vault wiring** (`app.py`): one shared `vault_kv`, gated by a single `if` (`app.py:374-379`ish) OR-ing together every Vault-backed feature's "am I configured" check (`token_store_backend == "vault"`, `has_service_mode_x509_cfg`, etc.). Adding krb5 means adding a `has_krb5_token_cfg` clause (simpler than x509's — krb5 has no service/legacy mode split, gate purely on "any `krb5-token` identity_provider entry exists"). `Settings._validate_vault_config` needs a matching clause requiring `vault_addr` etc. when a krb5-token entry exists. `x509_kv_path_prefix: str = "mcp/x509"` (`config.py`) is the exact pattern for a new `krb5_kv_path_prefix: str = "mcp/krb5"` field. Vault connection settings (`vault_addr`/`vault_kv_mount`/`vault_auth_mount`/`vault_auth_role`/`vault_sa_token_path`) are fully generic, already shared across 4+ backends.
- **`CredentialCache`'s real constraint** (`credentials/cache.py`): the background janitor deletes an entry outright once `entry.expires_at <= now`; `_lookup()` (shared by `get`/`peek`/`get_or_mint`) treats any `min_remaining >= 0` past `expires_at` as a miss. **There is no secondary retention window** — this is exactly why x509 doesn't lean on `CredentialCache` for renewal decisions and why this plan follows the same pattern for krb5.
- Existing krb5 surface from the prior plan (already shipped, reviewed, merged into this branch): `Krb5TokenServiceClient`/`MintedTicket`/5 exceptions (`credentials/krb5_service.py`), `KrbTokenProvider` (`credentials/krb5.py`), `KrbTicketRequest`/`KrbTicketMetadata`/`POST /v1/krb5/ticket` (`api/credentials.py`), `KrbTokenProviderConfig` (`config.py`), app.py wiring, `/v1/identities` support (`"credential"` link mechanism), `Krb5IdentityCard.vue` (portal, no checkbox yet), `CredentialCache.peek()` (added this session, metrics-free lookup — reused here for `is_linked()`, still the right tool for "does the in-process cache have a live entry", separate from the new Vault-backed renewability question).

---

### Task 1: `Krb5TokenServiceClient` — `renew()`, `mint_keytab()`, keytab-mode `mint()`

**Files:**
- Modify: `broker/src/af_mcp_broker/credentials/krb5_service.py`
- Test: Modify `broker/tests/test_krb5_service_client.py`

**Step 1: Write the failing tests**

Read the current `krb5_service.py` and its test file in full first (both already exist from the prior plan). Add tests for:
- `mint()` now accepts `keytab_b64: SecretStr | None = None` alongside the existing `password: SecretStr | None = None` — exactly one required; calling with both or neither raises a `ValueError` from the CLIENT side (a programming error in this codebase, not something the service should ever see — mirror the pattern used elsewhere in this codebase for "caller violated a documented precondition" if one exists, otherwise a plain `ValueError` with a clear message is fine). When `keytab_b64` is supplied, the POST body carries `{"username", "keytab_b64", ...}` instead of `{"username", "password", ...}`. A 400 response with `{"detail": "bad keytab"}` still raises `Krb5TokenBadCredentialError` (the same exception as a bad password — the provider doesn't need to distinguish "bad password" from "bad keytab" at this layer; both mean "this credential no longer works").
- `renew(*, subject: str, ccache_b64: str) -> MintedTicket`: POSTs to `{service_url}/v1/renew` with `{"ccache_b64": ccache_b64}`, same broker-identity-token auth pattern as `mint()`. Success parses the same 5-field response into a `MintedTicket`. **422** → a distinct `Krb5TokenInvalidCcacheError` (new exception — this is a malformed request built from OUR OWN stored value, so it signals internal corruption, not user-actionable input; do not reuse `Krb5TokenInvalidRequestError`, which callers may treat as "surface a 422 to the end user"). **400** → a distinct `Krb5TokenRenewalWindowClosedError` (new exception, `RuntimeError` subclass — this is an EXPECTED, recoverable condition: the provider catches it and falls through to keytab/password, it is never surfaced to a user as an error). 401/other-non-200 → `Krb5TokenMintError` (reuse, same as `mint()`'s generic infra-failure case). No 429 case (the service never rate-limits `/v1/renew` — don't add a branch for it; confirm this by testing that an unexpected status, e.g. 429 if the service ever sent one, falls through to the generic `Krb5TokenMintError` branch rather than being silently ignored).
- `mint_keytab(*, subject: str, username: str, password: SecretStr) -> tuple[str, str]` (returns `(keytab_b64, principal)`): POSTs to `{service_url}/v1/keytab` with `{"username", "password"}` (password revealed only at the call site, same discipline as `mint()`). Success parses `{"keytab_b64", "principal"}`. **400** → `Krb5TokenBadCredentialError` (reuse — same "wrong CERN password" meaning as mint's 400). **422** → `Krb5TokenInvalidRequestError` (reuse — malformed `username`, genuinely user-actionable the same way mint's 422 is). **429** → `Krb5TokenRateLimitedError` (reuse, with `Retry-After` passthrough — the service explicitly shares its rate limiter between `/v1/mint`'s password path and `/v1/keytab`). 401/other → `Krb5TokenMintError` (reuse).

Follow this file's own established test conventions exactly (the `httpx.MockTransport` + real `BrokerTokenIssuer` pattern from the prior plan's Task 2 — read that file's existing tests for the exact fixture shape before writing new ones, don't reinvent).

**Step 2: Run to verify failure**

Run: `pixi run -e dev pytest broker/tests/test_krb5_service_client.py -v`
Expected: FAIL — `renew`/`mint_keytab` don't exist yet, `mint()` doesn't accept `keytab_b64` yet.

**Step 3: Write the implementation**

- Add `Krb5TokenInvalidCcacheError(ValueError)` and `Krb5TokenRenewalWindowClosedError(RuntimeError)` to the exception set, each with a fixed, non-leaking message (matching the existing five exceptions' style — a `__init__` with no arguments setting a fixed `super().__init__(...)` message).
- Change `mint()`'s signature to `async def mint(self, *, subject: str, username: str, password: SecretStr | None = None, keytab_b64: SecretStr | None = None, lifetime: str | None = None, renewable_lifetime: str | None = None) -> MintedTicket`. At the top: `if (password is None) == (keytab_b64 is None): raise ValueError("exactly one of password or keytab_b64 is required")`. Build the body with whichever credential field is present (`"password": password.get_secret_value()` or `"keytab_b64": keytab_b64.get_secret_value()`), never both.
- Add `async def renew(self, *, subject: str, ccache_b64: str) -> MintedTicket`, POSTing to `f"{self._base_url}/v1/renew"` (reuse the same base-URL-stripping the constructor already does for `/v1/mint` — check whether `_mint_endpoint` is stored as a full URL or whether the base is stored separately; if only `_mint_endpoint` exists today, either store `_base_url` too or derive `/v1/renew` by string-replacing `/v1/mint` — pick whichever is cleaner given the actual current `__init__` code, don't guess).
- Add `async def mint_keytab(self, *, subject: str, username: str, password: SecretStr) -> tuple[str, str]`, POSTing to `{base_url}/v1/keytab`.
- All three methods mint a fresh `self._issuer.mint(subject, self._audience)` broker identity token per call (same as `mint()` today — no caching of the broker token across calls, matching the existing pattern).

**Step 4: Run to verify pass**

Run: `pixi run -e dev pytest broker/tests/test_krb5_service_client.py -v`
Expected: PASS (all tests, old and new)

**Step 5: Lint, typecheck, and commit**

```bash
pixi run -e dev lint-all
git add broker/src/af_mcp_broker/credentials/krb5_service.py broker/tests/test_krb5_service_client.py
git commit -m "feat(broker): add renew() and mint_keytab() to Krb5TokenServiceClient"
```

---

### Task 2: `Krb5VaultStore` / `StoredKrb5Credential`

**Files:**
- Create: `broker/src/af_mcp_broker/credentials/krb5_vault.py`
- Test: Create `broker/tests/test_krb5_vault.py`

**Step 1: Write the failing tests**

Read `broker/src/af_mcp_broker/credentials/x509_vault.py` and `broker/tests/test_x509_vault.py` in full first — this is a near-direct structural port. Write tests mirroring `test_x509_vault.py`'s organization (likely `TestLink`/`TestProxy`/`TestClearProxy`/`TestDelete`/`TestCas`-equivalent classes), covering:
- `store_ticket`/`get_ticket(subject, min_remaining)` freshness gating against `not_after` (same shape as x509's `store_proxy`/`get_proxy`), AND retrieval of `renew_until` for the renewal-window check (this is new — x509 has no equivalent "there's a second, later deadline" concept, since a VOMS proxy doesn't renew itself the way a Kerberos ticket does; make sure `get_ticket` — or a second accessor — surfaces `renew_until` even when the ticket is past `not_after`, since that's exactly the window `KrbTokenProvider` needs to check before giving up on Vault-backed renewal).
- `store_link`/`get_link(subject)` for the keytab half (username + keytab_b64) — same shape as x509's link half, but simpler (no POSIX identity fields; krb5 doesn't need them).
- `clear_ticket(subject)` — drops the ticket half, preserves the link (mirrors `clear_proxy`).
- `delete(subject)` — full unlink, both halves gone.
- Records are per-subject, isolated from other subjects (mirror x509's equivalent test).
- CAS retry-on-conflict behavior (mirror `test_x509_vault.py`'s `TestCas` class if a comparably-testable seam exists — check how it's actually tested there, e.g. injecting a version mismatch, before assuming you can reproduce the exact mechanism).

**Step 2: Run to verify failure**

Run: `pixi run -e dev pytest broker/tests/test_krb5_vault.py -v`
Expected: FAIL (module doesn't exist).

**Step 3: Write the implementation**

Structural template (read `x509_vault.py` for the exact class/method bodies to mirror — do not guess at the Vault KV read-modify-write mechanics, copy the established pattern faithfully):

```python
@dataclass(frozen=True)
class StoredKrb5Credential:
    """A Vault-persisted krb5 record: a link half (keytab, durable, opt-in via 'remember')
    plus a ticket half (last-minted ccache metadata, written on every mint regardless of
    remember -- this is what makes renew-without-remember possible)."""

    username: str | None = None
    keytab_b64: SecretStr | None = None
    ccache_b64: SecretStr | None = None
    principal: str | None = None
    realm: str | None = None
    not_after: float | None = None
    renew_until: float | None = None

    @property
    def has_link(self) -> bool:
        return self.username is not None and self.keytab_b64 is not None

    @property
    def has_ticket(self) -> bool:
        return self.ccache_b64 is not None and self.not_after is not None
```

`Krb5VaultStore` (mirror `VaultX509Store`'s constructor/CAS pattern exactly):
- `store_link(subject, *, username, keytab_b64)` — write/merge the link half.
- `get_link(subject) -> StoredKrb5Credential | None` — record only if `has_link`.
- `store_ticket(subject, *, ccache_b64, principal, realm, not_after, renew_until)` — merge the ticket half, preserve link half.
- `get_ticket(subject, min_remaining=0.0) -> StoredKrb5Credential | None` — record only if `has_ticket` AND `not_after - now >= min_remaining` (mirrors `get_proxy`'s freshness gate exactly).
- `get_renewable_ticket(subject) -> StoredKrb5Credential | None` — record only if `has_ticket` AND `renew_until is not None` AND `renew_until > now` (regardless of `not_after` — this is the NEW accessor `KrbTokenProvider` needs for the renewal tier, deliberately separate from `get_ticket`'s "is it still directly usable" check).
- `clear_ticket(subject)` — drop the ticket half.
- `delete(subject)` — destroy the whole record.

Use the KV path `{kv_path_prefix}/{subject}/krb5` (mirroring x509's `{kv_path_prefix}/{subject}/x509`).

**Step 4: Run to verify pass**

Run: `pixi run -e dev pytest broker/tests/test_krb5_vault.py -v`
Expected: PASS

**Step 5: Lint, typecheck, and commit**

```bash
pixi run -e dev lint-all
git add broker/src/af_mcp_broker/credentials/krb5_vault.py broker/tests/test_krb5_vault.py
git commit -m "feat(broker): add Krb5VaultStore for durable keytab/ticket persistence"
```

---

### Task 3: Vault wiring — `krb5_kv_path_prefix` + shared Vault gate

**Files:**
- Modify: `broker/src/af_mcp_broker/config.py`
- Modify: `broker/src/af_mcp_broker/app.py`
- Test: Modify `broker/tests/test_config.py` (a config-field test), extend `broker/tests/test_krb5_token_app.py` (a fail-closed-without-Vault test, mirroring however x509's equivalent is tested — find it first)

**Step 1: Write the failing tests**

- `test_config.py`: a `krb5_kv_path_prefix` default-value test (mirror `x509_kv_path_prefix`'s own test if one exists; if x509's field has no dedicated test, don't over-invent one — a single assertion on `Settings().krb5_kv_path_prefix == "mcp/krb5"` is enough).
- `test_krb5_token_app.py`: a test that a `krb5-token` `identity_providers` entry with Vault-backed remember support enabled but no Vault connection configured refuses to boot (mirror however the equivalent x509 service-mode-without-Vault fail-closed test is structured — find and read it first in `test_x509_service_mode.py` or wherever it actually lives).

**Step 2: Run to verify failure**

Run the relevant test files; expect FAIL.

**Step 3: Write the implementation**

- `config.py`: add `krb5_kv_path_prefix: str = "mcp/krb5"` near `x509_kv_path_prefix`, with a docstring in the same style.
- `config.py`: add a `has_krb5_token_cfg`-equivalent check to `_validate_vault_config` (find its exact current structure first) — require `vault_addr` etc. whenever any `identity_providers` entry has `type == "krb5-token"` (unconditionally, since unlike x509 there's no legacy/service-mode split — krb5's Vault usage is only for the optional "remember" feature, but since a `krb5-token` entry can't declare ahead of time whether any given user will ever check "remember", Vault must be configured for the type to be safely enabled at all — the alternative, deferring the Vault requirement until the first `remember=true` request, would be a silent-runtime-failure trap this codebase's own fail-closed-at-boot philosophy explicitly avoids elsewhere; confirm this reasoning against the actual `_validate_vault_config` docstring/comments before implementing, adjust if the existing philosophy documented there suggests otherwise).
- `app.py`: add a `has_krb5_token_cfg = any(cfg.type == "krb5-token" for cfg in settings.identity_providers)` (or equivalent) to the `vault_kv` construction's gating `if`.
- `app.py`: construct one shared `Krb5VaultStore` (mirroring `x509_vault_store`'s construction) when `has_krb5_token_cfg` is true, using `settings.krb5_kv_path_prefix`.

**Step 4: Run to verify pass**

Run the relevant test files; expect PASS.

**Step 5: Full suite, lint, typecheck, and commit**

```bash
pixi run -e dev test
pixi run -e dev lint-all
git add broker/src/af_mcp_broker/config.py broker/src/af_mcp_broker/app.py broker/tests/test_config.py broker/tests/test_krb5_token_app.py
git commit -m "feat(broker): wire Vault for krb5-token remember support"
```

---

### Task 4: `KrbTokenProvider` — the four-tier fallback

**Files:**
- Modify: `broker/src/af_mcp_broker/credentials/krb5.py`
- Test: Modify `broker/tests/test_krb5_token.py`

**Step 1: Write the failing tests**

Read the current `krb5.py` and `test_krb5_token.py` in full first (both exist from the prior plan — this task rewrites `issue()`/`is_linked()`/`revoke()` substantially, so understand the current single-tier behavior before layering in the new tiers). Add/rewrite tests covering, in addition to everything already tested:

- **Tier 2 (renew)**: given a Vault record with a ticket half past its `not_after` but with a still-valid `renew_until`, and NO fresh username/passphrase supplied, `issue()` calls `client.renew(...)` (not `client.mint(...)`), succeeds, and the result is both returned and re-persisted to Vault + `CredentialCache`.
- **Tier 2 fallthrough**: same setup but `client.renew(...)` raises `Krb5TokenRenewalWindowClosedError` → falls through to tier 3 (or tier 4/`NeedsUnlock` if no keytab stored) rather than propagating the error.
- **Tier 2 hard failure**: `client.renew(...)` raises `Krb5TokenMintError` (genuine infra failure, not a window-closed signal) → propagates, does NOT fall through (a real service outage shouldn't silently degrade to demanding a password from the user when the actual ticket might still be renewable once the outage clears).
- **Tier 3 (keytab remint)**: no usable cache/ticket-half, but Vault has a stored keytab (`get_link` returns a record), and no fresh username/password supplied → `issue()` calls `client.mint(keytab_b64=..., ...)` (not raising `NeedsUnlock`), succeeds, result persisted.
- **Tier 3 bad keytab**: `client.mint(keytab_b64=...)` raises `Krb5TokenBadCredentialError` → the provider proactively calls `vault_store.delete(subject)` (the stored keytab is now useless — password was rotated — mirroring x509's `renew_from_stored_link`'s auto-unlink-on-bad-stored-passphrase behavior) and THEN raises `NeedsUnlock` (since there's nothing left to fall back to).
- **Tier 4 + remember=True**: fresh username/password supplied with `remember=True` → after a successful password mint, `issue()` ALSO calls `client.mint_keytab(username=..., password=...)` using the SAME already-captured password (no second password prompt), and stores the result via `vault_store.store_link(...)`. Assert the fake client's `mint_keytab` was called with the right args, and `vault_store.get_link(subject)` returns a record afterward.
- **Tier 4 + remember=False (default)**: fresh username/password, no `remember` → `mint_keytab` is NOT called, no link half is stored — only the ticket half (via `store_ticket`, always, regardless of remember — confirm this happens even when `remember=False`, since tier-2 renewal must work for every user, not just ones who opted into "remember").
- **`is_linked()`**: now returns `True` if EITHER `CredentialCache.peek(...)` finds a live entry OR `vault_store.get_link(subject)` finds a stored keytab OR `vault_store.get_renewable_ticket(subject)` finds a still-renewable ticket half — i.e., "is there ANY way to get a usable ticket without a password prompt right now." Write a test for each of the three routes independently returning `True`, plus a "none of the three" `False` case.
- **`revoke()`**: now also calls `vault_store.clear_ticket(subject)` in addition to the existing `CredentialCache.revoke(...)` — dropping the ticket half without touching a stored keytab (mirrors x509's revoke/unlink distinction: revoke ≠ unlink).

Use a fake `Krb5VaultStore` double (in-memory dict keyed by subject, implementing the real class's public method signatures) rather than a real Vault-backed instance, mirroring however `test_x509.py`'s equivalent tests fake `VaultX509Store` — check that file for the exact fake-double convention used there before inventing your own.

**Step 2: Run to verify failure**

Run: `pixi run -e dev pytest broker/tests/test_krb5_token.py -v`
Expected: FAIL — `KrbTokenProvider.__init__` doesn't accept a `vault_store` yet, `issue()`/`is_linked()`/`revoke()` don't have the new logic.

**Step 3: Write the implementation**

Rewrite `KrbTokenProvider`:
- `__init__(self, client, cache, vault_store, alias, targets)` — add `vault_store: Krb5VaultStore` alongside the existing params.
- `is_linked(principal)`: check cache (`peek`), then `vault_store.get_link(subject)`, then `vault_store.get_renewable_ticket(subject)`, in whatever order is cheapest/clearest — return `True` on the first hit.
- `issue(principal, target, min_remaining_seconds=300, passphrase=None, *, username=None, lifetime=None, renewable_lifetime=None, remember=False)`:
  1. Cache hit → return (unchanged).
  2. `vault_store.get_ticket(subject, min_remaining=min_remaining_seconds)` → if found, build `IssuedCredential`, `cache.put(...)`, return (repopulate-from-Vault tier — this covers the case where the in-process cache was evicted/restarted but Vault still has a fresh-enough ticket).
  3. `vault_store.get_renewable_ticket(subject)` → if found (ticket half exists, past `not_after` but `renew_until` still valid): call `client.renew(subject=principal.subject, ccache_b64=<the stored ccache_b64>)`. On success: `store_ticket(...)` + `cache.put(...)`, return. On `Krb5TokenRenewalWindowClosedError`: fall through to step 4. On any other exception: propagate (do not fall through — a genuine infra failure must surface as one, not be silently downgraded to "ask for a password").
  4. `vault_store.get_link(subject)` → if found: call `client.mint(subject=principal.subject, username=<stored username>, keytab_b64=<stored keytab_b64>, lifetime=lifetime, renewable_lifetime=renewable_lifetime)`. On success: `store_ticket(...)` + `cache.put(...)`, return. On `Krb5TokenBadCredentialError`: `vault_store.delete(subject)` (full unlink — the keytab is dead), THEN proceed to step 5 as if no link existed. On any other exception: propagate.
  5. If `passphrase is None or username is None`: raise `NeedsUnlock(target, ..., unlock_endpoint="/v1/krb5/ticket")` (unchanged).
  6. Fresh mint via `client.mint(subject=..., username=username, password=<passphrase as SecretStr>, lifetime=..., renewable_lifetime=...)`, single-flighted via `cache.get_or_mint(...)` (unchanged mechanics, but the inner `_do_mint` now also calls `vault_store.store_ticket(...)` unconditionally after a successful mint, and — only when `remember` is `True` — additionally calls `client.mint_keytab(subject=principal.subject, username=username, password=<the SAME already-captured SecretStr>)` and `vault_store.store_link(subject, username=username, keytab_b64=...)`).
- `revoke(principal, target)`: `cache.revoke(...)` (unchanged) + `vault_store.clear_ticket(principal.subject)` (new).

Be careful with `SecretBytes`/`SecretStr` conversions at each boundary — follow the exact existing pattern in this file (`passphrase.get_secret_value().decode()` → `SecretStr(...)`) rather than introducing a new convention.

**Step 4: Run to verify pass**

Run: `pixi run -e dev pytest broker/tests/test_krb5_token.py -v`
Expected: PASS (all tests, old and new)

**Step 5: Full suite, lint, typecheck, and commit**

```bash
pixi run -e dev test
pixi run -e dev lint-all
git add broker/src/af_mcp_broker/credentials/krb5.py broker/tests/test_krb5_token.py
git commit -m "feat(broker): add renew/keytab fallback tiers and remember support to KrbTokenProvider"
```

---

### Task 5: `app.py` — pass `Krb5VaultStore` into `KrbTokenProvider`

**Files:**
- Modify: `broker/src/af_mcp_broker/app.py`
- Test: Extend `broker/tests/test_krb5_token_app.py`

**Step 1: Write the failing test**

A test confirming the constructed `KrbTokenProvider` (resolved from `credential_registry`) has its `vault_store` set to the shared `Krb5VaultStore` instance built in Task 3 (mirror however `test_x509_service_mode.py` or similar confirms `X509Provider._vault_store` wiring, if such a test exists — if none does, a simpler `isinstance`/attribute-presence check is fine, don't over-build test infra beyond what x509's own coverage bothers with).

**Step 2: Run to verify failure**

Run the test; expect FAIL (the `krb5-token` provider-registration branch in `app.py` doesn't pass `vault_store` yet).

**Step 3: Write the implementation**

Update the `elif cfg.type == "krb5-token":` branch (added in the prior plan's Task 7) to pass `vault_store=krb5_vault_store` (the instance built in Task 3) into `KrbTokenProvider(...)`.

**Step 4: Run to verify pass**

Run the test; expect PASS.

**Step 5: Full suite and commit**

```bash
pixi run -e dev test
git add broker/src/af_mcp_broker/app.py broker/tests/test_krb5_token_app.py
git commit -m "feat(broker): wire Krb5VaultStore into KrbTokenProvider construction"
```

---

### Task 6: `remember` on `POST /v1/krb5/ticket`

**Files:**
- Modify: `broker/src/af_mcp_broker/api/credentials.py`
- Test: Modify `broker/tests/test_krb5_ticket_endpoint.py`

**Step 1: Write the failing test**

A test POSTing `{"username": ..., "password": ..., "remember": true}` and confirming (via a fake `KrbTokenProvider`/fake vault store swapped into the app, mirroring however the existing test file already fakes the client) that `provider.issue(...)` was called with `remember=True`. Plus a default-`remember=False`-when-omitted test.

**Step 2: Run to verify failure**

Run the test file; expect FAIL (`remember` field doesn't exist on `KrbTicketRequest` yet, or isn't passed through).

**Step 3: Write the implementation**

Add `remember: bool = False` to `KrbTicketRequest` (mirroring `ProxyRequest.remember`'s exact field/default/docstring style). Pass `remember=body.remember` into the `provider.issue(...)` call in `create_krb5_ticket`.

**Step 4: Run to verify pass**

Run the test file; expect PASS.

**Step 5: Full suite and commit**

```bash
pixi run -e dev test
git add broker/src/af_mcp_broker/api/credentials.py broker/tests/test_krb5_ticket_endpoint.py
git commit -m "feat(broker): add remember flag to POST /v1/krb5/ticket"
```

---

### Task 7: Unlink support — `DELETE /v1/identities/link/krb5-token-alias`

**Files:**
- Modify: `broker/src/af_mcp_broker/api/identities.py`
- Test: Modify `broker/tests/test_identities.py` (or wherever `unlink_identity` is currently tested — find it first)

**Step 1: Write the failing test**

A test calling `DELETE /identities/link/{krb5-alias}` against an app with a krb5-token provider configured (with something stored — a fake link/ticket in a fake vault store) and confirming: 204 response, `vault_store.delete(subject)` was called, `credential_cache.revoke(subject, target)` was called for each of the entry's targets (mirroring `oauth21-direct`'s exact existing branch shape).

**Step 2: Run to verify failure**

Run the test; expect FAIL (currently hits the 501 fallback).

**Step 3: Write the implementation**

Add a `krb5-token` branch to `unlink_identity`, mirroring the `oauth21-direct` branch's shape: resolve the `KrbTokenProvider` instance for `provider` (the alias), call a new `vault_store.delete(subject)`-wrapping method on the provider itself (add `async def unlink(self, principal) -> None: await self._vault_store.delete(principal.subject)` to `KrbTokenProvider` if a route shouldn't reach into `_vault_store` directly — check how the `oauth21-direct` branch accesses its provider's internals for the established convention, follow it), then revoke the cache for every target in the entry's config, same as the `oauth21-direct` branch does.

**Step 4: Run to verify pass**

Run the test; expect PASS.

**Step 5: Full suite, lint, typecheck, and commit**

```bash
pixi run -e dev test
pixi run -e dev lint-all
git add broker/src/af_mcp_broker/api/identities.py broker/src/af_mcp_broker/credentials/krb5.py broker/tests/test_identities.py
git commit -m "feat(broker): support unlinking a krb5-token identity"
```

---

### Task 8: Docs — `docs/auth.md`

**Files:**
- Modify: `docs/auth.md`

**Step 1: Update the `KrbTokenProvider` section**

Read the current `### KrbTokenProvider: CERN Kerberos tickets (issue #274)` section (added in the prior plan) and extend it — do not rewrite it from scratch — to describe: the four-tier fallback (cache → renew → keytab → password), that `renew`/keytab-remint need no user interaction, that `remember=true` on `POST /v1/krb5/ticket` bootstraps and stores a keytab via a new `POST /v1/keytab` call using the same password already supplied (no second prompt), that `Krb5VaultStore` mirrors `VaultX509Store`'s "link half / ticket half" split, and the new unlink support (`DELETE /v1/identities/link/{alias}` now works for krb5-token, unlike x509 which still has no manual unlink). Update the example config snippet if the Vault requirement changes what a minimal working config looks like (it now unconditionally needs Vault connection settings, unlike the prior plan's Vault-free example).

**Step 2: Commit**

```bash
git add docs/auth.md
git commit -m "docs: document krb5-token remember/keytab/renew support"
```

---

### Task 9: Portal — "remember" checkbox + "forget" affordance

**Files:**
- Modify: `portal/src/lib/api.ts` (add `remember` param to `requestKrb5Ticket`)
- Modify: `portal/src/components/Krb5IdentityCard.vue`
- Test: Modify `portal/src/lib/__tests__/api.test.ts`, `portal/src/components/__tests__/Krb5IdentityCard.test.ts`

**Step 1: Write the failing tests**

- `api.test.ts`: `requestKrb5Ticket` gains a `remember: boolean = false` parameter (positioned after the existing ones — check `requestProxy`'s parameter ordering convention for where a boolean flag like this typically sits), included in the POST body. Test both `true` and default-`false` cases.
- `Krb5IdentityCard.test.ts`: a checkbox exists in the form (mirroring x509's `remember` checkbox markup/labeling style, but with copy accurate to what krb5's remember actually does — see Step 3), defaults to... **decide the default carefully**: x509 defaults `remember: true` (opt-out custody). For krb5, storing a keytab is arguably a bigger ask (a CERN-specific, less-familiar concept than "remember my certificate passphrase") — this session's earlier design conversation with Giordon treated persisting anything beyond a password as worth extra caution. Default this checkbox to **unchecked** (opt-IN, not opt-out) unless you find a strong reason in the existing x509 pattern to do otherwise — flag this choice clearly in your report rather than silently picking one. Submitting with the checkbox checked calls `requestKrb5Ticket(..., true)`; unchecked (default) calls it with `false`. Also test: when `linked=true` (implying something is already stored/renewable), render a "Forget this ticket" (or similar copy) button that calls the existing generic `unlinkIdentity()` (already used by `IdentityLink.vue` — import and reuse it, do not add a new API function) and, on success, emits a new `revoked` event (mirroring x509's `@revoked` pattern) so `IdentitiesPage.vue` can flip `linked` back to `false` locally.

**Step 2: Run to verify failure**

Run the relevant test files; expect FAIL.

**Step 3: Write the implementation**

- `api.ts`: extend `requestKrb5Ticket`'s signature and JSDoc (the existing JSDoc already has a password-clearing `IMPORTANT` note from the prior plan's review-driven fix — extend it, don't replace it, to also explain what `remember` does: "stores a Kerberos keytab (not the password) in the broker's Vault, letting future tickets be minted/renewed without re-entering a password").
- `Krb5IdentityCard.vue`: add the checkbox (mirroring x509's `.xc__consent`/`.xc__checkbox` class names as `.kc__consent`/`.kc__checkbox` for visual consistency), with hint copy that's accurate to krb5's actual mechanism (a keytab, not the password itself, is what gets stored — say so explicitly, since this is a real distinction worth a user's attention, unlike x509's simpler "your passphrase is stored" framing). Pass `remember.value` through to `requestKrb5Ticket`. Add a `revoked` emit and the "Forget" button (only shown when `linked === true`), calling the shared `unlinkIdentity(providerId)` — check `unlinkIdentity`'s actual signature in `api.ts` (it's already used by `IdentityLink.vue`; read that call site for the exact prop it needs, likely the provider's `id`/alias, which this component doesn't currently receive as a prop — add an `id: string` prop if needed, following whatever prop `IdentityLink.vue` already takes for the same purpose).
- `IdentitiesPage.vue`: bind the new `id` prop (if added) and `@revoked` handler (mirroring `handleX509Revoked`'s shape) to the `Krb5IdentityCard` branch.

**Step 4: Run to verify pass**

Run the relevant test files; expect PASS.

**Step 5: Full portal suite, lint, typecheck, and commit**

```bash
pixi run -e portal check
git add portal/src/lib/api.ts portal/src/lib/__tests__/api.test.ts portal/src/components/Krb5IdentityCard.vue portal/src/components/__tests__/Krb5IdentityCard.test.ts portal/src/components/IdentitiesPage.vue
git commit -m "feat(portal): add remember checkbox and forget button to Krb5IdentityCard"
```

(If `IdentitiesPage.test.ts` needs updating for the new prop/event binding, include it in this commit too.)

---

### Task 10: Full verification pass and PR update

**Step 1: Run everything**

```bash
pixi run -e dev lint-all
pixi run --environment dev test
pixi run -e portal check
helm lint charts/af-mcp-platform
```

Expected: all green.

**Step 2: Push and update PR #275**

Same HTTPS counter-rewrite recipe as before:

```bash
git -c url.https://github.com/.insteadOf=git@github.com: \
    -c credential.helper='!gh auth git-credential' \
    push origin krb5-token-provider-274
```

Fetch the current PR body, write the appended content to a scratch file via the Write tool (never a bash heredoc — see this session's earlier corruption incident), append a section describing the remember/keytab/renew/unlink work, and `gh pr edit 275 --repo maniaclab/af-mcp-platform --body-file <path>`.

---

## Execution notes for whoever runs this plan

- Task order matters: 1 and 2 are independent of each other but both feed Task 4. Task 3 (Vault wiring) is independent of 1/2 but feeds Task 5. Task 4 depends on 1, 2, and conceptually on 3 (needs `Krb5VaultStore` to exist, from Task 2, and the config field, from Task 3, though it can use a fake vault store in its own unit tests without waiting for Task 3's app.py wiring to land). Task 5 depends on 3 and 4. Task 6 depends on 4. Task 7 depends on 4 (needs `KrbTokenProvider`'s unlink-supporting internals). Task 8 can happen any time after 4-7 are functionally understood. Task 9 (portal) depends on 6 and 7 (needs the `remember` field and unlink to actually exist server-side). Task 10 is last.
- Several judgment calls are flagged inline (the checkbox's default state, exactly how `renew`'s base URL is derived, whether Vault is required unconditionally for any krb5-token entry or only when remember is actually used) — these are deliberately left for whoever implements, with the review pass as the real quality gate.
- This plan builds on top of PR #275's existing content (both the original backend plan and the portal-card plan) — it does not duplicate or revisit already-shipped, already-reviewed work from those two plans except where this plan explicitly modifies it (`KrbTokenProvider`, `Krb5TokenServiceClient`, `KrbTicketRequest`, `Krb5IdentityCard.vue`, `unlink_identity`).
