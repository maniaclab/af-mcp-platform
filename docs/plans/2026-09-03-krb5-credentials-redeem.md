# Krb5 Backend Redeem Endpoint Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Give backend MCP services a way to redeem a minted Kerberos ticket the same way `POST /v1/credentials/x509/redeem` already lets them redeem a VOMS proxy — plumbing only, no live `auth_type: krb5` consumer configured yet (matching how the original `krb5-token` provider work itself landed with `targets: []`).

**Architecture:** x509's redeem flow has two halves: (1) the aggregator mints an AF Broker Identity Token (`aud = spec.effective_audience`, no POSIX claims) and injects it as the outbound `Authorization` bearer when calling a backend service whose `services.yaml` entry has `auth_type: "x509"`; (2) the backend service itself — using the separate `af-credentials` client library, not anything in this repo — presents that same bearer token back to the broker's `POST /v1/credentials/x509/redeem`, which verifies it, maps its `aud` claim to a target via `app.state.x509_audiences`, and serves whatever proxy is currently cached/Vault-stored for `(sub, target)` — **read-only**, it never mints on demand (a synchronous backend-to-backend call has no way to prompt for a password anyway). This plan mirrors both halves for krb5, reading from the already-complete `KrbTokenProvider`/`Krb5VaultStore`/`CredentialCache` machinery rather than building any new storage.

`ServiceSpec.auth_type` (`mcp/registry.py`) is a plain `str`, not a `Literal` — adding `"krb5"` needs no schema change, just a new dispatch branch. No `services.yaml` entry will declare `auth_type: "krb5"` yet (per the "plumbing only" decision), so `app.state.krb5_audiences` will be empty in every real deployment until a consumer is chosen — exactly the same shape of deferred decision the original krb5-token-provider issue (#274) left for its own `targets: []`.

**Explicitly out of scope:** choosing the actual downstream service, any `services.yaml` change, and the separate `af-credentials` client library work (that's a different repo/plan — see the companion research this session gathered on `ProxyClient`'s current x509-only shape, to be executed as its own plan once this side's contract is final).

**Tech Stack:** Same as the rest of this repo — FastAPI, pydantic v2, structlog, pytest/pytest-asyncio.

---

## Reference material already gathered this session

- **`POST /v1/credentials/x509/redeem`** (`broker/src/af_mcp_broker/api/credentials.py:774-903`, mounted on `backend_router` — the router authenticated by an AF Broker Identity Token, distinct from the Keycloak-JWT `router`):
  - Verifies `Authorization: Bearer <token>` via `request.app.state.broker_token_issuer.verify(...)`. `claims["sub"]` = subject, `claims["aud"]` = token audience.
  - Maps `aud` → target via `app.state.x509_audiences` — a `dict[effective_audience -> target_name]` built in `app.py` as `{spec.effective_audience: spec.name for spec in services if spec.auth_type == "x509"}`. An unmapped `aud` → 403.
  - Resolves the provider for that target from `credential_registry`. If nothing cached/Vault-stored and fresh enough → 404 with a hint detail (`_REDEEM_MINT_HINT`-style constant). Otherwise builds and returns `ProxyRedeemResponse`.
  - `ProxyRedeemResponse`: `{pem: str, dn: str, voms_attributes: list[str], expires_at: str (ISO-8601), remaining_seconds: int, nickname: str | None}`.
  - Response bodies never leave the broker except via this one deliberate, documented exception route — the module docstring calls this out explicitly.
- **Aggregator `auth_type` dispatch** (`broker/src/af_mcp_broker/mcp/aggregator.py`, the function building each service's client factory, ~line 586 onward): a plain `if spec.auth_type == "none": ... if spec.auth_type == "x509": ...` chain, falling through to a generic `_bearer_factory` for anything else. The x509 branch (verbatim structure, read directly before implementing):
  ```python
  if spec.auth_type == "x509":
      async def _x509_factory() -> Client:
          ctx = get_context()
          if await ctx.get_state("authorized_call_target") != spec.name:
              # tools/list (or a stale-cache refresh): best-effort identity
              # header ...
              principal = await ctx.get_state("principal")
              if principal is None or broker_token_issuer is None:
                  return _build_client(spec, transport_cls)
              if not _might_be_entitled(principal, spec, policy):
                  return _build_client(spec, transport_cls)
              token, _ = broker_token_issuer.mint(principal.subject, spec.effective_audience)
              await ctx.set_state(f"__list_credential_status__:{spec.name}", (True, None), serializable=False)
              return _build_client(spec, transport_cls, headers={"Authorization": f"Bearer {token}"})

          principal = await ctx.get_state("principal")
          if principal is None:
              raise ToolError("No authenticated principal available for this tool call")
          if broker_token_issuer is None:
              raise ToolError(f"Service '{spec.name}' is an x509 service, which needs the broker to sign AF Broker Identity Tokens, but no signing key is configured (chart: broker.identityToken.existingSigningKeySecret).")

          try:
              provider = await credential_registry.resolve(spec.name)
          except KeyError as exc:
              raise ToolError(str(exc)) from exc

          await _require_linked(provider, principal, spec, settings, target_to_alias, identity_provider_configs)

          # Identity assertion only (sub/aud): the service redeems the proxy
          # with this token; it has no use for POSIX claims.
          token, _ = broker_token_issuer.mint(principal.subject, spec.effective_audience)
          return _build_client(spec, transport_cls, headers={"Authorization": f"Bearer {token}"})

      return _x509_factory
  ```
  Note the x509 branch does NOT call `provider.issue(...)` at all (unlike the generic bearer branch) — it only mints the identity token and lets the backend redeem separately. `_might_be_entitled`/`_require_linked` are already fully generic (take `provider`/`spec`/`principal`/`settings` with no x509-specific logic inside — confirmed by reading their call sites and signatures directly this session) — a krb5 branch can call them unchanged.
- **`app.py`'s `x509_audiences` construction** — find the exact site (search for `x509_audiences =`) to mirror for `krb5_audiences`.
- **`KrbTokenProvider`/`Krb5VaultStore`/`CredentialCache`** (already complete, from the two prior plans on `krb5-token-provider-274`, which this branch is based on): `CredentialCache.peek(subject, target, min_remaining=0.0)` (metrics-free live-cache read), `Krb5VaultStore.get_ticket(subject, min_remaining=0.0)` (Vault-authoritative fresh-ticket read, gated on `not_after`). Both are READ-ONLY accessors already built — this plan does not need to add any new storage or minting logic, only a route that reads them.
- **`af-credentials` context** (for awareness only — NOT part of this plan's file list): a separate, `maniaclab`-owned repo Giordon has admin on. Its `ProxyClient` is x509-only today, hardcoded to `/v1/credentials/x509/redeem`. A follow-up plan (separate repo, separate PR) will add `kind: Literal["x509","krb5"] = "x509"` support once this side's response contract (`KrbTicketRedeemResponse` below) is final — that plan needs this one's exact field names, so keep them stable once written.

---

### Task 1: `krb5_audiences` app-state wiring

**Files:**
- Modify: `broker/src/af_mcp_broker/app.py`
- Test: Modify `broker/tests/test_krb5_token_app.py` (or wherever `x509_audiences`'s construction is tested — find it first and mirror it)

**Step 1: Write the failing test**

Find and read the exact test (if any) covering `x509_audiences`'s construction/`app.state` exposure. Write an equivalent test asserting `app.state.krb5_audiences` is built correctly from a `services.yaml` fixture containing an `auth_type: "krb5"` service entry (even though no real deployment does this yet, the plumbing must work when one does) — e.g., a service named `krb5-example` with `audience: "krb5-example-service"` should produce `krb5_audiences == {"krb5-example-service": "krb5-example"}`.

**Step 2: Run to verify failure**

Run the relevant test file; expect FAIL (`AttributeError: 'State' object has no attribute 'krb5_audiences'` or similar).

**Step 3: Write the implementation**

In `app.py`, find the exact `x509_audiences = {...}` construction site and add an equivalent line immediately after it:

```python
krb5_audiences: dict[str, str] = {
    spec.effective_audience: spec.name
    for spec in service_registry.list_services()  # match x509_audiences's exact source expression -- read it first, don't guess the iterable
    if spec.auth_type == "krb5"
}
```

(Read the real `x509_audiences` line to confirm the exact source iterable/variable name — `service_registry.list_services()` is a guess at the plan-writing stage, verify against the actual code.) Assign `application.state.krb5_audiences = krb5_audiences` alongside the existing `application.state.x509_audiences = x509_audiences`.

**Step 4: Run to verify pass**

Run the test file; expect PASS.

**Step 5: Full suite, lint, typecheck, and commit**

```bash
pixi run --environment dev test
pixi run -e dev lint-all
git add broker/src/af_mcp_broker/app.py broker/tests/test_krb5_token_app.py
git commit -m "feat(broker): build krb5_audiences app-state mapping for redeem"
```

---

### Task 2: `POST /v1/credentials/krb5/redeem`

**Files:**
- Modify: `broker/src/af_mcp_broker/api/credentials.py`
- Test: Create `broker/tests/test_krb5_redeem.py` (or extend `test_krb5_ticket_endpoint.py` if that reads more naturally once you see the real file — check first)

**Step 1: Write the failing tests**

Read the REAL, current `POST /credentials/x509/redeem` route in full (`api/credentials.py:774-903`ish — line numbers are approximate, from an earlier read this session; confirm current location) before writing anything — this task is a close structural mirror, not a reinterpretation. Write tests covering:
- A valid AF Broker Identity Token whose `aud` maps (via the new `krb5_audiences`) to a configured target, with a live cached ticket for `(sub, target)` → 200, `KrbTicketRedeemResponse` body matches the cached credential's fields, `ccache_b64` present.
- Same but with the cache empty and only a Vault-stored fresh ticket (no cache hit — simulating a broker restart) → 200, same response, read from Vault.
- Nothing cached AND nothing in Vault for that `(sub, target)` → 404 with a hint detail (mirror x509's `_REDEEM_MINT_HINT`-style wording, adapted to say "mint one via POST /v1/krb5/ticket" instead of the x509 equivalent).
- A token whose `aud` doesn't map to any configured krb5 target → 403 (mirror x509's exact behavior/message here).
- No `Authorization` header / invalid token → 401 (mirror x509's exact handling — this may already be handled generically by whatever verifies `broker_token_issuer.verify(...)` for every route on `backend_router`, in which case you don't need a new test, just confirm the existing generic behavior covers this route too).
- Confirm the response NEVER includes anything beyond the documented fields — no raw Vault/cache internals leaking.

**Step 2: Run to verify failure**

Run the new test file; expect FAIL (404 — route doesn't exist yet).

**Step 3: Write the implementation**

In `api/credentials.py`, near the existing x509 redeem route:

1. Add a `KrbTicketRedeemResponse` pydantic model:
   ```python
   class KrbTicketRedeemResponse(BaseModel):
       model_config = ConfigDict(frozen=True)

       ccache_b64: str
       principal: str
       realm: str
       expires_at: str  # ISO-8601
       remaining_seconds: int
       renew_until: str | None = None  # ISO-8601, null if not renewable
   ```
   (Match field names EXACTLY to what `KrbTokenProvider`'s cached `IssuedCredential.payload` already carries — `ccache_b64`/`principal`/`realm`/`renew_until` — read `credentials/krb5.py`'s `_build_credential`/payload-construction code to confirm the exact keys before naming this model's fields, don't guess.)

2. Add `@backend_router.post("/credentials/krb5/redeem", response_model=KrbTicketRedeemResponse)`, mirroring the x509 route's exact structure: verify the bearer token, map `aud` → target via `request.app.state.krb5_audiences`, 403 if unmapped. Read the ticket **read-only** — no minting, no renewal side effects:
   ```python
   async def redeem_krb5_ticket(request: Request) -> KrbTicketRedeemResponse:
       # ... token verification mirroring redeem_x509_proxy's exact preamble ...
       target = request.app.state.krb5_audiences.get(audience)
       if target is None:
           raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="...")  # match x509's exact wording style

       cache = _cache(request)  # or however x509's route obtains the CredentialCache
       cred = await cache.peek(subject, target, min_remaining=0.0)
       if cred is None:
           vault_store = ...  # resolve the krb5 provider's vault_store the same way the route resolves whatever x509 needs
           record = await vault_store.get_ticket(subject, min_remaining=0.0)
           if record is None:
               raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No Kerberos ticket is currently available for this target. Mint one via POST /v1/krb5/ticket first.")
           # build KrbTicketRedeemResponse from `record`
           ...
       else:
           # build KrbTicketRedeemResponse from `cred.payload`
           ...
   ```
   (This pseudocode is a sketch of the CONTROL FLOW, not literal code to paste — read the real x509 route's exact variable names, helper functions (`_cache(request)`, however it resolves `broker_token_issuer`, however it resolves a provider from `credential_registry`), and mirror them precisely. Resolve the `KrbTokenProvider` for `target` via `credential_registry` to get at its `_vault_store` the same way the route needs to reach whatever x509 needs — check whether the x509 route reaches into the provider's internals directly or goes through a public method, and follow that same access pattern for krb5, adding a small public accessor to `KrbTokenProvider` if needed rather than reaching into `_vault_store` directly from the route — mirror whatever convention x509 actually uses.)

**Step 4: Run to verify pass**

Run the test file; expect PASS.

**Step 5: Full suite, lint, typecheck, and commit**

```bash
pixi run --environment dev test
pixi run -e dev lint-all
git add broker/src/af_mcp_broker/api/credentials.py broker/tests/test_krb5_redeem.py
git commit -m "feat(broker): add POST /v1/credentials/krb5/redeem"
```

---

### Task 3: Aggregator `auth_type: "krb5"` branch

**Files:**
- Modify: `broker/src/af_mcp_broker/mcp/aggregator.py`
- Test: Modify whatever test file covers the x509 aggregator branch (likely `test_mcp_aggregator.py` or `test_mcp_credential_injection_integration.py` — find it first)

**Step 1: Write the failing test**

Read the real x509 aggregator branch's test(s) in full first. Write an equivalent test for a `krb5`-`auth_type` service: confirm that on an authorized tool call, the outbound client factory injects `Authorization: Bearer <token>` where the token's `aud` claim equals `spec.effective_audience`, WITHOUT calling `provider.issue(...)` (unlike the bearer branch) — mirroring x509's exact "mint and inject, let the backend redeem" behavior, not the bearer branch's "mint via provider.issue() and inject that credential directly" behavior. Also test the `tools/list`-time best-effort branch (no `authorized_call_target` set yet) behaves the same as x509's equivalent.

**Step 2: Run to verify failure**

Run the test file; expect FAIL (falls through to the generic `_bearer_factory`, which behaves differently — e.g. tries `provider.issue()` and fails, or produces a different header).

**Step 3: Write the implementation**

Add an `if spec.auth_type == "krb5":` branch immediately after the x509 branch (or wherever reads most naturally in the real if-chain), copying the x509 branch's structure verbatim except for the `auth_type` check itself and any x509-specific wording in error messages (e.g. "is an x509 service, which needs..." → "is a krb5 service, which needs...").

**Step 4: Run to verify pass**

Run the test file; expect PASS.

**Step 5: Full suite, lint, typecheck, and commit**

```bash
pixi run --environment dev test
pixi run -e dev lint-all
git add broker/src/af_mcp_broker/mcp/aggregator.py <test file>
git commit -m "feat(broker): add auth_type=krb5 branch to the aggregator's client-factory dispatch"
```

---

### Task 4: Docs

**Files:**
- Modify: `docs/auth.md`

**Step 1: Extend the `KrbTokenProvider` section**

Add a short subsection (or extend the existing section — read it first to decide where this reads most naturally) documenting: `POST /v1/credentials/krb5/redeem`'s contract (mirroring how the x509 redeem endpoint is already documented elsewhere in this file — find that section and match its structure/depth), that it's read-only (never mints), the 404/403 cases, and the aggregator's new `auth_type: "krb5"` dispatch branch — explicitly noting, as the original issue #274 did, that no `services.yaml` entry uses it yet; this is provider-type-plumbing for a not-yet-chosen consumer, same as before.

**Step 2: Commit**

```bash
git add docs/auth.md
git commit -m "docs: document POST /v1/credentials/krb5/redeem and auth_type: krb5"
```

---

### Task 5: Full verification pass and PR

**Step 1: Run everything**

```bash
pixi run -e dev lint-all
pixi run --environment dev test
helm lint charts/af-mcp-platform
```

(No portal changes in this plan, so `pixi run -e portal check` isn't needed unless something surprising came up.)

**Step 2: Push and open a NEW PR (per this session's decision — this is a separate branch/PR from #275, not an addition to it)**

```bash
git -c url.https://github.com/.insteadOf=git@github.com: \
    -c credential.helper='!gh auth git-credential' \
    push -u origin krb5-credentials-redeem
```

Open a PR titled something like `feat: add POST /v1/credentials/krb5/redeem and auth_type: krb5` with `gh pr create` (write the body to a scratch file first, never a bash heredoc — a prior heredoc attempt this session corrupted a PR body by executing backtick-quoted inline-code spans as real shell commands). Note in the PR body that this branch is based on the not-yet-merged `krb5-token-provider-274` (PR #275) and should merge after it, since it depends on `KrbTokenProvider`/`Krb5VaultStore` existing.

---

## Execution notes for whoever runs this plan

- This branch (`krb5-credentials-redeem`) is based on `krb5-token-provider-274`, NOT `main` — it depends on that branch's `KrbTokenProvider`/`Krb5VaultStore`/`Krb5TokenServiceClient` work, which is not yet merged. The resulting PR should note this dependency and target merging after PR #275, not before or independent of it.
- Task order: 1 (audiences) and 2 (redeem route) can be done together or 1-then-2; 3 (aggregator) is independent of 1/2's route but should land after so the docs task can describe both together. 4 (docs) last before 5.
- `KrbTicketRedeemResponse`'s exact field names are load-bearing for the separate `af-credentials` plan that follows this one — get them right and don't rename them casually once Task 2 lands, since the client library work will be written against this exact contract.
- Do NOT touch `services.yaml`, do NOT choose a downstream consumer, do NOT bump any version numbers — all explicitly out of scope per this session's design conversation.
