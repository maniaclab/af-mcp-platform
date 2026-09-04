# krb5 User-Provided Keytab Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Remove `KrbTokenProvider`'s broker-side "remember" keytab auto-bootstrap (it calls `krb5-token-service`'s `mint_keytab()`, which shells out to `cern-get-keytab` — confirmed unreachable from the AF cluster's network: `cern-get-keytab`'s `msktutil` backend needs CERN-internal LDAP/AD access, and an SSH-tunnel-through-lxplus workaround is blocked by CERN's mandatory SSH 2FA, which cannot be satisfied non-interactively). Replace it with a user-provided-keytab flow: the user generates their own keytab on lxplus (which has no such reachability problem — it's running directly on CERN's network) and uploads it through the portal. The broker validates the upload by minting a ticket with it (`kinit -kt`, which only needs the CERN KDC on port 88 — already open, already used by every other tier) and, on success, stores it exactly where the old "remember" flow would have.

**Architecture:** `KrbTokenProvider.issue()`'s tiers 1-4 (cache, Vault repopulation, renew, remint-from-stored-keytab) are UNCHANGED — none of them ever touched `cern-get-keytab`; only tier 5's post-mint "bootstrap a keytab from the just-supplied password" side effect is removed. A new, separately-invoked `KrbTokenProvider.link_keytab()` method (parallel to `revoke()`/`unlink()`, not part of the `issue()` tier fallback) takes a user-uploaded keytab, validates it via the exact same `Krb5TokenServiceClient.mint(..., keytab_b64=...)` call tier 4 already uses, and on success persists it via `Krb5VaultStore.store_link()` — reusing 100% of the existing Vault schema and tier-4 remint logic; only how the link gets INTO Vault changes (upload instead of auto-bootstrap-from-password).

**Tech Stack:** Python 3.12 FastAPI (broker), Vue 3 + TypeScript (portal), pytest, vitest.

**Repos touched:**
- `/Users/kratsg/af-mcp-platform` (broker + portal + docs) — primary work, new branch off `main`.
- `/Users/kratsg/krb5-token-service` — README-only doc addition, no code change (confirmed with Giordon: "krb5-token-service is mostly fine... we just need to change how we get the keytab" — its own `/v1/keytab`/`mint_keytab()`/`cern-get-keytab` machinery is left in place, since it would work correctly for a hypothetical CERN-network-hosted deployment; it's only unreachable from *this* facility's network. Only the *caller* in af-mcp-broker is being removed.)

**Explicit design decision to flag in the PR description** (not silently assumed): `Krb5TokenServiceClient.mint_keytab()` (the af-mcp-broker-side HTTP client method wrapping krb5-token-service's `/v1/keytab`) is being deleted outright, not feature-flagged off, since nothing in af-mcp-broker will call it after this change and this codebase's convention is not to keep unused code "for a hypothetical future" (per the project's CLAUDE.md). It is one `git revert` away from returning if a future CERN-network-hosted facility ever wants it back.

---

### Task 1: Remove the "remember" auto-bootstrap from `KrbTokenProvider`, add `link_keytab()`

**Files:**
- Modify: `broker/src/af_mcp_broker/credentials/krb5.py`
- Test: `broker/tests/test_krb5_token.py` (exact filename — confirm via `ls broker/tests/ | grep krb5` before editing; adjust if it differs)

**Context:** Read the current file in full first — it's ~380+ lines. Relevant regions (line numbers approximate, current as of this plan's writing):
- Module docstring (lines 1-40ish) describes the tier architecture and the "remember" bootstrap — needs rewriting.
- `issue()` (line 134 onward): `remember: bool = False` parameter (line 144), and its docstring paragraph (lines 148-151).
- `_do_mint()` (line 279 onward): the `if remember:` block (lines 291-322) that calls `self._client.mint_keytab(...)` and `self._vault_store.store_link(...)`.

**Step 1: Write the failing tests first**

In the krb5 provider's test file, add a test asserting `issue()` no longer accepts (or silently ignores — pick whichever the existing test suite's style favors; if `issue()` is called with keyword args throughout the test suite, simply removing `remember=` from the signature makes any leftover caller a `TypeError`, which IS the test) a `remember` parameter, and add:

```python
async def test_link_keytab_validates_and_stores_link(self, ...):
    """link_keytab() mints a validating ticket with the uploaded keytab, then stores it as the link half."""
    # Arrange: fake Krb5TokenServiceClient.mint() to succeed for keytab_b64=<some fixture>.
    # Act: await provider.link_keytab(principal, target, username=..., keytab_b64=...)
    # Assert: vault_store.store_link was called with the right username/keytab_b64,
    # AND the ticket half was persisted (vault_store.store_ticket / cache populated),
    # AND the returned IssuedCredential's payload matches the mint response.

async def test_link_keytab_propagates_bad_credential_error(self, ...):
    """A keytab that doesn't work for the given username raises Krb5TokenBadCredentialError, and nothing is stored."""
    # Arrange: fake client.mint() to raise Krb5TokenBadCredentialError.
    # Act + Assert: pytest.raises(Krb5TokenBadCredentialError): await provider.link_keytab(...)
    # Assert: vault_store.store_link was NEVER called (validate-before-store, not store-then-validate).
```

Match this test file's existing fixture/mocking style exactly (look at how `test_issue_tier4_remint_from_stored_keytab`-equivalent tests, if present, mock `self._client`/`self._vault_store` — reuse the same fixtures rather than inventing new mocking patterns).

Also update/remove any existing test that exercises `issue(..., remember=True)` and asserts `mint_keytab()` gets called — that behavior no longer exists. Don't just delete the test silently; if it was testing something still relevant (e.g. that tier-5 mint still succeeds and persists the ticket), keep that assertion and drop only the remember-specific part.

**Step 2: Run the tests, confirm the new ones fail** (`link_keytab` doesn't exist yet) and any remember-specific test you haven't yet touched fails/errors appropriately.

Run: `pixi run --environment dev pytest broker/tests/test_krb5_token.py -v` (adjust filename if `ls` showed something else).

**Step 3: Implement**

In `krb5.py`:
1. Remove `remember: bool = False` from `issue()`'s signature, and its docstring paragraph explaining it.
2. Remove the entire `if remember:` block from inside `_do_mint()` (the try/except around `self._client.mint_keytab(...)` / `self._vault_store.store_link(...)` / the two log lines). `_do_mint()` should end at `return cred` (previously line ~290's `cred = await self._persist_and_cache(...)`, now just `return cred` — the tier-5 mint function returns immediately after persisting/caching, no side effect).
3. Add a new public method (place it near `revoke()`/`unlink()`, since it's a directly-invoked action, not a tier inside `issue()`):

```python
async def link_keytab(
    self,
    principal: Principal,
    target: str,
    *,
    username: str,
    keytab_b64: str,
    lifetime: str | None = None,
    renewable_lifetime: str | None = None,
) -> IssuedCredential:
    """Validate a user-supplied keytab by minting a ticket with it, then store it as this principal's link.

    The broker cannot generate a keytab itself (see the module docstring
    for why `cern-get-keytab` is unreachable from this facility's
    network) -- the user generates one themselves (e.g. on lxplus) and
    uploads it here. Validation IS the mint: a bad keytab surfaces as
    the exact same ``Krb5TokenBadCredentialError`` tier 4's remint
    already handles, from the exact same underlying `kinit -kt` check
    (krb5-token-service's own mint endpoint, keytab_b64 branch) -- there
    is no separate "just check, don't use" call.

    Nothing is stored if validation fails: this mints (and thus proves
    the keytab works) BEFORE calling store_link, not after -- a caller
    must never end up with a bad keytab persisted to Vault.
    """
    keytab_secret = SecretStr(keytab_b64)
    ticket = await self._client.mint(
        subject=principal.subject,
        username=username,
        keytab_b64=keytab_secret,
        lifetime=lifetime,
        renewable_lifetime=renewable_lifetime,
    )
    await self._vault_store.store_link(
        principal.subject,
        username=username,
        keytab_b64=keytab_secret,
    )
    return await self._persist_and_cache(principal, target, ticket, tier="keytab_link")
```

Check `_persist_and_cache`'s exact signature (it's already used by `_do_renew`/`_do_remint`/`_do_mint` — the `tier=` argument is presumably just a metrics/log label; use a new, distinct value like `"keytab_link"` so it's distinguishable from `"keytab_remint"` in metrics/logs, but confirm this argument's actual purpose by reading `_persist_and_cache`'s body first — don't guess).

4. Rewrite the module docstring (top of file). It currently frames "remember" as bootstrapping a keytab from a password (check the exact current wording — you read it in Step 1). Replace that framing with: the broker cannot mint a keytab itself (network-unreachable `cern-get-keytab` dependency — briefly explain why: CERN's `msktutil`-based keytab retrieval needs LDAP/AD access to `cerndc.cern.ch` and an HTTPS call to `lxkerbwin.cern.ch`, neither reachable from this facility's network, and a considered SSH-tunnel-through-lxplus workaround was ruled out because CERN's lxplus enforces mandatory 2FA on every SSH login, which cannot be satisfied non-interactively by an automated service); tier 4 (remint from a stored keytab) is unaffected because `kinit -kt` only needs the CERN KDC on port 88, already open; the link half of `Krb5VaultStore` is now populated by `link_keytab()` (a user-uploaded keytab, validated by minting with it) instead of by an automatic password-derived bootstrap.

**Step 4: Run tests, confirm they pass.**

**Step 5: Commit**

```bash
git add broker/src/af_mcp_broker/credentials/krb5.py broker/tests/test_krb5_token.py
git commit -m "feat(broker): replace krb5 keytab auto-bootstrap with user-provided upload"
```

(Adjust the test file path/name to whatever Step 1 actually found.)

---

### Task 2: Remove the now-dead `Krb5TokenServiceClient.mint_keytab()`

**Files:**
- Modify: `broker/src/af_mcp_broker/credentials/krb5_service.py`
- Test: wherever `mint_keytab` is tested (grep for it — likely `broker/tests/test_krb5_service_client.py`)

**Context:** After Task 1, nothing in af-mcp-broker calls `Krb5TokenServiceClient.mint_keytab()` anymore. Confirm this with `grep -rn "mint_keytab" broker/` before deleting — it should only appear in `krb5_service.py`'s own definition and its dedicated tests.

**Step 1:** Delete the `mint_keytab()` method from `krb5_service.py`. Check whether any of its exception classes (grep the file's class list from earlier: `Krb5TokenMintError`, `Krb5TokenBadCredentialError`, `Krb5TokenAccountError`, `Krb5TokenInvalidRequestError`, `Krb5TokenRateLimitedError`, `Krb5TokenInvalidCcacheError`, `Krb5TokenRenewalWindowClosedError`) are raised ONLY inside `mint_keytab()` and nowhere else (`mint()`/`renew()` also raise several of the same ones — do NOT delete an exception class still used elsewhere). Update the module docstring if it specifically describes `mint_keytab`'s role in the overall design (it likely does, given the file's docstring pattern seen in `minting.py`'s equivalent).

**Step 2:** Delete or update its dedicated tests. If some tests in that file also cover `mint()`/`renew()`, only remove the `mint_keytab`-specific test cases, not the whole file.

**Step 3:** Run the full broker test suite to confirm nothing else references the removed method:

Run: `pixi run --environment dev pytest broker/ -v`

**Step 4:** Run `pixi run -e dev lint-all` (ruff + mypy will catch any lingering reference or now-unused import).

**Step 5: Commit**

```bash
git add broker/src/af_mcp_broker/credentials/krb5_service.py <test file>
git commit -m "refactor(broker): remove unused Krb5TokenServiceClient.mint_keytab()"
```

---

### Task 3: Broker API — drop `remember`, add `POST /v1/krb5/keytab`

**Files:**
- Modify: `broker/src/af_mcp_broker/api/credentials.py`
- Test: wherever the krb5 ticket route is tested (grep for `/krb5/ticket` — likely `broker/tests/test_krb5_ticket_endpoint.py` or similar)

**Context:** Read `KrbTicketRequest` (around line 105), `KrbTicketMetadata` (around line 123), and the `create_krb5_ticket` route (around line 469-527) in full first — quoted verbatim above in this plan's investigation, but re-read from the file directly since line numbers may have shifted.

**Step 1: Write the failing tests**

Add tests for a new route, e.g.:

```python
async def test_link_keytab_route_success(self, ...):
    """POST /v1/krb5/keytab validates and stores a keytab, returning the same KrbTicketMetadata shape as /krb5/ticket."""
    # mock provider.link_keytab to return a fixture IssuedCredential
    # POST {"username": "gstark", "keytab_b64": "<base64>"} -> 201, body matches KrbTicketMetadata shape

async def test_link_keytab_route_bad_keytab_returns_400(self, ...):
    # mock provider.link_keytab to raise Krb5TokenBadCredentialError
    # POST -> 400
```

Mirror `create_krb5_ticket`'s existing test cases' structure/fixtures exactly (same dependency-override pattern for `keycloak_dependency`/`_krb5_provider`, if that's how the existing tests inject a fake provider — check the existing `/krb5/ticket` tests' setup before writing these).

Also update the existing `/krb5/ticket` route tests: remove any assertion involving a `remember` field in the request or response.

**Step 2: Run, confirm failure** (route doesn't exist / 404).

**Step 3: Implement**

1. Remove `remember: bool = False` from `KrbTicketRequest` (and its docstring comment).
2. Remove `remember=body.remember` from `create_krb5_ticket`'s call to `provider.issue(...)`.
3. Add a new request model right after `KrbTicketRequest`:

```python
class KrbKeytabLinkRequest(BaseModel):
    model_config = ConfigDict(frozen=True)

    username: str
    # Base64-encoded raw keytab bytes. The user generates this themselves
    # (e.g. on lxplus via `cern-get-keytab --keytab <user>.keytab --user`)
    # -- the broker cannot generate one itself; see krb5.py's module
    # docstring for why.
    keytab_b64: str
    target: str | None = None
    lifetime: str | None = None
    renewable_lifetime: str | None = None
```

4. Add a new route, placed right after `create_krb5_ticket`:

```python
@router.post(
    "/krb5/keytab",
    response_model=KrbTicketMetadata,
    status_code=status.HTTP_201_CREATED,
    summary="Validate and store a user-provided Kerberos keytab",
)
async def link_krb5_keytab(
    body: KrbKeytabLinkRequest,
    request: Request,
    principal: Annotated[Principal, Depends(keycloak_dependency)],
) -> KrbTicketMetadata:
    target = _resolve_krb5_target(request, body.target)
    provider = await _krb5_provider(request, target)
    try:
        cred = await provider.link_keytab(
            principal,
            target,
            username=body.username,
            keytab_b64=body.keytab_b64,
            lifetime=body.lifetime,
            renewable_lifetime=body.renewable_lifetime,
        )
    except Krb5TokenBadCredentialError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc
    except Krb5TokenAccountError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)
        ) from exc
    except Krb5TokenInvalidRequestError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)
        ) from exc
    except Krb5TokenRateLimitedError as exc:
        headers = {"Retry-After": exc.retry_after} if exc.retry_after else None
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=str(exc),
            headers=headers,
        ) from exc
    except Krb5TokenMintError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Kerberos ticket issuance is temporarily unavailable — retry later.",
        ) from exc

    payload = cred.payload
    renew_until = payload.get("renew_until")
    return KrbTicketMetadata(
        target=target,
        principal=payload["principal"],
        realm=payload["realm"],
        expires_at=_iso(cred.expires_at),
        remaining_seconds=max(0, int(cred.expires_at - time.time())),
        renew_until=_iso(renew_until) if renew_until is not None else None,
    )
```

This is intentionally near-identical to `create_krb5_ticket` — same error mapping, same response construction. If you find yourself copy-pasting more than this, consider (but don't over-engineer) whether the shared response-construction tail (`payload = cred.payload` through the `return KrbTicketMetadata(...)`) is worth factoring into a small helper — use judgment; a 6-line block duplicated twice is arguably fine, don't force an abstraction for its own sake.

**Step 4: Run tests, confirm pass.**

**Step 5: Commit**

```bash
git add broker/src/af_mcp_broker/api/credentials.py <test file>
git commit -m "feat(broker): add POST /v1/krb5/keytab to link a user-provided keytab"
```

---

### Task 4: Full broker verification before moving to the portal

**Files:** none (verification only)

Run:
- `pixi run -e dev lint-all`
- `pixi run --environment dev test`

Fix anything red before proceeding — don't let broker-side issues carry into the portal tasks.

---

### Task 5: Portal — remove the "remember" checkbox

**Files:**
- Modify: `portal/src/components/Krb5IdentityCard.vue`
- Modify: `portal/src/lib/api.ts`
- Test: wherever `Krb5IdentityCard.vue` and `requestKrb5Ticket` are unit-tested (grep for them under `portal/`)

**Step 1: Write/update failing tests**

Update the component's existing tests to no longer expect a "remember" checkbox to exist, and no longer pass a `remember` argument when asserting on `requestKrb5Ticket`'s call arguments. Update `api.ts`'s tests for `requestKrb5Ticket` to drop the `remember` parameter/body field from the expected request.

**Step 2: Run, confirm failures reflecting the still-present checkbox/param.**

**Step 3: Implement**

In `Krb5IdentityCard.vue`:
- Remove the `remember` ref (line ~52) and its reset in `openForm()` (line ~86).
- Remove the entire "Custody consent" `<div class="kc__form-group">` block containing the checkbox (lines ~274-295).
- Update `handleSubmit()`'s call to `requestKrb5Ticket(...)` to drop the trailing `remember.value` argument.
- Update the password field's hint text (line ~268-271, "...unless you remember this ticket below.") — that sentence no longer makes sense without the checkbox; simplify to something like "Your CERN password is used once to mint this ticket and is never stored — you'll need to re-enter it after the ticket expires." (Task 6 will separately mention the keytab-upload alternative near this same form, so don't try to cram that into this hint text now — keep this task scoped to removal.)
- Update the top-of-file module doc comment (lines 1-26) — it currently frames the whole card around the "remember" checkbox concept; leave a note that this will be substantially rewritten in Task 6 rather than polishing it twice, but do remove the now-false claim that a checkbox exists in this task.

In `api.ts`:
- Remove the `remember: boolean = false` parameter from `requestKrb5Ticket()`'s signature and the `remember` field from its request body.
- Update the function's docstring (lines ~588-604) to remove the "remember is the custody consent..." paragraph.

**Step 4: Run tests, confirm pass:** `pixi run -e portal check` (or whatever this repo's portal test task is — confirm via `docs/local-development.md`/`CLAUDE.md`, likely `pixi run -e portal dev`'s sibling `check`/`test` task).

**Step 5: Commit**

```bash
git add portal/src/components/Krb5IdentityCard.vue portal/src/lib/api.ts <test files>
git commit -m "feat(portal): remove krb5 keytab remember checkbox"
```

---

### Task 6: Portal — add the keytab-upload flow

**Files:**
- Modify: `portal/src/components/Krb5IdentityCard.vue`
- Modify: `portal/src/lib/api.ts`
- Modify: `portal/src/lib/krb5Identity.ts` (if it needs a new error-message helper for the keytab route — check its current contents first; reuse `krb5LinkErrorMessage` if its status-code mapping is already generic enough, since `/krb5/keytab` returns the exact same 400/403/422/429/502 status codes as `/krb5/ticket`)
- Test: component/unit tests for the above

**Step 1: Write failing tests** covering:
- A new "Link a keytab" UI affordance is present (however you choose to expose it — see Step 3's design note).
- Selecting/pasting a keytab and submitting calls a new API function (name it `linkKrb5Keytab` for symmetry with `requestKrb5Ticket`) with the right username/keytab_b64 payload.
- A validation failure (mock the API call rejecting) surfaces an error message using `krb5LinkErrorMessage` (confirm this helper's signature is generic enough to reuse for both routes' errors — read `krb5Identity.ts` first).

**Step 2: Run, confirm failures** (function/UI doesn't exist yet).

**Step 3: Implement**

Design note (use judgment on the exact layout, but the requirements are firm): this is a SEPARATE action from the existing password-mint form, not a merged single form — minting a one-shot ticket (needs a live CERN password) and linking a durable keytab (needs a pre-generated keytab file, not a password) are different user actions with different inputs. Add either a second collapsible section within the same card, or a second button ("Link a keytab for automatic renewal") that reveals its own small form, consistent with how `formOpen` already gates the password form. Whichever you choose, it must NOT be visible at the same time as the password-mint form (avoid two open forms cluttering one card) — reuse or extend the existing `formOpen`-style state machine rather than inventing an unrelated pattern.

The upload form needs:
- A CERN username field (a keytab alone doesn't disambiguate the account the way a password-typed-by-a-known-user does — the request needs `username` explicitly, matching `KrbKeytabLinkRequest`).
- A way to supply the keytab bytes: an `<input type="file">` reading the file via `FileReader.readAsArrayBuffer` (or `readAsBinaryString`/base64-encode client-side — a keytab is a small binary file, a few KB at most) into a base64 string for the JSON POST body. Do NOT add a raw-paste-base64 textarea as well unless a file input alone feels insufficient for your judgment — keep it to one clear input method.
- Instructions text, verbatim guidance for how to generate the keytab, based on this exact working sequence (confirmed working by Giordon on lxplus — reproduce these commands accurately, don't paraphrase them into something subtly different):
  ```
  ssh <username>@lxplus.cern.ch
  cern-get-keytab --keytab <username>.keytab --user
  # (enter your CERN password when prompted)
  kinit -kt <username>.keytab <username>@CERN.CH   # verify it works
  echo $?                                          # should print 0
  ```
  followed by "download `<username>.keytab` from lxplus (e.g. `scp <username>@lxplus.cern.ch:<username>.keytab .`) and upload it here."
- Submit button calling the new `linkKrb5Keytab()` function, disabled while busy, same busy/error-display conventions as the existing form.
- On success: same `result`/`emit('linked', meta)` handling as the password form's `handleSubmit` — the keytab-link route returns the same `KrbTicketMetadata` shape.

In `api.ts`, add:

```typescript
/**
 * Validate and store a user-provided Kerberos keytab.
 *
 * The broker mints a ticket with the keytab to prove it works (the same
 * `kinit -kt` check krb5-token-service's tier-4 remint already relies on)
 * before persisting it — a keytab that doesn't authenticate for `username`
 * is rejected with nothing stored.
 */
export async function linkKrb5Keytab(
  username: string,
  keytabB64: string,
  target?: string,
  lifetime?: string,
  renewableLifetime?: string,
): Promise<KrbTicketMetadata> {
  return apiFetch<KrbTicketMetadata>('/krb5/keytab', {
    method: 'POST',
    body: JSON.stringify({
      username,
      keytab_b64: keytabB64,
      target,
      lifetime,
      renewable_lifetime: renewableLifetime,
    }),
  });
}
```

(Match `apiFetch`'s exact usage pattern from `requestKrb5Ticket` immediately above it — same error handling, same import style.)

Rewrite `Krb5IdentityCard.vue`'s top-of-file module doc comment now (deferred from Task 5) to describe both flows: one-shot password mint (no custody), and keytab upload (custody, validated-then-stored, mirrors tier-4 remint).

**Step 4: Run tests, confirm pass:** `pixi run -e portal check`.

**Step 5: Commit**

```bash
git add portal/src/components/Krb5IdentityCard.vue portal/src/lib/api.ts portal/src/lib/krb5Identity.ts <test files>
git commit -m "feat(portal): add keytab upload flow for krb5 automatic renewal"
```

---

### Task 7: Docs — `docs/auth.md` (af-mcp-platform) and `README.md` (krb5-token-service)

**Files:**
- Modify: `/Users/kratsg/af-mcp-platform/docs/auth.md`
- Modify: `/Users/kratsg/krb5-token-service/README.md` (a DIFFERENT repo/working tree — this file's commit is separate from the af-mcp-platform commits above; do not mix them in one `git commit`)

**Step 1 (af-mcp-platform's docs/auth.md):** Find the `KrbTokenProvider` section (this doc was extensively written/updated earlier this session — read it in full first). Update:
- Remove any description of "remember" auto-bootstrapping a keytab from a password.
- Add a clear explanation of why: `cern-get-keytab`'s `msktutil` backend needs CERN-internal LDAP/AD reachability (`cerndc.cern.ch`, a different port than the KDC's 88) plus an HTTPS call to `lxkerbwin.cern.ch` — neither reachable from this facility's network (confirmed by testing: the call hangs and times out after `CERN_GET_KEYTAB_TIMEOUT_SECONDS`). An SSH-tunnel-through-lxplus workaround was investigated and ruled out: lxplus enforces mandatory multi-factor SSH (Kerberos + registered SSH key + interactive 2FA), and the interactive 2FA step cannot be satisfied by an unattended service.
- Document the replacement: `POST /v1/krb5/keytab` lets a user upload a keytab they generated themselves (on lxplus, where none of the above reachability problems exist), which the broker validates by minting a ticket with it before storing it — reusing the exact same `Krb5VaultStore` link-half schema and tier-4 remint logic the old "remember" flow populated, just populated a different way.
- Confirm tier 4 (remint from stored keytab) and the renew tier (tier 3) are both still described accurately — they are UNCHANGED by this work, but re-read them to make sure nothing you're rewriting nearby accidentally implies otherwise.

**Step 2 (krb5-token-service's README.md):** Read the current README in full. Add a note — likely near wherever `krb5.conf`/`[libdefaults]` is already documented, or a new small "Known deployment gotchas" / "Troubleshooting" section if none exists — documenting:

```
[libdefaults]
    dns_canonicalize_hostname = false
```

as a setting that may be needed in the deployed `krb5.conf` (see the chart's `krb5Config.override`/`krb5Config.contents` values, `charts/krb5-token-service/values.yaml`) to prevent DNS canonicalization of KDC hostnames — confirmed needed on the UChicago AF deployment. Phrase it as guidance ("you may need this, depending on your resolver/network setup — confirmed necessary at UChicago's AF") rather than asserting it's universally required, matching how Giordon described it. Do NOT change the chart's shipped default `krb5.conf` in `values.yaml` — this task is documentation-only, per explicit scope.

**Step 3:** No automated test for a docs-only change. Read your diff once for accuracy against what's actually implemented in Tasks 1-6 before committing (don't describe a route/parameter name that ended up different during implementation).

**Step 4: Commit** (as two SEPARATE commits, one per repo):

In af-mcp-platform:
```bash
git add docs/auth.md
git commit -m "docs: replace krb5 keytab auto-bootstrap docs with user-upload flow"
```

In krb5-token-service (separate `cd`, separate repo, separate commit — do not push this from af-mcp-platform's working tree):
```bash
cd /Users/kratsg/krb5-token-service
git add README.md
git commit -m "docs: note dns_canonicalize_hostname=false may be needed"
```

---

### Task 8: Final full verification

**Files:** none (verification only)

Run in af-mcp-platform:
- `pixi run -e dev lint-all`
- `pixi run --environment dev test`
- `pixi run -e portal check`

Run in krb5-token-service (if it has its own lint/check task for README changes — likely nothing beyond a markdown linter if one exists in pre-commit; check `.pre-commit-config.yaml`).

Report a clean summary. No commit for this task unless a fix is needed.

---

## Execution notes for whoever runs this (controller, not implementer)

- Follow **superpowers:subagent-driven-development**: implementer subagent per task → spec-compliance reviewer (independently verify, don't trust the report) → code-quality reviewer (`superpowers:code-reviewer`) → fix loops.
- New branch off `main` in af-mcp-platform for Tasks 1-7's af-mcp-platform commits (this repo's `main` currently has PR #275/#277's krb5 work merged/mergeable — branch from `main` after confirming #277 has actually merged, or from `krb5-credentials-redeem` if it hasn't yet, to avoid the same squash-merge-conflict situation encountered earlier this session).
- Task 7's krb5-token-service commit is independent — no branch/PR coordination needed with af-mcp-platform's branch, but check whether Giordon wants a PR there too or a direct push (that repo's contribution norms haven't been established this session — ask if unclear rather than assuming).
- PR body: written to a scratch file first, never a bash heredoc containing backticks.
- Version bumps: separate commit on `main` after merge, per this repo's established convention — not part of this PR.
