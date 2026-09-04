# Krb5 Portal Identity Card Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Give the portal's Identities page a working username+password form for the `krb5-token` provider, so a user can mint a Kerberos ticket via the already-shipped `POST /v1/krb5/ticket` broker endpoint.

**Architecture:** A new `Krb5IdentityCard.vue` component, modeled on `X509IdentityCard.vue` but stripped down (no preflight/proxy-details accordions — krb5 has no filesystem precondition check and no `GET` status endpoint today), wired into `IdentitiesPage.vue`'s existing `link_mechanism`-based card-selection chain via the new `"credential"` mechanism value the backend already emits. Backed by a new `requestKrb5Ticket()` API function and a `krb5Identity.ts` error-message helper mirroring `x509Identity.ts`'s.

**Explicitly out of scope for this plan** (per an in-session design conversation with Giordon):
- A "remember credentials" checkbox / any persistence of the CERN password or a keytab. Giordon is developing keytab-based renewal in krb5-token-service in a separate session; once that ships, a follow-up plan adds the checkbox and the Vault-backed storage it needs. This plan's card is one-shot: mint a ticket, done, no persistence.
- Any backend/broker changes — `POST /v1/krb5/ticket` already exists and is unmodified by this plan. This is a portal-only (Astro/Vue) change.
- A revoke button — x509 has a dedicated `DELETE /v1/x509/proxy`; no equivalent per-target revoke endpoint exists for krb5 today (only a blanket `DELETE /v1/credential` revoking every cached credential for the subject, which isn't fit for a single "revoke this ticket" button). No revoke UI in this plan.
- Displaying ticket expiry/principal/realm across page reloads — `/v1/identities` doesn't expose those fields for krb5 (only `linked: boolean`, via `KrbTokenProvider.is_linked()`'s cache-based check). This plan's card shows minted-ticket metadata transiently (from the `POST` response, in local component state) for the current page visit only, and falls back to the generic linked/not-linked badge otherwise.

**Tech Stack:** Astro, Vue 3 (`<script setup>`), TypeScript, Vitest + `@vue/test-utils`, ESLint + Prettier — the portal's existing stack, no new dependencies.

---

## Reference material already gathered this session

- `portal/src/components/X509IdentityCard.vue` (958 lines, `<style scoped>`, `.xc__*` BEM-ish class prefix) — the structural/styling template. Header (icon/name/status badge) → description → optional "powers" chips → expiry/custody line → action button → in-page form (input, checkbox, error, actions) → two fetch-on-expand accordions (skip both for krb5).
- `portal/src/components/IdentitiesPage.vue` (439 lines) — card selection is `v-if="p.link_mechanism === 'passphrase'"` → `X509IdentityCard`, else → generic `IdentityLink`. `X509IdentityCard` bindings: `:linked`, `:display_name`, `:enables`, `:powers="powersForAlias(p.id)"`, `:proxy_expires_at`, `:x509_link_mode`; emits `@linked="(meta, remember) => handleX509Linked(p.id, meta, remember)"`/`@revoked="handleX509Revoked(p.id)"`. Parent mutates the local `providers` ref in place on these events (no refetch) and calls `clearIdentitiesCache()` so the *next* page load isn't stale.
- `portal/src/lib/api.ts` (824 lines) — `ProviderType = 'keycloak-brokered' | 'oauth21-direct' | 'x509'`, `LinkMechanism = 'redirect' | 'passphrase' | 'none'` — **both missing `'krb5-token'`/`'credential'`, confirmed by grep**. Note: this file is already narrower than the backend's `ProviderType` Literal (no `broker-issued`/`condor-token` either) — only types with distinct UI get added here, which krb5 now needs.
  - `IdentityProvider` interface:
    ```ts
    export interface IdentityProvider {
      id: string;
      type: ProviderType;
      display_name: string;
      enables: string;
      linked: boolean;
      link_url: string | null;
      link_mechanism: LinkMechanism;
      proxy_expires_at?: string | null;       // x509-only
      x509_link_mode?: 'auto-renew' | 'until-expiry' | null;  // x509-only
      link_permission_denied?: boolean;       // keycloak-brokered-only
    }
    ```
    No new optional fields needed on this interface for krb5 (no expiry/mode exposed by `/v1/identities` today).
  - x509 API pattern to mirror:
    ```ts
    export interface ProxyMetadata { dn: string; voms_attributes: string[]; expires_at: string; remaining_seconds: number; }
    export async function requestProxy(passphrase: string, valid = '12:00', voms = 'atlas', remember = true): Promise<ProxyMetadata> {
      return apiFetch('/x509/proxy', { method: 'POST', body: JSON.stringify({ passphrase, valid, voms, remember }) });
    }
    ```
  - Shared HTTP layer: `apiFetch<T>(path, init)` → on `!res.ok` throws `new APIError(res.status, res.statusText, body)` (carries `.status`/`.statusText`/raw `.body` text). `SessionExpiredError`/`AccessDeniedError` are the other thrown types. No generic error-mapping in `api.ts` itself — that's each feature's own `*Identity.ts` module.
  - Confirmed via grep: zero references to `krb5` or `/v1/krb5/ticket` anywhere in `portal/src/` today.
- `portal/src/lib/x509Identity.ts` (136 lines, plain functions, no Vue/DOM, unit-testable in isolation) — `apiErrorDetail(err: APIError)` parses `err.body` as JSON and returns `.detail` if it's a string. `x509LinkErrorMessage(err: unknown): string` — `SessionExpiredError` → fixed reload message; `APIError` → prefer `apiErrorDetail`, else special-case 400/429/502; generic `Error` → `.message`; else a fixed fallback. Check whether `apiErrorDetail` is exported (reuse it from `krb5Identity.ts` if so, rather than duplicating).
- `portal/src/components/__tests__/X509IdentityCard.test.ts` (209 lines, Vitest + `@vue/test-utils`) — mocks `../../lib/api` at module level, configures per-test via `.mockResolvedValue`/`.mockRejectedValue`. Only 9 tests, all regression-focused on the two accordions' race conditions — **no existing test for the basic passphrase-submit/link/error flow** (krb5's card, having no accordions, needs its own coverage of exactly that flow, since there's no pre-existing bar to match — write it from scratch, thoroughly).
- `portal/src/pages/identities.astro` — thin wrapper (`Base` layout + `IdentitiesPage.vue` mounted `client:load`), nothing else to touch.
- Verification commands: `pixi run -e portal check` runs format-check + lint + astro-check + test together (the full portal CI gate); `pixi run -e portal test` runs just Vitest.
- Backend contract already shipped (PR #275, this same branch): `POST /v1/krb5/ticket` body `{username, password, target?, lifetime?, renewable_lifetime?}` → 201 `{target, principal, realm, expires_at, remaining_seconds, renew_until}` (no `ccache_b64`); errors 400 (bad username/password), 403 (account revoked/expired), 422 (malformed input), 429 (rate-limited, `Retry-After` forwarded), 502 (service unavailable) — see `broker/src/af_mcp_broker/api/credentials.py`'s `KrbTicketRequest`/`KrbTicketMetadata`/`create_krb5_ticket` and `docs/auth.md`'s `KrbTokenProvider` section for the authoritative shapes.

---

### Task 1: `lib/api.ts` — types and `requestKrb5Ticket()`

**Files:**
- Modify: `portal/src/lib/api.ts`
- Test: Modify `portal/src/lib/__tests__/api.test.ts` (find its existing `requestProxy`-equivalent test(s) and mirror them)

**Step 1: Write the failing test**

Read `portal/src/lib/__tests__/api.test.ts` in full first to find how it currently tests `requestProxy`/`fetchProxyStatus` (exact mocking approach for `fetch`/`apiFetch` — it may mock the global `fetch` directly rather than `api.ts` itself, since this IS `api.ts`). Add an equivalent test for the new function:

```ts
describe('requestKrb5Ticket', () => {
  it('POSTs username/password and returns ticket metadata', async () => {
    // mock fetch to return 201 with a KrbTicketMetadata-shaped body
    // assert the request body/method/path match, and the parsed return value
  });

  it('throws APIError on a non-2xx response', async () => {
    // mock fetch to return 400/403/422/429/502 and assert APIError is thrown
    // with the right status
  });
});
```

Match this file's exact existing test structure/mocking style — don't invent a new pattern.

**Step 2: Run to verify failure**

Run: `pixi run -e portal test -- api.test.ts` (or whatever exact invocation runs a single file in this repo's Vitest config — check `package.json`/`vitest.config`)
Expected: FAIL — `requestKrb5Ticket` is not exported yet.

**Step 3: Write the implementation**

In `portal/src/lib/api.ts`:

1. Extend the two literal unions:
   ```ts
   export type ProviderType = 'keycloak-brokered' | 'oauth21-direct' | 'krb5-token' | 'x509';
   export type LinkMechanism = 'redirect' | 'passphrase' | 'credential' | 'none';
   ```
   (Confirm exact current formatting/ordering before editing — insert `krb5-token`/`credential` in a sensible position, e.g. matching the backend's ordering where reasonable, but don't fight the file's existing convention if it differs.)

2. Add a response interface and the request function, positioned near the x509 equivalents:
   ```ts
   export interface KrbTicketMetadata {
     target: string;
     principal: string;
     realm: string;
     expires_at: string;
     remaining_seconds: number;
     renew_until: string | null;
   }

   export async function requestKrb5Ticket(
     username: string,
     password: string,
     target?: string,
     lifetime?: string,
     renewableLifetime?: string,
   ): Promise<KrbTicketMetadata> {
     return apiFetch('/krb5/ticket', {
       method: 'POST',
       body: JSON.stringify({
         username,
         password,
         target,
         lifetime,
         renewable_lifetime: renewableLifetime,
       }),
     });
   }
   ```
   Check whether `requestProxy` omits `undefined` optional fields from the JSON body or sends them as literal `undefined` (which `JSON.stringify` drops keys for automatically) — match whatever convention is actually used; the broker's `KrbTicketRequest` model already defaults all three optional fields to `None` server-side, so omitting them client-side is fine either way, but match existing style for consistency.

**Step 4: Run to verify pass**

Run the same test file; expect PASS.

**Step 5: Typecheck and commit**

```bash
pixi run -e portal astro-check
git add portal/src/lib/api.ts portal/src/lib/__tests__/api.test.ts
git commit -m "feat(portal): add krb5-token provider type and requestKrb5Ticket()"
```

---

### Task 2: `lib/krb5Identity.ts` — error-message helper

**Files:**
- Create: `portal/src/lib/krb5Identity.ts`
- Test: Create `portal/src/lib/__tests__/krb5Identity.test.ts`

**Step 1: Write the failing tests**

Read `portal/src/lib/x509Identity.ts` and `portal/src/lib/__tests__/x509Identity.test.ts` in full first (the `x509LinkErrorMessage`/`apiErrorDetail` functions and their existing tests are the exact template). Write krb5 equivalents:

```ts
import { describe, expect, it } from 'vitest';
import { APIError, SessionExpiredError } from '../api';
import { krb5LinkErrorMessage } from '../krb5Identity';

describe('krb5LinkErrorMessage', () => {
  it('returns a fixed message for SessionExpiredError', () => { /* ... */ });
  it('prefers the server detail when present on a 400', () => { /* ... */ });
  it('has a specific message for 400 (bad username/password)', () => { /* ... */ });
  it('has a specific message for 403 (account revoked/expired)', () => { /* ... */ });
  it('has a specific message for 422 (malformed input)', () => { /* ... */ });
  it('has a specific message for 429 (rate-limited)', () => { /* ... */ });
  it('has a specific message for 502 (service unavailable)', () => { /* ... */ });
  it('falls back to a generic message for other APIError statuses', () => { /* ... */ });
  it('uses .message for a plain Error', () => { /* ... */ });
  it('has a fixed fallback for a non-Error thrown value', () => { /* ... */ });
});
```

Match `x509Identity.test.ts`'s exact structure for constructing `APIError`/`SessionExpiredError` instances and asserting messages.

**Step 2: Run to verify failure**

Run the new test file; expect FAIL (module doesn't exist).

**Step 3: Write the implementation**

Mirror `x509Identity.ts`'s `apiErrorDetail`/`x509LinkErrorMessage` shape exactly, but for five status codes instead of three. First check whether `apiErrorDetail` is exported from `x509Identity.ts` — if so, import and reuse it directly (`import { apiErrorDetail } from './x509Identity'`) rather than duplicating it; if it's not exported, export it from `x509Identity.ts` (a one-line change, since it's a generic `APIError`-detail-parsing helper with nothing x509-specific in it) and import it from there. Do not paste a second copy of the same function.

```ts
export function krb5LinkErrorMessage(err: unknown): string {
  if (err instanceof SessionExpiredError) {
    return 'Your session expired — reload the page and try again.'; // match x509's exact wording convention
  }
  if (err instanceof APIError) {
    const detail = apiErrorDetail(err);
    if (detail) return detail;
    if (err.status === 400) return 'Incorrect CERN username or password.';
    if (err.status === 403) return 'This CERN account is revoked or its password has expired. Contact CERN account support.';
    if (err.status === 422) return 'The given username or ticket lifetime was invalid.';
    if (err.status === 429) return 'Too many attempts — wait a moment and try again.';
    if (err.status === 502) return 'The Kerberos ticket service is temporarily unavailable — retry later.';
    return `Request failed (${err.status}).`; // match x509's generic-APIError fallback wording exactly
  }
  if (err instanceof Error) return err.message;
  return 'Could not mint a Kerberos ticket.'; // match x509's fallback wording convention
}
```

Word the messages consistently with the broker's own fixed error text (see `Krb5TokenBadCredentialError`/`Krb5TokenAccountError`/`Krb5TokenInvalidRequestError`/`Krb5TokenRateLimitedError`/`Krb5TokenMintError` in `broker/src/af_mcp_broker/credentials/krb5_service.py`) — but note the broker's `detail` field, when present, always wins per `apiErrorDetail`, so these hardcoded strings are only the fallback when the response body couldn't be parsed.

**Step 4: Run to verify pass**

Run the test file; expect PASS.

**Step 5: Lint, typecheck, and commit**

```bash
pixi run -e portal lint
pixi run -e portal astro-check
git add portal/src/lib/krb5Identity.ts portal/src/lib/__tests__/krb5Identity.test.ts
# if x509Identity.ts's apiErrorDetail needed exporting:
git add portal/src/lib/x509Identity.ts
git commit -m "feat(portal): add krb5LinkErrorMessage error-message helper"
```

---

### Task 3: `components/Krb5IdentityCard.vue`

**Files:**
- Create: `portal/src/components/Krb5IdentityCard.vue`
- Test: Create `portal/src/components/__tests__/Krb5IdentityCard.test.ts`

**Step 1: Write the failing tests**

Read `X509IdentityCard.vue` and `X509IdentityCard.test.ts` in full first for the exact structural/testing template, then write tests covering (there is no pre-existing "submit flow" test to match a bar against — this is the first one, write it thoroughly):

- Renders "not linked" badge and a "Get Kerberos ticket" (or equivalent — see Step 3 for exact copy) button when `linked=false`.
- Renders "linked" badge and a "Refresh ticket" (or equivalent) button when `linked=true`.
- Clicking the button opens the form with `username`/`password` inputs, no checkbox.
- Submitting valid username/password calls `requestKrb5Ticket` with the right args, closes the form, emits `linked` with the returned metadata, and displays the metadata (principal/realm/expiry) transiently.
- The password field is cleared from component state immediately after submission (success or failure) — this is a security-sensitive assertion, mirror x509's "passphrase captured and cleared" test discipline exactly, even though x509's own test file doesn't happen to test this directly (check `x509Identity.ts`'s pattern/comments for the discipline being followed, and enforce it here with an explicit test).
- Each of the 5 error status codes (400/403/422/429/502) from a rejected `requestKrb5Ticket` call surfaces the corresponding message from `krb5LinkErrorMessage` in the form's error area, and does NOT close the form or emit `linked`.
- Cancel button closes the form and clears both fields without submitting.
- Submit button is disabled while busy and while either field is empty.

**Step 2: Run to verify failure**

Run the new test file; expect FAIL (component doesn't exist).

**Step 3: Write the implementation**

Mirror `X509IdentityCard.vue`'s structure closely, using a `.kc__*` class prefix (BEM-ish, matching `.xc__*`'s convention) and reusing the same shared CSS custom properties (`var(--color-af-*)`, fonts) rather than inventing new design tokens. Structural differences from x509:

- **No preflight or proxy-details accordions** — this component is just: icon/header/status badge → description → optional powers chips → action button → in-page form → (on success) a transient result summary block.
- **Two fields, not one**: `username` (text input) and `password` (password input), both required.
- **No "remember" checkbox** (explicitly deferred — see plan header). Add a hint line under the form noting the ticket is not remembered, e.g.: *"Your CERN password is used once to mint this ticket and is never stored — you'll need to re-enter it after the ticket expires."* (Word this to be accurate and not alarming — check it reads naturally next to the existing hint-text style in `X509IdentityCard.vue`.)
- **Button copy**: use wording that reflects "mint a ticket" rather than "link an identity," since this isn't a durable link the way x509's stored proxy is — e.g. `"Get Kerberos ticket"` when `!linked`, `"Refresh ticket"` when `linked`. Pick wording that reads naturally alongside the rest of the Identities page; this is a judgment call, not a hard requirement — the code review pass will catch anything confusing.
- **Password field discipline**: capture and clear `password.value` immediately before the `await`, exactly like `X509IdentityCard.vue`'s `handleSubmit` does for `passphrase.value` (read that function's comments — this is a security-sensitive pattern, copy it precisely, don't approximate it).
- **Success display**: on a successful mint, store the returned `KrbTicketMetadata` in local component state and render a small summary (principal, realm, expiry) below the header — this is NOT persisted anywhere and disappears on reload (per the plan's scope boundary); a subsequent visit just shows the plain `linked`/`not linked` badge from props.
- Props: `linked: boolean`, `display_name: string`, `enables: string`, `powers?: string[]` (drop `proxy_expires_at`/`x509_link_mode`, which don't apply).
- Emits: `linked(meta: KrbTicketMetadata)` only (no `revoked` — no revoke UI in this plan).
- Use `krb5LinkErrorMessage` (Task 2) for error display, `requestKrb5Ticket` (Task 1) for the API call.

**Step 4: Run to verify pass**

Run the test file; expect PASS.

**Step 5: Lint, typecheck, and commit**

```bash
pixi run -e portal lint
pixi run -e portal astro-check
git add portal/src/components/Krb5IdentityCard.vue portal/src/components/__tests__/Krb5IdentityCard.test.ts
git commit -m "feat(portal): add Krb5IdentityCard component"
```

---

### Task 4: Wire into `IdentitiesPage.vue`

**Files:**
- Modify: `portal/src/components/IdentitiesPage.vue`
- Test: Modify `portal/src/components/__tests__/IdentitiesPage.test.ts`

**Step 1: Write the failing test**

Read `IdentitiesPage.vue`'s full `v-if`/`v-else-if` card-selection chain and `IdentitiesPage.test.ts`'s existing per-mechanism rendering tests (it tests that the right card renders for `redirect`/`passphrase` rows via stable anchor ids — find the exact pattern). Add an equivalent test:

```ts
it('renders Krb5IdentityCard for a credential-mechanism provider', () => {
  // mount with a provider row: { link_mechanism: 'credential', type: 'krb5-token', ... }
  // assert Krb5IdentityCard is present (and IdentityLink/X509IdentityCard are not, for that row)
});
```

**Step 2: Run to verify failure**

Run the test file; expect FAIL (no `credential` branch exists yet, so it falls through to the generic `IdentityLink`, which the test should show is the WRONG component present).

**Step 3: Write the implementation**

In `IdentitiesPage.vue`:

1. Import `Krb5IdentityCard` and `requestKrb5Ticket`'s return type (`KrbTicketMetadata`) as needed.
2. Add a branch to the card-selection chain, positioned before the generic `else`:
   ```vue
   <Krb5IdentityCard
     v-else-if="p.link_mechanism === 'credential'"
     :linked="p.linked"
     :display_name="p.display_name"
     :enables="p.enables"
     :powers="powersForAlias(p.id)"
     @linked="(meta) => handleKrb5Linked(p.id, meta)"
   />
   ```
   (Confirm the real chain's exact `v-if`/`v-else-if`/`else` structure before editing — the summary above may not be verbatim; read the file directly.)
3. Add a `handleKrb5Linked(id: string, meta: KrbTicketMetadata)` function mirroring `handleX509Linked`'s shape: find the provider in the local `providers` ref by `id`, set `.linked = true`, call `clearIdentitiesCache()`. Krb5 has no `proxy_expires_at`/`x509_link_mode` fields to set.

**Step 4: Run to verify pass**

Run the test file; expect PASS.

**Step 5: Run the full portal suite, lint, typecheck, and commit**

```bash
pixi run -e portal check
git add portal/src/components/IdentitiesPage.vue portal/src/components/__tests__/IdentitiesPage.test.ts
git commit -m "feat(portal): wire Krb5IdentityCard into the Identities page"
```

---

### Task 5: Full verification pass

**Step 1: Run everything**

```bash
pixi run -e portal check
pixi run -e dev lint-all
pixi run --environment dev test
helm lint charts/af-mcp-platform
```

Expected: all green. (The broker/chart commands are re-run only to confirm this portal-only work didn't somehow disturb them — it shouldn't have touched any of those files.)

**Step 2: Manual smoke check (if a dev server is reasonably available)**

If `pixi run -e portal dev` can be started and a browser driven against it in this environment, visually confirm: the krb5-token row on the Identities page renders the new card, the form opens/closes, and a submission against a real or locally-stubbed broker round-trips (even a deliberate wrong-password 400 is a valid smoke check — the point is confirming the request actually reaches `/v1/krb5/ticket` and the error renders). If no krb5-token `identityProviders` entry is configured in the local dev broker, note that and skip this step rather than fabricating one — don't block on infrastructure this plan doesn't own.

**Step 3: Push the update and note it on the existing PR**

This work lands on the same branch/PR as the backend work (`krb5-token-provider-274` / PR #275) — issue #274's own text asked for "wiring up internals," and Giordon asked for the portal UI in the same session before merge, so it's the same unit of review rather than a second PR.

```bash
git -c url.https://github.com/.insteadOf=git@github.com: \
    -c credential.helper='!gh auth git-credential' \
    push origin krb5-token-provider-274
```

Then update the PR description (via `gh pr edit --body-file`, writing the new body to a scratch file first — a prior heredoc attempt in this same session corrupted a `gh pr create --body "$(cat <<'EOF' ...)"` call by executing backtick-quoted inline-code spans as real shell commands; always write PR bodies to a file and use `--body-file`, never a heredoc) to mention the new portal card, keeping the existing content intact.

---

## Execution notes for whoever runs this plan

- Task 1 has no dependencies. Tasks 2 and 3 each depend on Task 1 (the API function/types). Task 3 also depends on Task 2 (the error-message helper). Task 4 depends on Task 3. Task 5 is last.
- The "remember credentials" checkbox and any password/keytab persistence are explicitly out of scope — do not add them even if `X509IdentityCard.vue`'s pattern makes it tempting to mirror completely. A follow-up plan will cover this once krb5-token-service's keytab support ships.
- Several judgment calls are flagged inline (button copy, hint wording, exact test-file mocking conventions) — these are deliberately left to whoever implements, with the review pass as the actual quality gate, rather than over-specifying prose that a fresh read of the real files might contradict.
