<script setup lang="ts">
/**
 * Krb5IdentityCard.vue — the Identities page's card for a krb5-token entry
 * (link_mechanism: "credential").
 *
 * Unlike X509IdentityCard.vue's stored-proxy link, minting a Kerberos ticket
 * has traditionally been a one-shot action, but krb5-token-service now
 * supports keytab-based renewal (docs/plans/2026-09-03-krb5-remember-keytab.md):
 * the "remember" checkbox below is the custody consent for that, mirroring
 * X509IdentityCard.vue's own consent checkbox but defaulting UNCHECKED
 * (opt-in) rather than x509's opt-out default — storing a keytab is a
 * bigger, less-familiar ask than storing a passphrase. The in-page form
 * POSTs the user's CERN username/password to /v1/krb5/ticket, and a
 * successful mint's metadata (principal/realm/expiry) is shown transiently
 * in local component state only — it is never persisted, and disappears on
 * reload, leaving just the plain linked/not-linked badge from props.
 *
 * Once linked, a "Forget this ticket" button calls the shared
 * unlinkIdentity() (already used by IdentityLink.vue) to delete the whole
 * Vault record — the stored keytab included, not just the current ticket.
 *
 * CRITICAL SECURITY NOTE (same contract as X509IdentityCard.vue's
 * passphrase): the password input is captured and cleared immediately
 * before the API call, regardless of success or failure. It is never stored
 * anywhere beyond the controlled ref() within this component's lifecycle.
 */
import { nextTick, ref } from 'vue';
import { requestKrb5Ticket, unlinkIdentity, type KrbTicketMetadata } from '../lib/api';
import { krb5LinkErrorMessage } from '../lib/krb5Identity';
import { formatShortDateTime } from '../lib/x509Identity';

const props = defineProps<{
  id: string;
  linked: boolean;
  display_name: string;
  enables: string;
  /** Display names of catalog backends this identity's credential powers, empty/absent if none. */
  powers?: string[];
}>();

const emit = defineEmits<{
  (e: 'linked', meta: KrbTicketMetadata): void;
  (e: 'revoked'): void;
}>();

// Form state — password is ref('') and cleared immediately after use.
const formOpen = ref(false);
const username = ref('');
const password = ref('');
// Custody consent — opt-in (unchecked by default), unlike x509's opt-out
// `remember` (see the module doc comment above).
const remember = ref(false);
const busy = ref(false);
const error = ref<string | null>(null);
const usernameInput = ref<HTMLInputElement | null>(null);

// Transient result of the last successful mint — local state only, never
// persisted, and gone on reload (see the module doc comment above).
const result = ref<KrbTicketMetadata | null>(null);

// Two-step "Forget" confirmation (click "Forget this ticket", then "Confirm
// forget") — same inline armed-button pattern as X509IdentityCard.vue's
// proxy revoke, chosen over IdentityLink.vue's heavier native-<dialog>
// confirm since this card has no existing dialog machinery to reuse, and
// deleting the stored keytab is a comparable-consequence destructive action
// (losing hands-free renewal, same as revoking a proxy) rather than a
// lighter one.
const forgetArmed = ref(false);
// Separate from `error` above -- that one only renders inside the
// username/password form, but forgetting can be triggered (and can fail)
// while the form is closed.
const forgetError = ref<string | null>(null);

async function openForm() {
  formOpen.value = true;
  remember.value = false;
  error.value = null;
  await nextTick();
  usernameInput.value?.focus();
}

function closeForm() {
  formOpen.value = false;
  username.value = '';
  password.value = '';
  error.value = null;
}

async function handleSubmit() {
  if (!username.value || !password.value) return;

  busy.value = true;
  error.value = null;

  // Capture and immediately clear the password from Vue state
  const capturedUsername = username.value;
  const capturedPassword = password.value;
  password.value = ''; // cleared before the await — regardless of outcome

  try {
    const meta = await requestKrb5Ticket(
      capturedUsername,
      capturedPassword,
      undefined,
      undefined,
      undefined,
      remember.value,
    );
    formOpen.value = false;
    result.value = meta;
    emit('linked', meta);
  } catch (err) {
    // 400 = bad username/password, 403 = revoked/expired account, 422 =
    // malformed input, 429 = rate limit, 502 = service outage — see
    // krb5LinkErrorMessage's contract notes.
    error.value = krb5LinkErrorMessage(err);
  } finally {
    busy.value = false;
    // password was already cleared above — this is belt-and-suspenders
    password.value = '';
  }
}

async function handleForget() {
  if (!forgetArmed.value) {
    forgetArmed.value = true;
    return;
  }
  busy.value = true;
  forgetError.value = null;
  try {
    await unlinkIdentity(props.id);
    forgetArmed.value = false;
    result.value = null;
    emit('revoked');
  } catch (err) {
    forgetError.value = err instanceof Error ? err.message : 'Forget failed. Try again.';
  } finally {
    busy.value = false;
  }
}

/**
 * Short human form of an ISO-8601 expiry, e.g. "Sep 4, 12:00 AM GMT" — mint
 * responses always carry a valid `expires_at`, so unlike
 * x509Identity.ts's formatProxyExpiry there is no null/unparseable case to
 * fall back on here.
 */
function formatExpiry(iso: string): string {
  return formatShortDateTime(new Date(iso));
}
</script>

<template>
  <div class="kc" :class="{ 'kc--linked': linked }">
    <!-- Provider icon + identity info — same layout grammar as X509IdentityCard -->
    <div class="kc__icon" aria-hidden="true">K</div>

    <div class="kc__body">
      <div class="kc__header">
        <span class="kc__name">{{ display_name }}</span>
        <span v-if="linked" class="kc__status kc__status--linked">linked</span>
        <span v-else class="kc__status kc__status--unlinked">not linked</span>
      </div>

      <p class="kc__desc">{{ enables }}</p>
      <div v-if="powers && powers.length" class="kc__powers">
        <span class="kc__powers-label">Powers</span>
        <span v-for="power in powers" :key="power" class="kc__power-chip">{{ power }}</span>
      </div>

      <!-- Transient mint result — local state only, gone on reload. -->
      <div v-if="result" class="kc__result">
        <div class="kc__field">
          <span class="kc__label">Principal</span>
          <code class="kc__path">{{ result.principal }}</code>
        </div>
        <div class="kc__field">
          <span class="kc__label">Realm</span>
          <code class="kc__path">{{ result.realm }}</code>
        </div>
        <div class="kc__field">
          <span class="kc__label">Expires</span>
          <span class="kc__val">{{ formatExpiry(result.expires_at) }}</span>
        </div>
      </div>

      <div v-if="forgetError" class="kc__error" role="alert">{{ forgetError }}</div>
    </div>

    <!-- Action -->
    <div class="kc__actions">
      <button v-if="!formOpen" class="kc__btn kc__btn--link" :disabled="busy" @click="openForm">
        {{ linked ? 'Refresh ticket' : 'Get Kerberos ticket' }}
      </button>

      <!-- "Forget" deletes the whole stored Vault record (any remembered
           keytab included, not just the current ticket) -- shown only once
           linked, with a two-step confirm mirroring X509IdentityCard.vue's
           proxy revoke. -->
      <div v-if="!formOpen && linked" class="kc__forget-row">
        <button
          type="button"
          class="kc__btn kc__btn--forget"
          :class="{ 'kc__btn--forget-armed': forgetArmed }"
          :disabled="busy"
          @click="handleForget"
        >
          {{ forgetArmed ? (busy ? 'Forgetting…' : 'Confirm forget') : 'Forget this ticket' }}
        </button>
        <button
          v-if="forgetArmed && !busy"
          type="button"
          class="kc__btn kc__btn--cancel"
          @click="forgetArmed = false"
        >
          Cancel
        </button>
      </div>
    </div>

    <!-- Username/password form — in-page, never a redirect: the broker needs
         the CERN password once to mint the ticket. Spans the full card
         width. -->
    <form v-if="formOpen" class="kc__form" novalidate @submit.prevent="handleSubmit">
      <div class="kc__form-group">
        <label for="krb5-link-username" class="kc__form-label"> CERN username </label>
        <input
          id="krb5-link-username"
          ref="usernameInput"
          v-model="username"
          type="text"
          class="kc__input"
          placeholder="Enter CERN username"
          autocomplete="username"
          :disabled="busy"
          required
          aria-required="true"
        />
      </div>

      <div class="kc__form-group">
        <label for="krb5-link-password" class="kc__form-label"> CERN password </label>
        <input
          id="krb5-link-password"
          v-model="password"
          type="password"
          class="kc__input"
          placeholder="Enter password"
          autocomplete="current-password"
          :disabled="busy"
          required
          aria-required="true"
          aria-describedby="krb5-link-password-hint"
        />
        <span id="krb5-link-password-hint" class="kc__form-hint">
          Your CERN password is used once to mint this ticket and is never stored — you'll need to
          re-enter it after the ticket expires, unless you remember this ticket below.
        </span>
      </div>

      <!-- Custody consent: storing a keytab is the user's explicit choice,
           defaulting to NOT stored (opt-in) -- unlike X509IdentityCard.vue's
           opt-out passphrase custody, since a keytab is a bigger,
           less-familiar ask than a stored passphrase (see the module doc
           comment above). -->
      <div class="kc__form-group">
        <label class="kc__consent">
          <input
            v-model="remember"
            type="checkbox"
            class="kc__checkbox"
            :disabled="busy"
            aria-describedby="krb5-consent-hint"
          />
          <span>Remember this ticket for automatic renewal</span>
        </label>
        <span id="krb5-consent-hint" class="kc__form-hint">
          Your password itself is never stored. Checking this stores a Kerberos keytab (not your
          password) encrypted in the AF vault, so future tickets can be minted or renewed without
          you re-entering a password.
        </span>
      </div>

      <div v-if="error" class="kc__error" role="alert">{{ error }}</div>

      <div class="kc__form-actions">
        <button type="button" class="kc__btn kc__btn--cancel" :disabled="busy" @click="closeForm">
          Cancel
        </button>
        <button
          type="submit"
          class="kc__btn kc__btn--submit"
          :disabled="busy || !username || !password"
          :aria-busy="busy"
        >
          {{ busy ? 'Minting…' : linked ? 'Refresh ticket' : 'Get ticket' }}
        </button>
      </div>
    </form>
  </div>
</template>

<style scoped>
.kc {
  display: grid;
  grid-template-columns: 2.5rem 1fr minmax(8.5rem, auto);
  gap: 1rem;
  align-items: start;
  padding: 1rem;
  border: 1px solid var(--color-af-border);
  border-radius: 4px;
  background: var(--color-af-surface);
  transition: border-color 150ms;
}

.kc--linked {
  border-color: rgb(from var(--color-af-teal) r g b / 0.2);
}

.kc__icon {
  width: 2.5rem;
  height: 2.5rem;
  border-radius: 4px;
  background: var(--color-af-border);
  border: 1px solid var(--color-af-muted);
  display: flex;
  align-items: center;
  justify-content: center;
  font-family: 'IBM Plex Mono', monospace;
  font-size: 1.125rem;
  font-weight: 700;
  color: var(--color-af-dim);
  flex-shrink: 0;
}

.kc--linked .kc__icon {
  background: rgb(from var(--color-af-teal) r g b / 0.08);
  border-color: rgb(from var(--color-af-teal) r g b / 0.25);
  color: var(--color-af-teal);
}

.kc__body {
  min-width: 0;
  display: flex;
  flex-direction: column;
  gap: 0.375rem;
}

.kc__header {
  display: flex;
  align-items: center;
  gap: 0.625rem;
}

.kc__name {
  font-family: 'IBM Plex Sans', system-ui, sans-serif;
  font-size: 0.9375rem;
  font-weight: 600;
  color: var(--color-af-text);
}

.kc__status {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.5625rem;
  font-weight: 600;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  padding: 0.125rem 0.375rem;
  border-radius: 2px;
}

.kc__status--linked {
  background: rgb(from var(--color-af-green) r g b / 0.16);
  color: color-mix(in srgb, var(--color-af-green) 70%, var(--color-af-dim));
  border: 1px solid rgb(from var(--color-af-green) r g b / 0.22);
}

.kc__status--unlinked {
  background: rgb(from var(--color-af-dim) r g b / 0.12);
  color: var(--color-af-dim);
  border: 1px solid rgb(from var(--color-af-dim) r g b / 0.25);
}

.kc__desc {
  font-size: 0.8125rem;
  color: var(--color-af-dim);
  margin: 0;
  line-height: 1.5;
}

.kc__powers {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 0.375rem;
  margin: 0.375rem 0 0;
}

.kc__powers-label {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.6875rem;
  font-weight: 600;
  letter-spacing: 0.04em;
  text-transform: uppercase;
  color: var(--color-af-label);
}

.kc__power-chip {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.6875rem;
  color: var(--color-af-teal);
  background: rgb(from var(--color-af-teal) r g b / 0.08);
  border: 1px solid rgb(from var(--color-af-teal) r g b / 0.18);
  padding: 0.1875rem 0.5rem;
  border-radius: 2px;
}

/* Transient mint result — principal/realm/expiry, local-state only. */
.kc__result {
  display: flex;
  flex-direction: column;
  gap: 0.375rem;
  margin-top: 0.25rem;
}

.kc__field {
  display: flex;
  align-items: baseline;
  gap: 0.5rem;
}

.kc__label {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.5625rem;
  font-weight: 600;
  letter-spacing: 0.1em;
  text-transform: uppercase;
  color: var(--color-af-dim);
  flex-shrink: 0;
}

.kc__val {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.75rem;
  color: var(--color-af-text);
}

.kc__path {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.6875rem;
  color: var(--color-af-dim);
  word-break: break-all;
}

/* Fixed min-width matching the .kc grid's third column, and left-aligned --
 * same reasoning as X509IdentityCard.vue's .xc__actions, so this card's
 * mint button lands at the same x position as every other identity card's
 * action column. */
.kc__actions {
  flex-shrink: 0;
  padding-top: 0.125rem;
  min-width: 8.5rem;
  text-align: left;
  display: flex;
  flex-direction: column;
  align-items: flex-start;
  gap: 0.375rem;
}

.kc--linked .kc__actions {
  align-self: center;
}

.kc__forget-row {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

/* Username/password form — spans the full card width, below the header row. */
.kc__form {
  grid-column: 1 / -1;
  display: flex;
  flex-direction: column;
  gap: 1rem;
  max-width: 36rem;
  padding-top: 0.25rem;
}

.kc__form-group {
  display: flex;
  flex-direction: column;
  gap: 0.375rem;
}

.kc__form-label {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.6875rem;
  font-weight: 600;
  letter-spacing: 0.06em;
  text-transform: uppercase;
  color: var(--color-af-dim);
}

.kc__input {
  background: var(--color-af-void);
  border: 1px solid var(--color-af-muted);
  border-radius: 3px;
  color: var(--color-af-text);
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.875rem;
  padding: 0.5rem 0.75rem;
  transition: border-color 150ms;
  width: 100%;
}

.kc__input::placeholder {
  color: var(--color-af-label);
}
.kc__input:focus {
  outline: none;
  border-color: var(--color-af-teal);
  box-shadow: 0 0 0 2px rgb(from var(--color-af-teal) r g b / 0.15);
}
.kc__input:disabled {
  opacity: 0.5;
}

.kc__form-hint {
  font-size: 0.6875rem;
  color: var(--color-af-label);
}

/* Custody consent checkbox row -- same treatment as
   X509IdentityCard.vue's .xc__consent/.xc__checkbox. */
.kc__consent {
  display: flex;
  align-items: baseline;
  gap: 0.5rem;
  font-size: 0.8125rem;
  color: var(--color-af-text);
  line-height: 1.5;
  cursor: pointer;
}

.kc__checkbox {
  flex-shrink: 0;
  accent-color: var(--color-af-teal);
  translate: 0 0.125rem;
}

.kc__error {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.75rem;
  color: var(--color-af-red);
  padding: 0.5rem 0.75rem;
  border: 1px solid rgb(from var(--color-af-red) r g b / 0.25);
  border-radius: 3px;
  background: rgb(from var(--color-af-red) r g b / 0.06);
}

.kc__form-actions {
  display: flex;
  gap: 0.75rem;
}

/* Buttons */
.kc__btn {
  display: inline-flex;
  align-items: center;
  padding: 0.4375rem 0.875rem;
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.6875rem;
  font-weight: 600;
  letter-spacing: 0.06em;
  text-transform: uppercase;
  border-radius: 3px;
  border: 1px solid;
  cursor: pointer;
  transition:
    background 120ms,
    color 120ms,
    border-color 120ms;
  white-space: nowrap;
}
.kc__btn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}
.kc__btn:focus-visible {
  outline: 2px solid var(--color-af-teal);
  outline-offset: 2px;
}

.kc__btn--link,
.kc__btn--submit {
  background: rgb(from var(--color-af-teal) r g b / 0.1);
  color: var(--color-af-teal);
  border-color: rgb(from var(--color-af-teal) r g b / 0.3);
}
.kc__btn--link:not(:disabled):hover,
.kc__btn--submit:not(:disabled):hover {
  background: rgb(from var(--color-af-teal) r g b / 0.18);
  border-color: rgb(from var(--color-af-teal) r g b / 0.5);
}

.kc__btn--cancel {
  background: transparent;
  color: var(--color-af-dim);
  border-color: var(--color-af-muted);
}
.kc__btn--cancel:not(:disabled):hover {
  color: var(--color-af-text);
  border-color: var(--color-af-dim);
}

/* Forget: a destructive action -- quiet by default, red on hover/armed,
   same treatment as X509IdentityCard.vue's .xc__btn--revoke. */
.kc__btn--forget {
  background: transparent;
  color: var(--color-af-dim);
  border-color: var(--color-af-muted);
  font-size: 0.625rem;
  padding: 0.375rem 0.75rem;
}
.kc__btn--forget:not(:disabled):hover,
.kc__btn--forget-armed {
  color: var(--color-af-red);
  border-color: rgb(from var(--color-af-red) r g b / 0.35);
  background: rgb(from var(--color-af-red) r g b / 0.06);
}

@media (max-width: 640px) {
  .kc {
    grid-template-columns: 2rem 1fr;
    grid-template-rows: auto auto;
  }
  .kc__icon {
    width: 2rem;
    height: 2rem;
    font-size: 0.875rem;
  }
  .kc__actions {
    grid-column: 2;
    padding-top: 0;
  }
}
</style>
