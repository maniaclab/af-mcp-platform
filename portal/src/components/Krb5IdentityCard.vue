<script setup lang="ts">
/**
 * Krb5IdentityCard.vue — the Identities page's card for a krb5-token entry
 * (link_mechanism: "credential").
 *
 * Two separate, mutually exclusive actions live in this card, gated by
 * their own `formOpen`/`keytabFormOpen` refs (opening one closes the
 * other):
 *
 * - "Get Kerberos ticket" / "Refresh ticket" — a one-shot mint. The in-page
 *   form POSTs the user's CERN username/password to POST /v1/krb5/ticket.
 *   No custody: the broker uses the password once and never stores it, and
 *   nothing here establishes a durable renewal link.
 * - "Link a keytab" — a durable link. The user generates a keytab
 *   themselves (on lxplus, per the in-form instructions — the broker cannot
 *   generate one itself, see krb5.py's module docstring for why) and
 *   uploads it via POST /v1/krb5/keytab. The broker validates the keytab by
 *   minting a ticket with it (mirroring krb5-token-service's tier-4
 *   remint) before persisting it; a keytab that doesn't authenticate is
 *   rejected with nothing stored.
 *
 * Both routes return the same `KrbTicketMetadata` shape, so a successful
 * call from either form shares the same transient result rendering below
 * (principal/realm/expiry) — shown in local component state only, never
 * persisted, and gone on reload, leaving just the plain linked/not-linked
 * badge from props.
 *
 * Once linked, a "Forget this ticket" button calls the shared
 * unlinkIdentity() (already used by IdentityLink.vue) to delete the whole
 * Vault record — the stored keytab included, not just the current ticket.
 *
 * CRITICAL SECURITY NOTE (same contract as X509IdentityCard.vue's
 * passphrase): the password input is captured and cleared immediately
 * before the API call, regardless of success or failure. It is never stored
 * anywhere beyond the controlled ref() within this component's lifecycle.
 * The keytab file's contents pass through this component only as a
 * transient base64 string built for the one POST body — also never
 * persisted client-side.
 */
import { nextTick, ref } from 'vue';
import {
  linkKrb5Keytab,
  requestKrb5Ticket,
  unlinkIdentity,
  type KrbTicketMetadata,
} from '../lib/api';
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
const busy = ref(false);
const error = ref<string | null>(null);
const usernameInput = ref<HTMLInputElement | null>(null);

// Keytab-upload form state — separate from the password-mint form above,
// and mutually exclusive with it (see openForm()/openKeytabForm()).
const keytabFormOpen = ref(false);
const keytabUsername = ref('');
const keytabFile = ref<File | null>(null);
const keytabBusy = ref(false);
const keytabError = ref<string | null>(null);
const keytabUsernameInput = ref<HTMLInputElement | null>(null);
const keytabFileInput = ref<HTMLInputElement | null>(null);

// Transient result of the last successful mint (either form) — local state
// only, never persisted, and gone on reload (see the module doc comment
// above).
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

// Reset the two-step forget confirmation and any stale forget error whenever
// the mint form's visibility changes -- the forget row is hidden while the
// form is open (`v-if="!formOpen && linked"`), so without this an armed
// confirmation (or a leftover failure alert) survives invisibly and
// reappears pre-armed/stale once the form closes again.
function resetForgetState() {
  forgetArmed.value = false;
  forgetError.value = null;
}

async function openForm() {
  formOpen.value = true;
  closeKeytabForm();
  error.value = null;
  resetForgetState();
  await nextTick();
  usernameInput.value?.focus();
}

function closeForm() {
  formOpen.value = false;
  username.value = '';
  password.value = '';
  error.value = null;
  resetForgetState();
}

async function openKeytabForm() {
  keytabFormOpen.value = true;
  closeForm();
  keytabError.value = null;
  resetForgetState();
  await nextTick();
  keytabUsernameInput.value?.focus();
}

function closeKeytabForm() {
  keytabFormOpen.value = false;
  keytabUsername.value = '';
  keytabFile.value = null;
  if (keytabFileInput.value) keytabFileInput.value.value = '';
  keytabError.value = null;
  resetForgetState();
}

/** Reads a File as a base64 string — a keytab is a small binary file, a few KB at most. */
function fileToBase64(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      // readAsDataURL yields "data:<mime>;base64,<data>" — keep only the payload.
      const dataUrl = reader.result as string;
      resolve(dataUrl.slice(dataUrl.indexOf(',') + 1));
    };
    reader.onerror = () => reject(reader.error ?? new Error('Failed to read the keytab file.'));
    reader.readAsDataURL(file);
  });
}

function handleKeytabFileChange(event: Event) {
  const input = event.target as HTMLInputElement;
  keytabFile.value = input.files?.[0] ?? null;
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

async function handleKeytabSubmit() {
  if (!keytabUsername.value || !keytabFile.value) return;

  keytabBusy.value = true;
  keytabError.value = null;

  try {
    const keytabB64 = await fileToBase64(keytabFile.value);
    const meta = await linkKrb5Keytab(keytabUsername.value, keytabB64);
    keytabFormOpen.value = false;
    result.value = meta;
    emit('linked', meta);
  } catch (err) {
    // Same status-code contract as the password form's handleSubmit — see
    // krb5LinkErrorMessage's contract notes (shared between both routes).
    keytabError.value = krb5LinkErrorMessage(err);
  } finally {
    keytabBusy.value = false;
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

      <!-- Separate action from the one-shot mint above: uploads a
           user-generated keytab so the broker can renew the ticket
           hands-free -- see the module doc comment for the design split.
           Visible whenever its own form isn't already open (independent of
           `formOpen`), so it can be clicked directly to switch away from an
           open password form -- openKeytabForm() then closes that form. -->
      <button
        v-if="!keytabFormOpen"
        type="button"
        class="kc__btn kc__btn--keytab"
        :disabled="keytabBusy"
        @click="openKeytabForm"
      >
        Link a keytab
      </button>

      <!-- "Forget" deletes the whole stored Vault record (any linked
           keytab included, not just the current ticket) -- shown only once
           linked, with a two-step confirm mirroring X509IdentityCard.vue's
           proxy revoke. -->
      <div v-if="!formOpen && !keytabFormOpen && linked" class="kc__forget-row">
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
          re-enter it after the ticket expires.
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

    <!-- Keytab-upload form -- a separate action from the password-mint form
         above, never shown at the same time (see openForm()/
         openKeytabForm()'s mutual exclusion). Spans the full card width. -->
    <form v-if="keytabFormOpen" class="kc__form" novalidate @submit.prevent="handleKeytabSubmit">
      <p class="kc__form-hint">
        Generate a keytab on lxplus, then upload it here so the broker can renew your Kerberos
        ticket automatically without asking for your password again:
      </p>
      <pre class="kc__keytab-steps"><code>ssh &lt;username&gt;@lxplus.cern.ch
cern-get-keytab --keytab &lt;username&gt;.keytab --user
# (enter your CERN password when prompted)
kinit -kt &lt;username&gt;.keytab &lt;username&gt;@CERN.CH   # verify it works
echo $?                                          # should print 0</code></pre>
      <p class="kc__form-hint">
        Then download <code>&lt;username&gt;.keytab</code> from lxplus (e.g.
        <code>scp &lt;username&gt;@lxplus.cern.ch:&lt;username&gt;.keytab .</code>) and upload it
        below.
      </p>

      <div class="kc__form-group">
        <label for="krb5-keytab-username" class="kc__form-label"> CERN username </label>
        <input
          id="krb5-keytab-username"
          ref="keytabUsernameInput"
          v-model="keytabUsername"
          type="text"
          class="kc__input"
          placeholder="Enter CERN username"
          autocomplete="username"
          :disabled="keytabBusy"
          required
          aria-required="true"
        />
      </div>

      <div class="kc__form-group">
        <label for="krb5-keytab-file" class="kc__form-label"> Keytab file </label>
        <input
          id="krb5-keytab-file"
          ref="keytabFileInput"
          type="file"
          class="kc__input"
          :disabled="keytabBusy"
          required
          aria-required="true"
          @change="handleKeytabFileChange"
        />
      </div>

      <div v-if="keytabError" class="kc__error" role="alert">{{ keytabError }}</div>

      <div class="kc__form-actions">
        <button
          type="button"
          class="kc__btn kc__btn--cancel"
          :disabled="keytabBusy"
          @click="closeKeytabForm"
        >
          Cancel
        </button>
        <button
          type="submit"
          class="kc__btn kc__btn--submit"
          :disabled="keytabBusy || !keytabUsername || !keytabFile"
          :aria-busy="keytabBusy"
        >
          {{ keytabBusy ? 'Linking…' : 'Link keytab' }}
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

/* lxplus keytab-generation steps, reproduced verbatim in the keytab-upload form. */
.kc__keytab-steps {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.75rem;
  line-height: 1.6;
  color: var(--color-af-text);
  background: var(--color-af-void);
  border: 1px solid var(--color-af-muted);
  border-radius: 3px;
  padding: 0.625rem 0.75rem;
  margin: 0;
  overflow-x: auto;
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

.kc__btn--cancel,
.kc__btn--keytab {
  background: transparent;
  color: var(--color-af-dim);
  border-color: var(--color-af-muted);
}
.kc__btn--cancel:not(:disabled):hover,
.kc__btn--keytab:not(:disabled):hover {
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
