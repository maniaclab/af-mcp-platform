<script setup lang="ts">
/**
 * ServiceXIdentityCard.vue — the Identities page's card for a servicex-token
 * entry (link_mechanism: "servicex-token").
 *
 * Deliberately NOT full OAuth automation: ServiceX's own token-minting
 * endpoint is gated by a Flask session cookie only ServiceX's own
 * /auth-callback can create, and the token it mints is only ever handed to
 * the user's own browser (a config-file download or a profile-page view),
 * never to a third party via redirect or API — so there is no way for this
 * card to obtain the token on the user's behalf. Instead this is "make the
 * manual step as easy as one click + paste": an external-link button (href
 * from the `external_login_url` prop, operator-configured to wherever the
 * ServiceX deployment mints/shows personal tokens) opens ServiceX's own
 * token page in a new tab, and a single paste field POSTs the copied value
 * to POST /v1/servicex/link (api.ts's linkServiceXToken), which the broker
 * verifies with one redeem before persisting anything.
 *
 * Simpler than X509IdentityCard.vue: no proxy-expiry/custody-mode concept
 * (a servicex-token link is always the hands-free-renewal shape, no
 * "until-expiry" alternative), no POSIX/preflight section. Closer to
 * Krb5IdentityCard.vue's single-secret-field shape, but with only one
 * action (there is no separate durable-keytab-equivalent upload) and no
 * hands-free-attempt-before-form flow (there is nothing to attempt without
 * a first link).
 *
 * CRITICAL SECURITY NOTE (same contract as X509IdentityCard.vue's
 * passphrase / Krb5IdentityCard.vue's password): the refresh-token input is
 * captured and cleared immediately before the API call, regardless of
 * success or failure. It is never stored anywhere beyond the controlled
 * ref() within this component's lifecycle.
 */
import { nextTick, ref } from 'vue';
import { linkServiceXToken, unlinkIdentity, type ServiceXTokenMetadata } from '../lib/api';
import { servicexLinkErrorMessage } from '../lib/servicexIdentity';
import { formatShortDateTime } from '../lib/x509Identity';

const props = defineProps<{
  id: string;
  linked: boolean;
  display_name: string;
  enables: string;
  /** Display names of catalog backends this identity's credential powers, empty/absent if none. */
  powers?: string[];
  /** URL of ServiceX's own token page, e.g.
   * "https://servicex.af.uchicago.edu/api-token" -- opened in a new tab.
   * The "Get your ServiceX token" button is hidden when this is null/absent
   * (an operator hasn't configured one). */
  external_login_url?: string | null;
}>();

const emit = defineEmits<{
  (e: 'linked', meta: ServiceXTokenMetadata): void;
  (e: 'revoked'): void;
}>();

// Form state — refreshToken is ref('') and cleared immediately after use.
const formOpen = ref(false);
const refreshToken = ref('');
const busy = ref(false);
const error = ref<string | null>(null);
const tokenInput = ref<HTMLInputElement | null>(null);

// Transient result of the last successful link — local state only, gone on
// reload, same treatment as Krb5IdentityCard.vue's `result`.
const result = ref<ServiceXTokenMetadata | null>(null);

// Two-step "Forget" confirmation, same inline armed-button pattern as
// X509IdentityCard.vue's proxy revoke / Krb5IdentityCard.vue's forget.
const forgetArmed = ref(false);
const forgetError = ref<string | null>(null);

function resetForgetState() {
  forgetArmed.value = false;
  forgetError.value = null;
}

async function openForm() {
  formOpen.value = true;
  error.value = null;
  resetForgetState();
  await nextTick();
  tokenInput.value?.focus();
}

function closeForm() {
  formOpen.value = false;
  refreshToken.value = '';
  error.value = null;
  resetForgetState();
}

async function handleSubmit() {
  if (!refreshToken.value) return;

  busy.value = true;
  error.value = null;

  // Capture and immediately clear the refresh token from Vue state
  const captured = refreshToken.value;
  refreshToken.value = ''; // cleared before the await — regardless of outcome

  try {
    const meta = await linkServiceXToken(captured);
    formOpen.value = false;
    result.value = meta;
    emit('linked', meta);
  } catch (err) {
    // 400 = bad refresh token, 502 = redeem service down — see
    // servicexLinkErrorMessage's contract notes.
    error.value = servicexLinkErrorMessage(err);
  } finally {
    busy.value = false;
    // refreshToken was already cleared above — this is belt-and-suspenders
    refreshToken.value = '';
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

/** Short human form of an ISO-8601 expiry, e.g. "Sep 4, 12:00 AM GMT". */
function formatExpiry(iso: string): string {
  return formatShortDateTime(new Date(iso));
}
</script>

<template>
  <div class="sc" :class="{ 'sc--linked': linked }">
    <!-- Provider icon + identity info — same layout grammar as X509IdentityCard -->
    <div class="sc__icon" aria-hidden="true">S</div>

    <div class="sc__body">
      <div class="sc__header">
        <span class="sc__name">{{ display_name }}</span>
        <span v-if="linked" class="sc__status sc__status--linked">linked</span>
        <span v-else class="sc__status sc__status--unlinked">not linked</span>
      </div>

      <p class="sc__desc">{{ enables }}</p>
      <div v-if="powers && powers.length" class="sc__powers">
        <span class="sc__powers-label">Powers</span>
        <span v-for="power in powers" :key="power" class="sc__power-chip">{{ power }}</span>
      </div>

      <!-- Transient link result — local state only, gone on reload. -->
      <div v-if="result" class="sc__result">
        <div class="sc__field">
          <span class="sc__label">Access token expires</span>
          <span class="sc__val">{{ formatExpiry(result.expires_at) }}</span>
        </div>
      </div>

      <div v-if="forgetError" class="sc__error" role="alert">{{ forgetError }}</div>
    </div>

    <!-- Action -->
    <div class="sc__actions">
      <a
        v-if="external_login_url"
        :href="external_login_url"
        target="_blank"
        rel="noopener"
        class="sc__btn sc__btn--external"
      >
        Get your ServiceX token ↗
      </a>

      <button
        v-if="!formOpen && !linked"
        class="sc__btn sc__btn--link"
        :disabled="busy"
        @click="openForm"
      >
        Link ServiceX token
      </button>

      <!-- Re-link overwrites the stored refresh token in place — the fix
           for a rotated/regenerated ServiceX token. Subdued styling,
           matching X509IdentityCard's Re-link treatment. -->
      <button
        v-else-if="!formOpen && linked"
        class="sc__btn sc__btn--relink"
        :disabled="busy"
        @click="openForm"
      >
        Re-link
      </button>

      <!-- "Forget" deletes the whole stored Vault record (refresh token and
           any cached access token) -- shown only once linked, with the same
           two-step confirm as X509IdentityCard.vue's proxy revoke /
           Krb5IdentityCard.vue's forget. -->
      <div v-if="!formOpen && linked" class="sc__forget-row">
        <button
          type="button"
          class="sc__btn sc__btn--forget"
          :class="{ 'sc__btn--forget-armed': forgetArmed }"
          :disabled="busy"
          @click="handleForget"
        >
          {{ forgetArmed ? (busy ? 'Forgetting…' : 'Confirm forget') : 'Forget this token' }}
        </button>
        <button
          v-if="forgetArmed && !busy"
          type="button"
          class="sc__btn sc__btn--cancel"
          @click="forgetArmed = false"
        >
          Cancel
        </button>
      </div>
    </div>

    <!-- Refresh-token paste form — in-page, never a redirect: there is no
         URL ServiceX could redirect the token back to (see the module doc
         comment). Spans the full card width. -->
    <form v-if="formOpen" class="sc__form" novalidate @submit.prevent="handleSubmit">
      <p class="sc__form-hint">
        Log in via the button above, generate or copy your personal ServiceX token from its page,
        then paste it below.
      </p>

      <div class="sc__form-group">
        <label for="servicex-link-token" class="sc__form-label"> ServiceX personal token </label>
        <input
          id="servicex-link-token"
          ref="tokenInput"
          v-model="refreshToken"
          type="password"
          class="sc__input"
          placeholder="Paste your ServiceX token"
          autocomplete="off"
          :disabled="busy"
          required
          aria-required="true"
          aria-describedby="servicex-link-token-hint"
        />
        <span id="servicex-link-token-hint" class="sc__form-hint">
          Verified with one redeem before it's stored — cleared from this page immediately after
          submission.
        </span>
      </div>

      <div v-if="error" class="sc__error" role="alert">{{ error }}</div>

      <div class="sc__form-actions">
        <button type="button" class="sc__btn sc__btn--cancel" :disabled="busy" @click="closeForm">
          Cancel
        </button>
        <button
          type="submit"
          class="sc__btn sc__btn--submit"
          :disabled="busy || !refreshToken"
          :aria-busy="busy"
        >
          {{ busy ? 'Linking…' : linked ? 'Re-link' : 'Link' }}
        </button>
      </div>
    </form>
  </div>
</template>

<style scoped>
.sc {
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

.sc--linked {
  border-color: rgb(from var(--color-af-teal) r g b / 0.2);
}

.sc__icon {
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

.sc--linked .sc__icon {
  background: rgb(from var(--color-af-teal) r g b / 0.08);
  border-color: rgb(from var(--color-af-teal) r g b / 0.25);
  color: var(--color-af-teal);
}

.sc__body {
  min-width: 0;
  display: flex;
  flex-direction: column;
  gap: 0.375rem;
}

.sc__header {
  display: flex;
  align-items: center;
  gap: 0.625rem;
}

.sc__name {
  font-family: 'IBM Plex Sans', system-ui, sans-serif;
  font-size: 0.9375rem;
  font-weight: 600;
  color: var(--color-af-text);
}

.sc__status {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.5625rem;
  font-weight: 600;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  padding: 0.125rem 0.375rem;
  border-radius: 2px;
}

.sc__status--linked {
  background: rgb(from var(--color-af-green) r g b / 0.16);
  color: color-mix(in srgb, var(--color-af-green) 70%, var(--color-af-dim));
  border: 1px solid rgb(from var(--color-af-green) r g b / 0.22);
}

.sc__status--unlinked {
  background: rgb(from var(--color-af-dim) r g b / 0.12);
  color: var(--color-af-dim);
  border: 1px solid rgb(from var(--color-af-dim) r g b / 0.25);
}

.sc__desc {
  font-size: 0.8125rem;
  color: var(--color-af-dim);
  margin: 0;
  line-height: 1.5;
}

.sc__powers {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 0.375rem;
  margin: 0.375rem 0 0;
}

.sc__powers-label {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.6875rem;
  font-weight: 600;
  letter-spacing: 0.04em;
  text-transform: uppercase;
  color: var(--color-af-label);
}

.sc__power-chip {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.6875rem;
  color: var(--color-af-teal);
  background: rgb(from var(--color-af-teal) r g b / 0.08);
  border: 1px solid rgb(from var(--color-af-teal) r g b / 0.18);
  padding: 0.1875rem 0.5rem;
  border-radius: 2px;
}

/* Transient link result — access-token expiry, local-state only. */
.sc__result {
  display: flex;
  flex-direction: column;
  gap: 0.375rem;
  margin-top: 0.25rem;
}

.sc__field {
  display: flex;
  align-items: baseline;
  gap: 0.5rem;
}

.sc__label {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.5625rem;
  font-weight: 600;
  letter-spacing: 0.1em;
  text-transform: uppercase;
  color: var(--color-af-dim);
  flex-shrink: 0;
}

.sc__val {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.75rem;
  color: var(--color-af-text);
}

/* Fixed min-width matching the .sc grid's third column, and left-aligned --
 * same reasoning as X509IdentityCard.vue's .xc__actions. */
.sc__actions {
  flex-shrink: 0;
  padding-top: 0.125rem;
  min-width: 8.5rem;
  text-align: left;
  display: flex;
  flex-direction: column;
  align-items: flex-start;
  gap: 0.375rem;
}

.sc--linked .sc__actions {
  align-self: center;
}

.sc__forget-row {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

/* Refresh-token paste form — spans the full card width, below the header row. */
.sc__form {
  grid-column: 1 / -1;
  display: flex;
  flex-direction: column;
  gap: 1rem;
  max-width: 36rem;
  padding-top: 0.25rem;
}

.sc__form-group {
  display: flex;
  flex-direction: column;
  gap: 0.375rem;
}

.sc__form-label {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.6875rem;
  font-weight: 600;
  letter-spacing: 0.06em;
  text-transform: uppercase;
  color: var(--color-af-dim);
}

.sc__input {
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

.sc__input::placeholder {
  color: var(--color-af-label);
}
.sc__input:focus {
  outline: none;
  border-color: var(--color-af-teal);
  box-shadow: 0 0 0 2px rgb(from var(--color-af-teal) r g b / 0.15);
}
.sc__input:disabled {
  opacity: 0.5;
}

.sc__form-hint {
  font-size: 0.6875rem;
  color: var(--color-af-label);
}

.sc__error {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.75rem;
  color: var(--color-af-red);
  padding: 0.5rem 0.75rem;
  border: 1px solid rgb(from var(--color-af-red) r g b / 0.25);
  border-radius: 3px;
  background: rgb(from var(--color-af-red) r g b / 0.06);
}

.sc__form-actions {
  display: flex;
  gap: 0.75rem;
}

/* Buttons */
.sc__btn {
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
  text-decoration: none;
  transition:
    background 120ms,
    color 120ms,
    border-color 120ms;
  white-space: nowrap;
}
.sc__btn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}
.sc__btn:focus-visible {
  outline: 2px solid var(--color-af-teal);
  outline-offset: 2px;
}

.sc__btn--link,
.sc__btn--submit {
  background: rgb(from var(--color-af-teal) r g b / 0.1);
  color: var(--color-af-teal);
  border-color: rgb(from var(--color-af-teal) r g b / 0.3);
}
.sc__btn--link:not(:disabled):hover,
.sc__btn--submit:not(:disabled):hover {
  background: rgb(from var(--color-af-teal) r g b / 0.18);
  border-color: rgb(from var(--color-af-teal) r g b / 0.5);
}

/* External link-out — visually distinct (not the primary teal action) so it
   reads as "go elsewhere first", matching a secondary/outline treatment. */
.sc__btn--external {
  background: transparent;
  color: var(--color-af-text);
  border-color: var(--color-af-muted);
}
.sc__btn--external:hover {
  border-color: var(--color-af-dim);
}

.sc__btn--relink,
.sc__btn--cancel {
  background: transparent;
  color: var(--color-af-dim);
  border-color: var(--color-af-muted);
}
.sc__btn--relink:not(:disabled):hover,
.sc__btn--cancel:not(:disabled):hover {
  color: var(--color-af-text);
  border-color: var(--color-af-dim);
}

/* Forget: a destructive action -- quiet by default, red on hover/armed,
   same treatment as X509IdentityCard.vue's .xc__btn--revoke. */
.sc__btn--forget {
  background: transparent;
  color: var(--color-af-dim);
  border-color: var(--color-af-muted);
  font-size: 0.625rem;
  padding: 0.375rem 0.75rem;
}
.sc__btn--forget:not(:disabled):hover,
.sc__btn--forget-armed {
  color: var(--color-af-red);
  border-color: rgb(from var(--color-af-red) r g b / 0.35);
  background: rgb(from var(--color-af-red) r g b / 0.06);
}

@media (max-width: 640px) {
  .sc {
    grid-template-columns: 2rem 1fr;
    grid-template-rows: auto auto;
  }
  .sc__icon {
    width: 2rem;
    height: 2rem;
    font-size: 0.875rem;
  }
  .sc__actions {
    grid-column: 2;
    padding-top: 0;
  }
}
</style>
