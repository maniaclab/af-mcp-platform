<script setup lang="ts">
/**
 * X509IdentityCard.vue — the Identities page's card for the broker's
 * synthetic "x509" entry (link_mechanism: "passphrase").
 *
 * Unlike IdentityLink.vue's redirect flows, x509 links via an in-page
 * passphrase form that POSTs to /v1/x509/proxy — the same unlock endpoint
 * ProxyStatus.vue uses. In voms-token-service mode the broker stores the
 * passphrase in Vault (the link) and renews the proxy hands-free from then
 * on; "Re-link" re-runs the same flow to overwrite a stale link in place
 * (e.g. after a changed Globus password).
 *
 * CRITICAL SECURITY NOTE (same contract as ProxyStatus.vue): the passphrase
 * input is captured and cleared immediately before the API call, regardless
 * of success or failure. It is never stored anywhere beyond the controlled
 * ref() within this component's lifecycle.
 */
import { nextTick, ref } from 'vue';
import { requestProxy, type ProxyMetadata } from '../lib/api';
import { formatProxyExpiry, x509LinkErrorMessage } from '../lib/x509Identity';

const props = defineProps<{
  linked: boolean;
  display_name: string;
  enables: string;
  proxy_expires_at?: string | null;
}>();

const emit = defineEmits<{
  (e: 'linked', meta: ProxyMetadata): void;
}>();

// Form state — passphrase is ref('') and cleared immediately after use.
const formOpen = ref(false);
const passphrase = ref('');
const busy = ref(false);
const error = ref<string | null>(null);
const passphraseInput = ref<HTMLInputElement | null>(null);

async function openForm() {
  formOpen.value = true;
  error.value = null;
  await nextTick();
  passphraseInput.value?.focus();
}

function closeForm() {
  formOpen.value = false;
  passphrase.value = '';
  error.value = null;
}

async function handleSubmit() {
  if (!passphrase.value) return;

  busy.value = true;
  error.value = null;

  // Capture and immediately clear the passphrase from Vue state
  const captured = passphrase.value;
  passphrase.value = ''; // cleared before the await — regardless of outcome

  try {
    const meta = await requestProxy(captured);
    formOpen.value = false;
    emit('linked', meta);
  } catch (err) {
    // 400 = bad passphrase, 429 = unlock rate limit, 502 = service outage —
    // see x509LinkErrorMessage's contract notes.
    error.value = x509LinkErrorMessage(err);
  } finally {
    busy.value = false;
    // passphrase was already cleared above — this is belt-and-suspenders
    passphrase.value = '';
  }
}
</script>

<template>
  <div class="xc" :class="{ 'xc--linked': linked }">
    <!-- Provider icon + identity info — same layout grammar as IdentityLink -->
    <div class="xc__icon" aria-hidden="true">X</div>

    <div class="xc__body">
      <div class="xc__header">
        <span class="xc__name">{{ display_name }}</span>
        <span v-if="linked" class="xc__status xc__status--linked">linked</span>
        <span v-else class="xc__status xc__status--unlinked">not linked</span>
      </div>

      <p class="xc__desc">{{ enables }}</p>

      <p v-if="linked && formatProxyExpiry(props.proxy_expires_at)" class="xc__expiry">
        Proxy expires {{ formatProxyExpiry(props.proxy_expires_at) }}
      </p>
    </div>

    <!-- Action -->
    <div class="xc__actions">
      <button
        v-if="!formOpen && !linked"
        class="xc__btn xc__btn--link"
        :disabled="busy"
        @click="openForm"
      >
        Link certificate
      </button>

      <!-- Re-link re-runs the same passphrase flow, overwriting the stored
           link in place — the fix for a changed Globus password. Subdued
           styling, matching IdentityLink's Reconnect treatment. -->
      <button
        v-else-if="!formOpen && linked"
        class="xc__btn xc__btn--relink"
        :disabled="busy"
        @click="openForm"
      >
        Re-link
      </button>
    </div>

    <!-- Passphrase form — in-page, never a redirect: the broker needs the
         Globus passphrase once to mint (and, in service mode, store) the
         link. Spans the full card width below the header row. -->
    <form v-if="formOpen" class="xc__form" novalidate @submit.prevent="handleSubmit">
      <div class="xc__form-group">
        <label for="x509-link-passphrase" class="xc__form-label">
          Grid certificate passphrase
        </label>
        <input
          id="x509-link-passphrase"
          ref="passphraseInput"
          v-model="passphrase"
          type="password"
          class="xc__input"
          placeholder="Enter passphrase"
          autocomplete="current-password"
          :disabled="busy"
          required
          aria-required="true"
          aria-describedby="x509-link-passphrase-hint"
        />
        <span id="x509-link-passphrase-hint" class="xc__form-hint">
          Used once to generate the proxy — cleared immediately after submission.
        </span>
      </div>

      <div v-if="error" class="xc__error" role="alert">{{ error }}</div>

      <div class="xc__form-actions">
        <button type="button" class="xc__btn xc__btn--cancel" :disabled="busy" @click="closeForm">
          Cancel
        </button>
        <button
          type="submit"
          class="xc__btn xc__btn--submit"
          :disabled="busy || !passphrase"
          :aria-busy="busy"
        >
          {{ busy ? 'Linking…' : linked ? 'Re-link' : 'Link' }}
        </button>
      </div>
    </form>
  </div>
</template>

<style scoped>
.xc {
  display: grid;
  grid-template-columns: 2.5rem 1fr auto;
  gap: 1rem;
  align-items: start;
  padding: 1.25rem;
  border: 1px solid var(--color-af-border);
  border-radius: 4px;
  background: var(--color-af-surface);
  transition: border-color 150ms;
}

.xc--linked {
  border-color: rgb(from var(--color-af-teal) r g b / 0.2);
}

.xc__icon {
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

.xc--linked .xc__icon {
  background: rgb(from var(--color-af-teal) r g b / 0.08);
  border-color: rgb(from var(--color-af-teal) r g b / 0.25);
  color: var(--color-af-teal);
}

.xc__body {
  min-width: 0;
  display: flex;
  flex-direction: column;
  gap: 0.375rem;
}

.xc__header {
  display: flex;
  align-items: center;
  gap: 0.625rem;
}

.xc__name {
  font-family: 'IBM Plex Sans', system-ui, sans-serif;
  font-size: 0.9375rem;
  font-weight: 600;
  color: var(--color-af-text);
}

.xc__status {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.5625rem;
  font-weight: 600;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  padding: 0.125rem 0.375rem;
  border-radius: 2px;
}

.xc__status--linked {
  background: rgb(from var(--color-af-green) r g b / 0.12);
  color: var(--color-af-green);
  border: 1px solid rgb(from var(--color-af-green) r g b / 0.25);
}

.xc__status--unlinked {
  background: rgb(from var(--color-af-dim) r g b / 0.12);
  color: var(--color-af-dim);
  border: 1px solid rgb(from var(--color-af-dim) r g b / 0.25);
}

.xc__desc {
  font-size: 0.8125rem;
  color: var(--color-af-dim);
  margin: 0;
  line-height: 1.5;
}

.xc__expiry {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.6875rem;
  color: var(--color-af-teal);
  margin: 0;
}

.xc__actions {
  flex-shrink: 0;
  padding-top: 0.125rem;
  max-width: 18rem;
  text-align: right;
}

/* Same centering fix as IdentityLink's .il--linked .il__actions — the linked
   row's action button has a different natural height than the body column. */
.xc--linked .xc__actions {
  align-self: center;
}

/* Passphrase form — spans the full card width, below the header row. */
.xc__form {
  grid-column: 1 / -1;
  display: flex;
  flex-direction: column;
  gap: 1rem;
  max-width: 36rem;
  padding-top: 0.25rem;
}

.xc__form-group {
  display: flex;
  flex-direction: column;
  gap: 0.375rem;
}

.xc__form-label {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.6875rem;
  font-weight: 600;
  letter-spacing: 0.06em;
  text-transform: uppercase;
  color: var(--color-af-dim);
}

.xc__input {
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

.xc__input::placeholder {
  color: var(--color-af-label);
}
.xc__input:focus {
  outline: none;
  border-color: var(--color-af-teal);
  box-shadow: 0 0 0 2px rgb(from var(--color-af-teal) r g b / 0.15);
}
.xc__input:disabled {
  opacity: 0.5;
}

.xc__form-hint {
  font-size: 0.6875rem;
  color: var(--color-af-label);
}

.xc__error {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.75rem;
  color: var(--color-af-red);
  padding: 0.5rem 0.75rem;
  border: 1px solid rgb(from var(--color-af-red) r g b / 0.25);
  border-radius: 3px;
  background: rgb(from var(--color-af-red) r g b / 0.06);
}

.xc__form-actions {
  display: flex;
  gap: 0.75rem;
}

/* Buttons */
.xc__btn {
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
.xc__btn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}
.xc__btn:focus-visible {
  outline: 2px solid var(--color-af-teal);
  outline-offset: 2px;
}

.xc__btn--link,
.xc__btn--submit {
  background: rgb(from var(--color-af-teal) r g b / 0.1);
  color: var(--color-af-teal);
  border-color: rgb(from var(--color-af-teal) r g b / 0.3);
}
.xc__btn--link:not(:disabled):hover,
.xc__btn--submit:not(:disabled):hover {
  background: rgb(from var(--color-af-teal) r g b / 0.18);
  border-color: rgb(from var(--color-af-teal) r g b / 0.5);
}

/* Re-link: a maintenance action — same subdued treatment as IdentityLink's
   Reconnect (dashed border, smaller, quieter teal). */
.xc__btn--relink {
  background: transparent;
  color: var(--color-af-teal);
  border-style: dashed;
  border-color: rgb(from var(--color-af-teal) r g b / 0.35);
  font-size: 0.625rem;
  padding: 0.375rem 0.75rem;
}
.xc__btn--relink:not(:disabled):hover {
  background: rgb(from var(--color-af-teal) r g b / 0.08);
  border-color: rgb(from var(--color-af-teal) r g b / 0.5);
}

.xc__btn--cancel {
  background: transparent;
  color: var(--color-af-dim);
  border-color: var(--color-af-muted);
}
.xc__btn--cancel:not(:disabled):hover {
  color: var(--color-af-text);
  border-color: var(--color-af-dim);
}

@media (max-width: 640px) {
  .xc {
    grid-template-columns: 2rem 1fr;
    grid-template-rows: auto auto;
  }
  .xc__icon {
    width: 2rem;
    height: 2rem;
    font-size: 0.875rem;
  }
  .xc__actions {
    grid-column: 2;
    padding-top: 0;
  }
}
</style>
