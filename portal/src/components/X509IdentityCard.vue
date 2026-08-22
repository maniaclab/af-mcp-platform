<script setup lang="ts">
/**
 * X509IdentityCard.vue — the Identities page's card for an x509 entry
 * (link_mechanism: "passphrase"), and the single home for x509 credential
 * status since the /status/ page was retired: linking, custody consent,
 * the Grid Certificates preflight checklist, and VOMS proxy details all
 * live here.
 *
 * Unlike IdentityLink.vue's redirect flows, x509 links via an in-page
 * passphrase form that POSTs to /v1/x509/proxy. Custody is an explicit
 * choice (the "remember" checkbox): checked (default), the broker stores
 * the passphrase encrypted in the AF vault and renews the proxy hands-free;
 * unchecked, only the proxy is stored and the link lasts exactly its
 * validity window. "Re-link" re-runs the same flow to overwrite a stale
 * link in place (e.g. after a changed Globus password).
 *
 * The two accordions fetch on expand, not on page load — the checklist and
 * proxy details are diagnostics, not something every Identities visit
 * should pay a round trip for.
 *
 * CRITICAL SECURITY NOTE (same contract as before): the passphrase input is
 * captured and cleared immediately before the API call, regardless of
 * success or failure. It is never stored anywhere beyond the controlled
 * ref() within this component's lifecycle.
 */
import { nextTick, ref } from 'vue';
import {
  fetchProxyStatus,
  fetchX509Preflight,
  requestProxy,
  revokeProxy,
  type ProxyMetadata,
  type ProxyStatus,
  type X509Preflight,
} from '../lib/api';
import {
  formatProxyExpiry,
  preflightCheckLabel,
  x509LinkErrorMessage,
  x509LinkModeLabel,
  x509PreflightErrorMessage,
} from '../lib/x509Identity';

const props = defineProps<{
  linked: boolean;
  display_name: string;
  enables: string;
  /** Comma-joined display names of catalog backends this identity's credential powers, empty if none. */
  powers?: string;
  proxy_expires_at?: string | null;
  x509_link_mode?: 'auto-renew' | 'until-expiry' | null;
}>();

const emit = defineEmits<{
  (e: 'linked', meta: ProxyMetadata, remember: boolean): void;
  (e: 'revoked'): void;
}>();

// Form state — passphrase is ref('') and cleared immediately after use.
const formOpen = ref(false);
const passphrase = ref('');
const remember = ref(true);
const busy = ref(false);
const error = ref<string | null>(null);
const passphraseInput = ref<HTMLInputElement | null>(null);

// Grid Certificates preflight accordion — fetched on expand, never on load.
const preflightOpen = ref(false);
const preflight = ref<X509Preflight | null>(null);
const preflightLoading = ref(false);
const preflightError = ref<string | null>(null);

// VOMS proxy details accordion — fetched on expand, never on load.
const proxyOpen = ref(false);
const proxyStatus = ref<ProxyStatus | null>(null);
const proxyLoading = ref(false);
const proxyError = ref<string | null>(null);
// Two-step revoke confirmation (click "Revoke proxy", then "Confirm revoke").
const revokeArmed = ref(false);

async function openForm() {
  formOpen.value = true;
  remember.value = true;
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
    const meta = await requestProxy(captured, '12:00', 'atlas', remember.value);
    formOpen.value = false;
    proxyStatus.value = null; // stale — refetched on next expand
    emit('linked', meta, remember.value);
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

// Per-accordion toggle sequence numbers. Every toggle (either direction)
// bumps its counter, and a fetch may only apply its result while the
// counter still matches the value captured at that fetch's own expand —
// a response landing after a collapse (or after a newer expand) is
// discarded. Without this, a slow /v1/x509/proxy/status response landing
// right after a collapse click rewrote the chip at every toggle, one fetch
// behind the clicks — the deployed active/no-proxy ping-pong.
let preflightSeq = 0;
let proxySeq = 0;

async function togglePreflight() {
  preflightOpen.value = !preflightOpen.value;
  preflightSeq += 1;
  if (!preflightOpen.value) return;
  const seq = preflightSeq;
  preflightLoading.value = true;
  preflightError.value = null;
  try {
    const result = await fetchX509Preflight();
    if (seq !== preflightSeq) return; // collapsed or re-expanded since
    preflight.value = result;
  } catch (err) {
    if (seq !== preflightSeq) return;
    preflight.value = null;
    preflightError.value = x509PreflightErrorMessage(err);
  } finally {
    if (seq === preflightSeq) preflightLoading.value = false;
  }
}

async function toggleProxyDetails() {
  proxyOpen.value = !proxyOpen.value;
  revokeArmed.value = false;
  proxySeq += 1;
  if (!proxyOpen.value) return;
  const seq = proxySeq;
  proxyLoading.value = true;
  proxyError.value = null;
  try {
    const status = await fetchProxyStatus();
    if (seq !== proxySeq) return; // collapsed or re-expanded since
    proxyStatus.value = status;
  } catch (err) {
    if (seq !== proxySeq) return;
    proxyStatus.value = null;
    proxyError.value = err instanceof Error ? err.message : 'Could not load proxy status.';
  } finally {
    if (seq === proxySeq) proxyLoading.value = false;
  }
}

async function handleRevoke() {
  if (!revokeArmed.value) {
    revokeArmed.value = true;
    return;
  }
  busy.value = true;
  proxyError.value = null;
  try {
    await revokeProxy();
    revokeArmed.value = false;
    proxyStatus.value = { cached: false, voms_attributes: [] };
    emit('revoked');
  } catch (err) {
    proxyError.value = err instanceof Error ? err.message : 'Revoke failed.';
  } finally {
    busy.value = false;
  }
}

function formatRemaining(seconds?: number | null): string {
  if (seconds === undefined || seconds === null || seconds <= 0) return 'expired';
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  return h > 0 ? `${h}h ${m}m remaining` : `${m}m remaining`;
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
      <p v-if="powers" class="xc__powers"><span class="xc__powers-label">Powers:</span> {{ powers }}</p>

      <!-- Custody line: which mode the link is in. Falls back to the plain
           expiry line for a legacy-mode link, which has no custody concept. -->
      <p
        v-if="linked && x509LinkModeLabel(props.x509_link_mode, props.proxy_expires_at)"
        class="xc__expiry"
      >
        {{ x509LinkModeLabel(props.x509_link_mode, props.proxy_expires_at) }}
      </p>
      <p v-else-if="linked && formatProxyExpiry(props.proxy_expires_at)" class="xc__expiry">
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
         Globus passphrase once to mint the proxy (and, only with consent
         below, to store for renewal). Spans the full card width. -->
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
          Sent once to mint the proxy — cleared from this page immediately after submission.
        </span>
      </div>

      <!-- Custody consent: storing the passphrase is the user's explicit
           choice, defaulting to the hands-free-renewal behavior. -->
      <div class="xc__form-group">
        <label class="xc__consent">
          <input
            v-model="remember"
            type="checkbox"
            class="xc__checkbox"
            :disabled="busy"
            aria-describedby="x509-consent-hint"
          />
          <span>
            Remember my passphrase for automatic renewal (stored encrypted in the AF vault)
          </span>
        </label>
        <span v-if="!remember" id="x509-consent-hint" class="xc__form-hint xc__form-hint--consent">
          Your proxy will work for its validity window, then you'll re-link here.
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

    <!-- Grid Certificates preflight — is the ~/.globus credential in a state
         where minting could possibly work? Fetched on expand. -->
    <div class="xc__section">
      <button
        type="button"
        class="xc__section-toggle"
        :aria-expanded="preflightOpen"
        @click="togglePreflight"
      >
        <span class="xc__section-chevron" :class="{ 'xc__section-chevron--open': preflightOpen }"
          >&#9656;</span
        >
        <span>Grid Certificates</span>
        <span v-if="preflight?.ok" class="xc__chip xc__chip--ok">Mounted &#10003;</span>
        <span v-else-if="preflight" class="xc__chip xc__chip--warn">Problems found &#9888;</span>
      </button>

      <div v-if="preflightOpen" class="xc__section-body">
        <p v-if="preflightLoading" class="xc__section-note" aria-live="polite">
          Checking certificate files…
        </p>
        <div v-else-if="preflightError" class="xc__error" role="alert">{{ preflightError }}</div>
        <div v-else-if="preflight" class="xc__table-wrap">
          <table class="xc__table">
            <thead>
              <tr>
                <th>Check</th>
                <th>Path</th>
                <th>Exists</th>
                <th>Mode</th>
                <th>Readable</th>
              </tr>
            </thead>
            <tbody>
              <template v-for="check in preflight.checks" :key="check.name">
                <tr :class="{ 'xc__row--bad': !check.ok }">
                  <td>{{ preflightCheckLabel(check.name) }}</td>
                  <td>
                    <code class="xc__path">{{ check.path }}</code>
                  </td>
                  <td :class="check.exists ? 'xc__cell--ok' : 'xc__cell--bad'">
                    {{ check.exists ? '✓' : '✗' }}
                  </td>
                  <td>{{ check.mode ?? '—' }}</td>
                  <td
                    :class="
                      check.readable_by_service === undefined || check.readable_by_service === null
                        ? ''
                        : check.readable_by_service
                          ? 'xc__cell--ok'
                          : 'xc__cell--bad'
                    "
                  >
                    {{
                      check.readable_by_service === undefined || check.readable_by_service === null
                        ? '—'
                        : check.readable_by_service
                          ? '✓'
                          : '✗'
                    }}
                  </td>
                </tr>
                <!-- The actionable fix (e.g. the chmod 400 command) for a
                     failing check gets its own full-width row. -->
                <tr v-if="!check.ok && check.detail" class="xc__detail-row">
                  <td colspan="5">{{ check.detail }}</td>
                </tr>
              </template>
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- VOMS proxy details — DN, attributes, expiry, revoke. Only offered
         once linked; fetched on expand. -->
    <div v-if="linked" class="xc__section">
      <button
        type="button"
        class="xc__section-toggle"
        :aria-expanded="proxyOpen"
        @click="toggleProxyDetails"
      >
        <span class="xc__section-chevron" :class="{ 'xc__section-chevron--open': proxyOpen }"
          >&#9656;</span
        >
        <span>VOMS proxy details</span>
        <span v-if="proxyStatus?.cached" class="xc__chip xc__chip--ok">active</span>
        <span v-else-if="proxyStatus" class="xc__chip">no proxy</span>
      </button>

      <div v-if="proxyOpen" class="xc__section-body">
        <p v-if="proxyLoading" class="xc__section-note" aria-live="polite">
          Checking proxy status…
        </p>
        <div v-else-if="proxyError" class="xc__error" role="alert">{{ proxyError }}</div>
        <template v-else-if="proxyStatus">
          <div v-if="proxyStatus.cached" class="xc__proxy-grid">
            <div class="xc__field">
              <span class="xc__label">Subject DN</span>
              <code class="xc__path">{{ proxyStatus.dn ?? '—' }}</code>
            </div>
            <div class="xc__field">
              <span class="xc__label">Expires</span>
              <span class="xc__val">
                {{ formatProxyExpiry(proxyStatus.expires_at) ?? 'unknown' }}
                ({{ formatRemaining(proxyStatus.remaining_seconds) }})
              </span>
            </div>
            <div v-if="proxyStatus.nickname" class="xc__field">
              <span class="xc__label">CERN account</span>
              <code class="xc__path">{{ proxyStatus.nickname }}</code>
            </div>
            <div class="xc__field">
              <button
                type="button"
                class="xc__btn xc__btn--revoke"
                :class="{ 'xc__btn--revoke-armed': revokeArmed }"
                :disabled="busy"
                @click="handleRevoke"
              >
                {{ busy ? 'Revoking…' : revokeArmed ? 'Confirm revoke' : 'Revoke proxy' }}
              </button>
              <button
                v-if="revokeArmed && !busy"
                type="button"
                class="xc__btn xc__btn--cancel"
                @click="revokeArmed = false"
              >
                Cancel
              </button>
            </div>
          </div>
          <p v-else class="xc__section-note">
            No proxy is currently stored — link (or re-link) above to mint one.
          </p>
        </template>
      </div>
    </div>
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

.xc__powers {
  font-size: 0.75rem;
  color: var(--color-af-dim);
  margin: 0.375rem 0 0;
  line-height: 1.5;
}

.xc__powers-label {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.6875rem;
  font-weight: 600;
  letter-spacing: 0.04em;
  text-transform: uppercase;
  color: var(--color-af-label);
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

.xc__form-hint--consent {
  color: var(--color-af-amber);
}

/* Custody consent checkbox row */
.xc__consent {
  display: flex;
  align-items: baseline;
  gap: 0.5rem;
  font-size: 0.8125rem;
  color: var(--color-af-text);
  line-height: 1.5;
  cursor: pointer;
}

.xc__checkbox {
  flex-shrink: 0;
  accent-color: var(--color-af-teal);
  translate: 0 0.125rem;
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

/* Accordion sections (Grid Certificates, VOMS proxy details) */
.xc__section {
  grid-column: 1 / -1;
  border-top: 1px solid var(--color-af-border);
  padding-top: 0.625rem;
}

.xc__section-toggle {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  background: none;
  border: none;
  padding: 0.125rem 0;
  cursor: pointer;
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.6875rem;
  font-weight: 600;
  letter-spacing: 0.06em;
  text-transform: uppercase;
  color: var(--color-af-dim);
}
.xc__section-toggle:hover {
  color: var(--color-af-text);
}
.xc__section-toggle:focus-visible {
  outline: 2px solid var(--color-af-teal);
  outline-offset: 2px;
}

.xc__section-chevron {
  display: inline-block;
  transition: rotate 120ms;
}
.xc__section-chevron--open {
  rotate: 90deg;
}
@media (prefers-reduced-motion: reduce) {
  .xc__section-chevron {
    transition: none;
  }
}

.xc__chip {
  font-size: 0.5625rem;
  padding: 0.125rem 0.375rem;
  border-radius: 2px;
  border: 1px solid var(--color-af-muted);
  color: var(--color-af-dim);
  text-transform: none;
  letter-spacing: 0.04em;
}
.xc__chip--ok {
  background: rgb(from var(--color-af-green) r g b / 0.12);
  color: var(--color-af-green);
  border-color: rgb(from var(--color-af-green) r g b / 0.25);
}
.xc__chip--warn {
  background: rgb(from var(--color-af-amber) r g b / 0.12);
  color: var(--color-af-amber);
  border-color: rgb(from var(--color-af-amber) r g b / 0.3);
}

.xc__section-body {
  padding: 0.75rem 0 0.25rem;
}

.xc__section-note {
  font-size: 0.8125rem;
  color: var(--color-af-dim);
  margin: 0;
}

/* Preflight checklist table */
.xc__table-wrap {
  overflow-x: auto;
}

.xc__table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.75rem;
}

.xc__table th {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.5625rem;
  font-weight: 600;
  letter-spacing: 0.1em;
  text-transform: uppercase;
  color: var(--color-af-label);
  text-align: left;
  padding: 0.375rem 0.75rem 0.375rem 0;
  border-bottom: 1px solid var(--color-af-border);
}

.xc__table td {
  padding: 0.4375rem 0.75rem 0.4375rem 0;
  border-bottom: 1px solid rgb(from var(--color-af-border) r g b / 0.5);
  color: var(--color-af-text);
  vertical-align: baseline;
}

.xc__row--bad td {
  border-bottom: none;
}

.xc__detail-row td {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.6875rem;
  color: var(--color-af-amber);
  padding-top: 0;
}

.xc__cell--ok {
  color: var(--color-af-green);
}
.xc__cell--bad {
  color: var(--color-af-red);
  font-weight: 600;
}

.xc__path {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.6875rem;
  color: var(--color-af-dim);
  word-break: break-all;
}

/* Proxy details */
.xc__proxy-grid {
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
}

.xc__field {
  display: flex;
  flex-direction: column;
  gap: 0.3125rem;
}

.xc__field:last-child {
  flex-direction: row;
  gap: 0.75rem;
}

.xc__label {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.5625rem;
  font-weight: 600;
  letter-spacing: 0.1em;
  text-transform: uppercase;
  color: var(--color-af-dim);
}

.xc__val {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.75rem;
  color: var(--color-af-text);
}

.xc__voms-list {
  display: flex;
  flex-wrap: wrap;
  gap: 0.375rem;
}

.xc__voms-attr {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.6875rem;
  color: var(--color-af-teal);
  background: rgb(from var(--color-af-teal) r g b / 0.08);
  border: 1px solid rgb(from var(--color-af-teal) r g b / 0.18);
  padding: 0.1875rem 0.5rem;
  border-radius: 2px;
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

.xc__btn--revoke {
  background: transparent;
  color: var(--color-af-dim);
  border-color: var(--color-af-muted);
}
.xc__btn--revoke:not(:disabled):hover,
.xc__btn--revoke-armed {
  color: var(--color-af-red);
  border-color: rgb(from var(--color-af-red) r g b / 0.35);
  background: rgb(from var(--color-af-red) r g b / 0.06);
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
