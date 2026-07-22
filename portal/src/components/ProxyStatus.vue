<script setup lang="ts">
/**
 * ProxyStatus.vue — x509 proxy unlock form and active proxy display.
 *
 * CRITICAL SECURITY NOTE: The passphrase input is always cleared immediately
 * after the API call, regardless of success or failure. It is never stored
 * anywhere beyond the controlled ref() within this component's lifecycle.
 */
import { ref, computed, nextTick } from 'vue';
import { requestProxy, revokeProxy } from '../lib/api';
import type { ProxyStatus } from '../lib/api';

const props = defineProps<{
  status: ProxyStatus;
}>();

const emit = defineEmits<{
  (e: 'unlocked', status: ProxyStatus): void;
  (e: 'revoked'): void;
}>();

// Form state — passphrase is ref('') and cleared immediately after use.
// `valid` is an "HH:MM" lifetime; `voms` is a VO name with no leading slash.
const passphrase = ref('');
const validDuration = ref<'04:00' | '08:00' | '12:00'>('12:00');
const vomsRole = ref('atlas');
const busy = ref(false);
const error = ref<string | null>(null);

// Revoke-confirm dialog uses the native <dialog> element (showModal()), which
// gives us a real focus trap, ESC to close, and inert siblings for free. We
// only need to remember the trigger so focus can return to it on close.
const revokeDialog = ref<HTMLDialogElement | null>(null);
const revokeTrigger = ref<HTMLButtonElement | null>(null);
const cancelBtn = ref<HTMLButtonElement | null>(null);

async function openRevokeConfirm(evt: Event) {
  revokeTrigger.value = evt.currentTarget as HTMLButtonElement;
  await nextTick();
  revokeDialog.value?.showModal();
  // Move focus off the destructive "Revoke" button — start on Cancel.
  cancelBtn.value?.focus();
}

function closeRevokeConfirm() {
  revokeDialog.value?.close();
}

// Native <dialog> fires `close` whether it was closed by ESC, form method="dialog",
// or an explicit .close() call — this is our single place to restore focus.
function onRevokeDialogClose() {
  revokeTrigger.value?.focus();
  revokeTrigger.value = null;
}

async function handleUnlock(evt: Event) {
  evt.preventDefault();
  if (!passphrase.value) return;

  busy.value = true;
  error.value = null;

  // Capture and immediately clear the passphrase from Vue state
  const captured = passphrase.value;
  passphrase.value = ''; // cleared before the await — regardless of outcome

  try {
    const meta = await requestProxy(captured, validDuration.value, vomsRole.value);
    // Use the server's remaining_seconds directly — no client recomputation.
    emit('unlocked', {
      cached: true,
      dn: meta.dn,
      expires_at: meta.expires_at,
      voms_attributes: meta.voms_attributes,
      remaining_seconds: meta.remaining_seconds,
    });
  } catch (err) {
    error.value =
      err instanceof Error
        ? err.message
        : 'Proxy request failed. Check your passphrase and try again.';
  } finally {
    busy.value = false;
    // passphrase was already cleared above — this is belt-and-suspenders
    passphrase.value = '';
  }
}

async function handleRevoke() {
  closeRevokeConfirm();
  busy.value = true;
  error.value = null;
  try {
    await revokeProxy();
    emit('revoked');
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Revoke failed.';
  } finally {
    busy.value = false;
  }
}

function formatExpiry(iso?: string): string {
  if (!iso) return 'unknown';
  return new Date(iso).toLocaleString('en-US', {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    timeZoneName: 'short',
  });
}

function formatRemaining(seconds?: number): string {
  if (seconds === undefined || seconds <= 0) return 'expired';
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  return h > 0 ? `${h}h ${m}m remaining` : `${m}m remaining`;
}

const remainingClass = computed(() => {
  const s = props.status.remaining_seconds ?? 0;
  if (s <= 0) return 'expired';
  if (s < 3600) return 'critical'; // < 1h
  if (s < 21600) return 'warn'; // < 6h
  return 'ok';
});
</script>

<template>
  <!-- ── Active proxy view ─────────────────────────────────────────── -->
  <div v-if="status.cached" class="ps">
    <div class="ps__status-bar">
      <span class="ps__indicator ps__indicator--active" aria-label="Proxy active"></span>
      <span class="ps__status-text">AMI proxy active</span>
      <span class="ps__remaining" :class="`ps__remaining--${remainingClass}`">
        {{ formatRemaining(status.remaining_seconds) }}
      </span>
    </div>

    <div class="ps__grid">
      <div class="ps__field">
        <span class="ps__label">Subject DN</span>
        <code class="ps__dn">{{ status.dn ?? '—' }}</code>
      </div>

      <div class="ps__field">
        <span class="ps__label">Expires</span>
        <span class="ps__val">{{ formatExpiry(status.expires_at) }}</span>
      </div>

      <div
        v-if="status.voms_attributes && status.voms_attributes.length > 0"
        class="ps__field ps__field--full"
      >
        <span class="ps__label">VOMS attributes</span>
        <div class="ps__voms-list">
          <code v-for="attr in status.voms_attributes" :key="attr" class="ps__voms-attr">{{
            attr
          }}</code>
        </div>
      </div>
    </div>

    <div v-if="error" class="ps__error" role="alert">{{ error }}</div>

    <div class="ps__actions">
      <button class="ps__btn ps__btn--revoke" :disabled="busy" @click="openRevokeConfirm">
        Revoke proxy
      </button>
    </div>

    <!--
      Native <dialog> gives us a real focus trap (TAB cycles inside), ESC to
      close, and inert siblings, all handled by the platform. We restore focus
      to the trigger button in onRevokeDialogClose.
    -->
    <dialog
      ref="revokeDialog"
      class="ps__modal"
      aria-labelledby="ps-revoke-title"
      @close="onRevokeDialogClose"
    >
      <h2 id="ps-revoke-title" class="ps__modal-title">Revoke proxy?</h2>
      <p class="ps__modal-body">
        This immediately invalidates the grid proxy. Any running jobs using this credential may
        fail. You can unlock a new proxy at any time.
      </p>
      <div class="ps__modal-actions">
        <button
          ref="cancelBtn"
          type="button"
          class="ps__btn ps__btn--cancel"
          @click="closeRevokeConfirm"
        >
          Cancel
        </button>
        <button
          type="button"
          class="ps__btn ps__btn--confirm-revoke"
          :disabled="busy"
          @click="handleRevoke"
        >
          {{ busy ? 'Revoking…' : 'Revoke' }}
        </button>
      </div>
    </dialog>
  </div>

  <!-- ── No proxy — unlock form ────────────────────────────────────── -->
  <div v-else class="ps">
    <div class="ps__status-bar">
      <span class="ps__indicator ps__indicator--inactive" aria-label="No proxy"></span>
      <span class="ps__status-text ps__status-text--inactive">No active proxy</span>
    </div>

    <p class="ps__help">
      Enter your grid certificate passphrase to generate a VOMS proxy. The passphrase is used once
      and never stored.
    </p>

    <form class="ps__form" @submit.prevent="handleUnlock" novalidate>
      <div class="ps__form-group">
        <label for="proxy-passphrase" class="ps__form-label"> Grid certificate passphrase </label>
        <input
          id="proxy-passphrase"
          v-model="passphrase"
          type="password"
          class="ps__input"
          placeholder="Enter passphrase"
          autocomplete="current-password"
          :disabled="busy"
          required
          aria-required="true"
          aria-describedby="passphrase-hint"
        />
        <span id="passphrase-hint" class="ps__form-hint">
          Used once to generate the proxy — cleared immediately after submission.
        </span>
      </div>

      <div class="ps__form-row">
        <div class="ps__form-group ps__form-group--inline">
          <label for="proxy-valid" class="ps__form-label">Valid for</label>
          <select id="proxy-valid" v-model="validDuration" class="ps__select" :disabled="busy">
            <option value="04:00">4 hours</option>
            <option value="08:00">8 hours</option>
            <option value="12:00">12 hours</option>
          </select>
        </div>

        <div class="ps__form-group ps__form-group--inline">
          <label for="proxy-voms" class="ps__form-label">VOMS</label>
          <select id="proxy-voms" v-model="vomsRole" class="ps__select" :disabled="busy">
            <option value="atlas">atlas</option>
          </select>
        </div>
      </div>

      <div v-if="error" class="ps__error" role="alert">{{ error }}</div>

      <button
        type="submit"
        class="ps__btn ps__btn--unlock"
        :disabled="busy || !passphrase"
        :aria-busy="busy"
      >
        {{ busy ? 'Generating proxy…' : 'Unlock AMI access' }}
      </button>
    </form>
  </div>
</template>

<style scoped>
.ps {
  display: flex;
  flex-direction: column;
  gap: 1.25rem;
}

/* Status bar */
.ps__status-bar {
  display: flex;
  align-items: center;
  gap: 0.625rem;
}

.ps__indicator {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  flex-shrink: 0;
}

.ps__indicator--active {
  background: var(--color-af-green);
  box-shadow: 0 0 6px rgb(from var(--color-af-green) r g b / 0.5);
}

.ps__indicator--inactive {
  background: var(--color-af-muted);
}

.ps__status-text {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.8125rem;
  font-weight: 600;
  letter-spacing: 0.04em;
  color: var(--color-af-green);
}

.ps__status-text--inactive {
  color: var(--color-af-dim);
}

.ps__remaining {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.75rem;
  margin-left: auto;
}

.ps__remaining--ok {
  color: var(--color-af-green);
}
.ps__remaining--warn {
  color: var(--color-af-amber);
}
.ps__remaining--critical {
  color: var(--color-af-red);
}
.ps__remaining--expired {
  color: var(--color-af-red);
  font-weight: 600;
}

/* Info grid */
.ps__grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(14rem, 1fr));
  gap: 1rem;
  padding: 1rem;
  background: rgb(from var(--color-af-void) r g b / 0.4);
  border: 1px solid var(--color-af-border);
  border-radius: 4px;
}

.ps__field {
  display: flex;
  flex-direction: column;
  gap: 0.3125rem;
}

.ps__field--full {
  grid-column: 1 / -1;
}

.ps__label {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.5625rem;
  font-weight: 600;
  letter-spacing: 0.1em;
  text-transform: uppercase;
  color: var(--color-af-dim);
}

.ps__dn {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.6875rem;
  color: var(--color-af-text);
  word-break: break-all;
}

.ps__val {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.75rem;
  color: var(--color-af-text);
}

.ps__voms-list {
  display: flex;
  flex-wrap: wrap;
  gap: 0.375rem;
}

.ps__voms-attr {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.6875rem;
  color: var(--color-af-teal);
  background: rgb(from var(--color-af-teal) r g b / 0.08);
  border: 1px solid rgb(from var(--color-af-teal) r g b / 0.18);
  padding: 0.1875rem 0.5rem;
  border-radius: 2px;
}

/* Unlock form */
.ps__help {
  font-size: 0.875rem;
  color: var(--color-af-dim);
  margin: 0;
  line-height: 1.6;
}

.ps__form {
  display: flex;
  flex-direction: column;
  gap: 1rem;
  max-width: 36rem;
}

.ps__form-group {
  display: flex;
  flex-direction: column;
  gap: 0.375rem;
}

.ps__form-group--inline {
  flex: 1;
}

.ps__form-row {
  display: flex;
  gap: 1rem;
  flex-wrap: wrap;
}

.ps__form-label {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.6875rem;
  font-weight: 600;
  letter-spacing: 0.06em;
  text-transform: uppercase;
  color: #9ca3af;
}

.ps__input,
.ps__select {
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

.ps__input::placeholder {
  color: #4b5563;
}
.ps__input:focus,
.ps__select:focus {
  outline: none;
  border-color: var(--color-af-teal);
  box-shadow: 0 0 0 2px rgb(from var(--color-af-teal) r g b / 0.15);
}
.ps__input:disabled,
.ps__select:disabled {
  opacity: 0.5;
}

.ps__form-hint {
  font-size: 0.6875rem;
  color: #4b5563;
}

.ps__error {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.75rem;
  color: var(--color-af-red);
  padding: 0.5rem 0.75rem;
  border: 1px solid rgb(from var(--color-af-red) r g b / 0.25);
  border-radius: 3px;
  background: rgb(from var(--color-af-red) r g b / 0.06);
}

/* Action row */
.ps__actions {
  display: flex;
  gap: 0.75rem;
}

/* Buttons */
.ps__btn {
  display: inline-flex;
  align-items: center;
  padding: 0.5rem 1rem;
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
.ps__btn:disabled {
  opacity: 0.45;
  cursor: not-allowed;
}
.ps__btn:focus-visible {
  outline: 2px solid var(--color-af-teal);
  outline-offset: 2px;
}

.ps__btn--unlock {
  background: rgb(from var(--color-af-teal) r g b / 0.12);
  color: var(--color-af-teal);
  border-color: rgb(from var(--color-af-teal) r g b / 0.3);
  padding: 0.5625rem 1.25rem;
}
.ps__btn--unlock:not(:disabled):hover {
  background: rgb(from var(--color-af-teal) r g b / 0.2);
  border-color: rgb(from var(--color-af-teal) r g b / 0.5);
}

.ps__btn--revoke {
  background: transparent;
  color: var(--color-af-dim);
  border-color: var(--color-af-muted);
}
.ps__btn--revoke:not(:disabled):hover {
  color: var(--color-af-red);
  border-color: rgb(from var(--color-af-red) r g b / 0.35);
  background: rgb(from var(--color-af-red) r g b / 0.06);
}

.ps__btn--cancel {
  background: transparent;
  color: var(--color-af-dim);
  border-color: var(--color-af-muted);
}
.ps__btn--cancel:hover {
  color: var(--color-af-text);
  border-color: var(--color-af-dim);
}

.ps__btn--confirm-revoke {
  background: rgb(from var(--color-af-red) r g b / 0.1);
  color: var(--color-af-red);
  border-color: rgb(from var(--color-af-red) r g b / 0.3);
}
.ps__btn--confirm-revoke:hover {
  background: rgb(from var(--color-af-red) r g b / 0.18);
}

/* Modal — the native <dialog> element sits centered via its UA styles; we
 * override the box chrome and add our own ::backdrop with the AF ground tint.
 */
.ps__modal {
  background: var(--color-af-surface);
  border: 1px solid var(--color-af-muted);
  border-radius: 6px;
  padding: 1.75rem;
  max-width: 28rem;
  width: calc(100% - 2rem);
  color: inherit;
}

.ps__modal::backdrop {
  background: rgb(from var(--color-af-void) r g b / 0.85);
  backdrop-filter: blur(4px);
}

.ps__modal-title {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 1rem;
  font-weight: 600;
  color: var(--color-af-text);
  margin: 0 0 0.75rem;
}

.ps__modal-body {
  font-size: 0.875rem;
  color: #9ca3af;
  line-height: 1.6;
  margin: 0 0 1.5rem;
}

.ps__modal-actions {
  display: flex;
  gap: 0.75rem;
  justify-content: flex-end;
}
</style>
