<script setup lang="ts">
/**
 * TokensPage.vue — manual Bearer bootstrap for programmatic MCP clients
 * (issue #24). Interactive browser use never touches this page — oauth2-proxy
 * handles that transparently (see docs/auth.md). This page exists for clients
 * like Claude Desktop that can't do OAuth discovery yet.
 *
 * CRITICAL SECURITY NOTE: the minted token value only ever lives in
 * `mintedToken` for the lifetime of the mint dialog. It is cleared the moment
 * the dialog closes (Done, ESC, or backdrop click all fire the native
 * `close` event) and is never written back into the token list — the list
 * always comes from GET /v1/tokens, which never echoes a token value.
 */
import { ref, computed, onMounted, nextTick } from 'vue';
import { mintToken, listTokens, revokeToken, SessionExpiredError } from '../lib/api';
import type { MintedToken, TokenSummary } from '../lib/api';

const tokens = ref<TokenSummary[]>([]);
const loading = ref(true);
const error = ref<string | null>(null);
const sessionExpired = ref(false);

const sortedTokens = computed(() =>
  [...tokens.value].sort((a, b) => Date.parse(b.issued_at) - Date.parse(a.issued_at)),
);

async function loadTokens() {
  try {
    tokens.value = await listTokens();
  } catch (err) {
    if (err instanceof SessionExpiredError) {
      sessionExpired.value = true;
    } else {
      error.value = err instanceof Error ? err.message : 'Could not load tokens.';
    }
  } finally {
    loading.value = false;
  }
}

onMounted(loadTokens);

function reload() {
  location.reload();
}

// ── Mint dialog ──────────────────────────────────────────────────────────
// Native <dialog> gives a real focus trap, ESC to close, and inert siblings
// for free (see ProxyStatus.vue for the same pattern).
const mintDialog = ref<HTMLDialogElement | null>(null);
const mintTrigger = ref<HTMLButtonElement | null>(null);

const ttlSeconds = ref<'3600' | '21600' | '86400'>('3600');
const note = ref('');
const minting = ref(false);
const mintError = ref<string | null>(null);
const mintedToken = ref<MintedToken | null>(null);
const copyLabel = ref('Copy');

async function openMintDialog(evt: Event) {
  mintTrigger.value = evt.currentTarget as HTMLButtonElement;
  mintedToken.value = null;
  mintError.value = null;
  note.value = '';
  ttlSeconds.value = '3600';
  copyLabel.value = 'Copy';
  await nextTick();
  mintDialog.value?.showModal();
}

// Fires on ESC, backdrop click, or an explicit .close() — the single place
// that must scrub the minted token from memory once the dialog is gone.
function onMintDialogClose() {
  mintTrigger.value?.focus();
  mintTrigger.value = null;
  mintedToken.value = null;
}

async function handleMint(evt: Event) {
  evt.preventDefault();
  minting.value = true;
  mintError.value = null;
  try {
    mintedToken.value = await mintToken(Number(ttlSeconds.value), note.value.trim() || undefined);
  } catch (err) {
    mintError.value = err instanceof Error ? err.message : 'Could not mint a token. Try again.';
  } finally {
    minting.value = false;
  }
}

async function copyToken() {
  if (!mintedToken.value) return;
  try {
    await navigator.clipboard.writeText(mintedToken.value.token);
    copyLabel.value = 'Copied!';
    setTimeout(() => {
      copyLabel.value = 'Copy';
    }, 2000);
  } catch {
    copyLabel.value = 'Copy failed — select and copy manually';
  }
}

async function handleDone() {
  mintDialog.value?.close(); // triggers onMintDialogClose, which clears mintedToken
  await loadTokens();
}

// ── Revoke ───────────────────────────────────────────────────────────────
const revokingJti = ref<string | null>(null);
const revokeError = ref<string | null>(null);

async function handleRevoke(jti: string) {
  revokingJti.value = jti;
  revokeError.value = null;
  try {
    await revokeToken(jti);
    tokens.value = tokens.value.filter((t) => t.jti !== jti);
  } catch (err) {
    revokeError.value = err instanceof Error ? err.message : 'Revoke failed.';
  } finally {
    revokingJti.value = null;
  }
}

// ── Formatting ───────────────────────────────────────────────────────────
const relativeFormatter = new Intl.RelativeTimeFormat('en', { numeric: 'auto' });

function formatRelative(iso: string): string {
  const deltaSeconds = Math.round((Date.parse(iso) - Date.now()) / 1000);
  const abs = Math.abs(deltaSeconds);
  if (abs < 60) return relativeFormatter.format(deltaSeconds, 'second');
  if (abs < 3600) return relativeFormatter.format(Math.round(deltaSeconds / 60), 'minute');
  if (abs < 86400) return relativeFormatter.format(Math.round(deltaSeconds / 3600), 'hour');
  return relativeFormatter.format(Math.round(deltaSeconds / 86400), 'day');
}

function formatAbsolute(iso: string): string {
  return new Date(iso).toLocaleString('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    timeZoneName: 'short',
  });
}

function isExpired(iso: string): boolean {
  return Date.parse(iso) <= Date.now();
}

const sourceLabel: Record<string, string> = {
  manual: 'manual',
  'mcp-oauth': 'mcp-oauth',
  'oauth2-proxy': 'oauth2-proxy',
};
</script>

<template>
  <div class="tp">
    <div class="tp__toolbar">
      <button ref="mintTrigger" type="button" class="tp__btn tp__btn--mint" @click="openMintDialog">
        Mint new token
      </button>
    </div>

    <!-- Loading -->
    <div v-if="loading" class="tp__loading" aria-live="polite">
      <span class="tp__spinner" aria-hidden="true"></span>
      Loading tokens…
    </div>

    <!-- Session expired -->
    <div v-else-if="sessionExpired" class="tp__error" role="alert">
      <span class="tp__error-title">Session expired</span>
      <span class="tp__error-body">
        Your session has expired.
        <button type="button" class="tp__reload" @click="reload">Reload</button>
        to re-authenticate.
      </span>
    </div>

    <!-- Error -->
    <div v-else-if="error" class="tp__error" role="alert">
      <span class="tp__error-title">Could not load tokens</span>
      <span class="tp__error-body">{{ error }}</span>
    </div>

    <template v-else>
      <div v-if="revokeError" class="tp__error" role="alert">
        <span class="tp__error-title">Revoke failed</span>
        <span class="tp__error-body">{{ revokeError }}</span>
      </div>

      <!-- Token list -->
      <div
        v-if="sortedTokens.length > 0"
        class="tp__table"
        role="region"
        aria-label="Issued tokens"
      >
        <table class="tp__table-el" aria-label="Your issued tokens">
          <thead>
            <tr>
              <th scope="col" class="tp__th">Note</th>
              <th scope="col" class="tp__th">Issued</th>
              <th scope="col" class="tp__th">Expires</th>
              <th scope="col" class="tp__th">Source</th>
              <th scope="col" class="tp__th tp__th--action">
                <span class="sr-only">Actions</span>
              </th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="row in sortedTokens" :key="row.jti" class="tp__row">
              <td class="tp__td tp__td--note">{{ row.note || '(no note)' }}</td>
              <td class="tp__td" :title="formatAbsolute(row.issued_at)">
                {{ formatRelative(row.issued_at) }}
              </td>
              <td
                class="tp__td"
                :class="{ 'tp__td--expired': isExpired(row.expires_at) }"
                :title="formatAbsolute(row.expires_at)"
              >
                {{ isExpired(row.expires_at) ? 'expired' : formatRelative(row.expires_at) }}
              </td>
              <td class="tp__td">
                <span class="tp__badge" :class="`tp__badge--${row.source}`">
                  {{ sourceLabel[row.source] ?? row.source }}
                </span>
              </td>
              <td class="tp__td tp__td--action">
                <button
                  type="button"
                  class="tp__btn tp__btn--revoke"
                  :disabled="revokingJti === row.jti"
                  @click="handleRevoke(row.jti)"
                >
                  {{ revokingJti === row.jti ? 'Revoking…' : 'Revoke' }}
                </button>
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <!-- Empty state -->
      <div v-else class="tp__empty">
        <p class="tp__empty-title">No tokens yet</p>
        <p class="tp__empty-body">Mint one above to bootstrap a programmatic MCP client.</p>
      </div>

      <p class="tp__gap-note">
        This list only shows tokens minted here. Keycloak doesn't yet expose per-token metadata for
        interactive sign-in (oauth2-proxy) sessions or a future MCP OAuth flow, so those aren't
        listed — see <code>docs/auth.md</code>.
      </p>
    </template>

    <!-- Mint dialog -->
    <dialog
      ref="mintDialog"
      class="tp__modal"
      aria-labelledby="tp-modal-title"
      @close="onMintDialogClose"
    >
      <template v-if="!mintedToken">
        <h2 id="tp-modal-title" class="tp__modal-title">Mint a new token</h2>
        <p class="tp__modal-body">
          Creates a static Bearer token for pasting into an MCP client config (e.g. Claude Desktop).
          It will be shown exactly once.
        </p>

        <form class="tp__form" @submit.prevent="handleMint" novalidate>
          <div class="tp__form-row">
            <div class="tp__form-group tp__form-group--inline">
              <label for="tp-ttl" class="tp__form-label">Valid for</label>
              <select id="tp-ttl" v-model="ttlSeconds" class="tp__select" :disabled="minting">
                <option value="3600">1 hour</option>
                <option value="21600">6 hours</option>
                <option value="86400">24 hours</option>
              </select>
            </div>
          </div>

          <div class="tp__form-group">
            <label for="tp-note" class="tp__form-label">Note (optional)</label>
            <input
              id="tp-note"
              v-model="note"
              type="text"
              class="tp__input"
              placeholder="e.g. claude-desktop"
              maxlength="200"
              :disabled="minting"
            />
          </div>

          <div v-if="mintError" class="tp__error" role="alert">{{ mintError }}</div>

          <div class="tp__modal-actions">
            <button type="button" class="tp__btn tp__btn--cancel" @click="mintDialog?.close()">
              Cancel
            </button>
            <button
              type="submit"
              class="tp__btn tp__btn--mint"
              :disabled="minting"
              :aria-busy="minting"
            >
              {{ minting ? 'Minting…' : 'Mint token' }}
            </button>
          </div>
        </form>
      </template>

      <template v-else>
        <h2 id="tp-modal-title" class="tp__modal-title">Token created</h2>

        <div class="tp__warn" role="alert">
          This is the only time this token will be shown. Copy it now.
        </div>

        <div class="tp__token-box">
          <code class="tp__token-value">{{ mintedToken.token }}</code>
          <button type="button" class="tp__btn tp__btn--copy" @click="copyToken">
            {{ copyLabel }}
          </button>
        </div>

        <dl class="tp__token-meta">
          <div class="tp__token-meta-row">
            <dt>Note</dt>
            <dd>{{ mintedToken.note || '(no note)' }}</dd>
          </div>
          <div class="tp__token-meta-row">
            <dt>Expires</dt>
            <dd>{{ formatAbsolute(mintedToken.expires_at) }}</dd>
          </div>
        </dl>

        <div class="tp__modal-actions">
          <button type="button" class="tp__btn tp__btn--mint" @click="handleDone">Done</button>
        </div>
      </template>
    </dialog>
  </div>
</template>

<style scoped>
.tp {
  display: flex;
  flex-direction: column;
  gap: 1.25rem;
}

.sr-only {
  position: absolute;
  width: 1px;
  height: 1px;
  padding: 0;
  margin: -1px;
  overflow: hidden;
  clip: rect(0, 0, 0, 0);
  white-space: nowrap;
  border: 0;
}

/* Toolbar */
.tp__toolbar {
  display: flex;
  justify-content: flex-end;
}

/* Loading */
.tp__loading {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  padding: 2rem;
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.8125rem;
  color: var(--color-af-dim);
}

.tp__spinner {
  width: 16px;
  height: 16px;
  border: 2px solid var(--color-af-border);
  border-top-color: var(--color-af-teal);
  border-radius: 50%;
  animation: spin 600ms linear infinite;
}
@keyframes spin {
  to {
    transform: rotate(360deg);
  }
}
@media (prefers-reduced-motion: reduce) {
  .tp__spinner {
    animation: none;
    border-top-color: var(--color-af-dim);
  }
}

/* Error */
.tp__error {
  display: flex;
  flex-direction: column;
  gap: 0.375rem;
  padding: 1rem;
  border: 1px solid rgb(from var(--color-af-red) r g b / 0.2);
  border-radius: 4px;
  background: rgb(from var(--color-af-red) r g b / 0.05);
}
.tp__error-title {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.8125rem;
  font-weight: 600;
  color: var(--color-af-red);
}
.tp__error-body {
  font-size: 0.875rem;
  color: #9ca3af;
}
.tp__reload {
  font: inherit;
  color: var(--color-af-teal);
  background: none;
  border: none;
  padding: 0;
  cursor: pointer;
  text-decoration: underline;
}

/* Table */
.tp__table {
  overflow-x: auto;
  border: 1px solid var(--color-af-border);
  border-radius: 4px;
}

.tp__table-el {
  width: 100%;
  border-collapse: collapse;
  font-family: 'IBM Plex Sans', system-ui, sans-serif;
  font-size: 0.8125rem;
}

.tp__th {
  text-align: left;
  padding: 0.625rem 0.875rem;
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.625rem;
  font-weight: 600;
  letter-spacing: 0.1em;
  text-transform: uppercase;
  color: var(--color-af-dim);
  border-bottom: 1px solid var(--color-af-border);
  white-space: nowrap;
  background: var(--color-af-surface);
}

.tp__th--action {
  width: 6rem;
}

.tp__row {
  border-bottom: 1px solid var(--color-af-border);
  transition: background 120ms;
}
.tp__row:hover {
  background: rgba(255, 255, 255, 0.025);
}
.tp__row:last-child {
  border-bottom: none;
}

.tp__td {
  padding: 0.625rem 0.875rem;
  vertical-align: middle;
  color: var(--color-af-text);
}

.tp__td--note {
  color: #9ca3af;
}

.tp__td--expired {
  color: var(--color-af-red);
}

.tp__td--action {
  text-align: right;
}

.tp__badge {
  display: inline-block;
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.5625rem;
  font-weight: 600;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  padding: 0.1875rem 0.5rem;
  border-radius: 2px;
}

.tp__badge--manual {
  background: rgb(from var(--color-af-teal) r g b / 0.12);
  color: var(--color-af-teal);
  border: 1px solid rgb(from var(--color-af-teal) r g b / 0.25);
}
.tp__badge--mcp-oauth,
.tp__badge--oauth2-proxy {
  background: rgb(from var(--color-af-dim) r g b / 0.12);
  color: var(--color-af-dim);
  border: 1px solid rgb(from var(--color-af-dim) r g b / 0.25);
}

/* Empty */
.tp__empty {
  padding: 3rem 1.5rem;
  text-align: center;
  border: 1px dashed var(--color-af-border);
  border-radius: 4px;
}
.tp__empty-title {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 1rem;
  color: #4b5563;
  margin: 0 0 0.5rem;
}
.tp__empty-body {
  font-size: 0.875rem;
  color: var(--color-af-muted);
  margin: 0;
}

.tp__gap-note {
  font-size: 0.75rem;
  color: var(--color-af-dim);
  line-height: 1.6;
  margin: 0;
}
.tp__gap-note code {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.6875rem;
  color: #9ca3af;
}

/* Buttons (shared shape with ProxyStatus.vue / IdentityLink.vue) */
.tp__btn {
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
.tp__btn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}
.tp__btn:focus-visible {
  outline: 2px solid var(--color-af-teal);
  outline-offset: 2px;
}

.tp__btn--mint {
  background: rgb(from var(--color-af-teal) r g b / 0.12);
  color: var(--color-af-teal);
  border-color: rgb(from var(--color-af-teal) r g b / 0.3);
  padding: 0.5625rem 1.25rem;
}
.tp__btn--mint:not(:disabled):hover {
  background: rgb(from var(--color-af-teal) r g b / 0.2);
  border-color: rgb(from var(--color-af-teal) r g b / 0.5);
}

.tp__btn--revoke {
  background: transparent;
  color: var(--color-af-dim);
  border-color: var(--color-af-muted);
  padding: 0.375rem 0.75rem;
}
.tp__btn--revoke:not(:disabled):hover {
  color: var(--color-af-red);
  border-color: rgb(from var(--color-af-red) r g b / 0.35);
  background: rgb(from var(--color-af-red) r g b / 0.06);
}

.tp__btn--cancel {
  background: transparent;
  color: var(--color-af-dim);
  border-color: var(--color-af-muted);
}
.tp__btn--cancel:hover {
  color: var(--color-af-text);
  border-color: var(--color-af-dim);
}

.tp__btn--copy {
  background: rgb(from var(--color-af-teal) r g b / 0.1);
  color: var(--color-af-teal);
  border-color: rgb(from var(--color-af-teal) r g b / 0.3);
  flex-shrink: 0;
}
.tp__btn--copy:hover {
  background: rgb(from var(--color-af-teal) r g b / 0.18);
}

/* Form */
.tp__form {
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

.tp__form-row {
  display: flex;
  gap: 1rem;
  flex-wrap: wrap;
}

.tp__form-group {
  display: flex;
  flex-direction: column;
  gap: 0.375rem;
}
.tp__form-group--inline {
  flex: 1;
}

.tp__form-label {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.6875rem;
  font-weight: 600;
  letter-spacing: 0.06em;
  text-transform: uppercase;
  color: #9ca3af;
}

.tp__input,
.tp__select {
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
.tp__input:focus,
.tp__select:focus {
  outline: none;
  border-color: var(--color-af-teal);
  box-shadow: 0 0 0 2px rgb(from var(--color-af-teal) r g b / 0.15);
}
.tp__input:disabled,
.tp__select:disabled {
  opacity: 0.5;
}

/* Modal */
.tp__modal {
  background: var(--color-af-surface);
  border: 1px solid var(--color-af-muted);
  border-radius: 6px;
  padding: 1.75rem;
  max-width: 32rem;
  width: calc(100% - 2rem);
  color: inherit;
}
.tp__modal::backdrop {
  background: rgb(from var(--color-af-void) r g b / 0.85);
  backdrop-filter: blur(4px);
}

.tp__modal-title {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 1rem;
  font-weight: 600;
  color: var(--color-af-text);
  margin: 0 0 0.75rem;
}
.tp__modal-body {
  font-size: 0.875rem;
  color: #9ca3af;
  line-height: 1.6;
  margin: 0 0 1.25rem;
}
.tp__modal-actions {
  display: flex;
  gap: 0.75rem;
  justify-content: flex-end;
  margin-top: 1.25rem;
}

/* "Shown once" warning */
.tp__warn {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.8125rem;
  font-weight: 600;
  color: var(--color-af-amber);
  background: rgb(from var(--color-af-amber) r g b / 0.1);
  border: 1px solid rgb(from var(--color-af-amber) r g b / 0.3);
  border-radius: 4px;
  padding: 0.75rem 1rem;
  margin: 0 0 1rem;
  line-height: 1.5;
}

.tp__token-box {
  display: flex;
  align-items: center;
  gap: 0.625rem;
  padding: 0.75rem;
  background: var(--color-af-void);
  border: 1px solid var(--color-af-muted);
  border-radius: 4px;
  margin-bottom: 1rem;
}

.tp__token-value {
  flex: 1;
  min-width: 0;
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.75rem;
  color: var(--color-af-text);
  word-break: break-all;
  max-height: 8rem;
  overflow-y: auto;
}

.tp__token-meta {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
  margin: 0;
  font-size: 0.8125rem;
}
.tp__token-meta-row {
  display: flex;
  gap: 0.5rem;
}
.tp__token-meta-row dt {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.625rem;
  font-weight: 600;
  letter-spacing: 0.06em;
  text-transform: uppercase;
  color: var(--color-af-dim);
  width: 5rem;
  flex-shrink: 0;
}
.tp__token-meta-row dd {
  margin: 0;
  color: #9ca3af;
}

@media (max-width: 640px) {
  .tp__toolbar {
    justify-content: stretch;
  }
  .tp__toolbar .tp__btn {
    width: 100%;
    justify-content: center;
  }
}
</style>
