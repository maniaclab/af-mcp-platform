<script setup lang="ts">
/**
 * TokensPage.vue — mints broker-issued identity PATs for programmatic MCP
 * clients (issue #144 step 2a), backed by a durable, HA-safe registry with
 * enforced revocation. Interactive browser use never touches this page —
 * oauth2-proxy handles that transparently (see docs/auth.md). This page
 * exists for clients like Claude Desktop that can't do OAuth discovery yet.
 *
 * CRITICAL SECURITY NOTE: the minted token value only ever lives in
 * `mintedToken` for the lifetime of the mint dialog. It is cleared the moment
 * the dialog closes (Done, ESC, or backdrop click all fire the native
 * `close` event) and is never written back into the token list — the list
 * always comes from GET /v1/tokens, which never echoes a token value.
 */
import { ref, computed, onMounted, nextTick, type Ref } from 'vue';
import {
  AccessDeniedError,
  mintToken,
  listTokens,
  revokeToken,
  fetchCapabilities,
  SessionExpiredError,
} from '../lib/api';
import type { MintedToken, TokenSummary } from '../lib/api';
import {
  NOTE_MAX_LENGTH,
  capabilityGrantLabel,
  shortLookupId,
  tokenStatus,
  truncateNote,
} from '../lib/tokenDisplay';
import {
  claudeMcpAddSnippet,
  curlMintSnippet,
  pythonMintAndConnectSnippet,
} from '../lib/tokenCliSnippets';
import { getBrokerOrigin } from '../lib/auth';

const tokens = ref<TokenSummary[]>([]);
const loading = ref(true);
const error = ref<string | null>(null);
const sessionExpired = ref(false);
const accessDenied = ref<AccessDeniedError | null>(null);

const sortedTokens = computed(() =>
  [...tokens.value].sort((a, b) => Date.parse(b.created_at) - Date.parse(a.created_at)),
);

async function loadTokens() {
  try {
    tokens.value = await listTokens();
  } catch (err) {
    if (err instanceof AccessDeniedError) {
      accessDenied.value = err;
    } else if (err instanceof SessionExpiredError) {
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
// for free (see IdentityLink.vue for the same pattern).
const mintDialog = ref<HTMLDialogElement | null>(null);
const mintTrigger = ref<HTMLButtonElement | null>(null);

// '90' is the broker's own default (Settings.pat_default_expiry_days) --
// mirrored here only as the form's starting selection; the broker applies
// its own default regardless if expires_in_days is omitted from the
// request. 'never' maps to never_expires: true (an explicit opt-in per
// api/tokens.py's MintTokenRequest -- never silently the default).
const expiryOption = ref<'30' | '90' | '365' | 'never'>('90');
const name = ref('');
const note = ref('');
const minting = ref(false);
const mintError = ref<string | null>(null);
const mintedToken = ref<MintedToken | null>(null);
const copyLabel = ref('Copy');

// ── Capability PATs (issue #144 step 4) ─────────────────────────────────
// `availableCapabilities` is the caller's CURRENT capabilities (GET
// /v1/capabilities), fetched once on mount -- never a static list, since
// the whole point of a capability PAT is that it can only ever narrow what
// its owner already holds *right now*. `restrictCapabilities` is the mint
// form's opt-in: unchecked (the default) mints an ordinary identity PAT,
// exactly as before this field existed; checked reveals the checkbox list
// below and mints a capability PAT scoped to whatever's selected.
const availableCapabilities = ref<string[]>([]);
const restrictCapabilities = ref(false);
const selectedCapabilities = ref<Set<string>>(new Set());

onMounted(async () => {
  try {
    const { grants } = await fetchCapabilities();
    availableCapabilities.value = grants.map((g) => g.capability).sort();
  } catch {
    // Best-effort: if this fails, the mint dialog simply offers no
    // capability restriction (identity PATs remain fully mintable, which
    // is the more important path to keep working) rather than blocking
    // the page load or the dialog itself over a secondary feature.
    availableCapabilities.value = [];
  }
});

function toggleSelectedCapability(capability: string, checked: boolean) {
  if (checked) {
    selectedCapabilities.value.add(capability);
  } else {
    selectedCapabilities.value.delete(capability);
  }
}

async function openMintDialog(evt: Event) {
  mintTrigger.value = evt.currentTarget as HTMLButtonElement;
  mintedToken.value = null;
  mintError.value = null;
  name.value = '';
  note.value = '';
  expiryOption.value = '90';
  copyLabel.value = 'Copy';
  restrictCapabilities.value = false;
  selectedCapabilities.value = new Set();
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
    const neverExpires = expiryOption.value === 'never';
    mintedToken.value = await mintToken(
      name.value.trim() || undefined,
      note.value.trim() || undefined,
      neverExpires ? undefined : Number(expiryOption.value),
      neverExpires,
      restrictCapabilities.value ? [...selectedCapabilities.value] : undefined,
    );
  } catch (err) {
    // Includes the 409 duplicate-name case (api/tokens.py's DuplicateNameError)
    // -- APIError's message already carries the broker's `detail` text.
    mintError.value = err instanceof Error ? err.message : 'Could not mint a token. Try again.';
  } finally {
    minting.value = false;
  }
}

const CLIPBOARD_LABEL_RESET_MS = 2000;

// Shared by copyToken() (the minted-token box) and the CLI snippets section
// below (copyCurlSnippet()/copyPythonSnippet()) -- same "Copy" -> "Copied!" ->
// reset dance, just against different clipboard text and label refs.
async function copyToClipboard(text: string, label: Ref<string>) {
  try {
    await navigator.clipboard.writeText(text);
    label.value = 'Copied!';
    setTimeout(() => {
      label.value = 'Copy';
    }, CLIPBOARD_LABEL_RESET_MS);
  } catch {
    label.value = 'Copy failed — select and copy manually';
  }
}

async function copyToken() {
  if (!mintedToken.value) return;
  await copyToClipboard(mintedToken.value.token, copyLabel);
}

async function handleDone() {
  mintDialog.value?.close(); // triggers onMintDialogClose, which clears mintedToken
  await loadTokens();
}

// ── "Use from the command line" (issue #122) ────────────────────────────
// Copy-paste snippets for minting/using a token outside the portal (testing,
// scripts, CI) -- the tracked path, as opposed to a token obtained directly
// from Keycloak (which POST /v1/tokens never sees, so it can't be listed or
// revoked below; see docs/connecting-a-client.md).
// Empty until onMounted resolves it -- never read `window` at setup() time,
// since Astro prerenders this component server-side (client:load) where
// there is no window (see the build's SSR pass).
const brokerOrigin = ref('');
onMounted(async () => {
  brokerOrigin.value = await getBrokerOrigin();
});

const curlSnippet = computed(() => curlMintSnippet(brokerOrigin.value));
const pythonSnippet = computed(() => pythonMintAndConnectSnippet(brokerOrigin.value));

const curlCopyLabel = ref('Copy');
const pythonCopyLabel = ref('Copy');

async function copyCurlSnippet() {
  await copyToClipboard(curlSnippet.value, curlCopyLabel);
}

async function copyPythonSnippet() {
  await copyToClipboard(pythonSnippet.value, pythonCopyLabel);
}

// "Register as an MCP client" one-liner shown alongside the raw token in
// the "Token created" step above (issue #152) -- reuses the same
// brokerOrigin this section resolves. Only ever constructible from
// `mintedToken`, which onMintDialogClose scrubs the moment the dialog
// closes -- like the token itself, this is never reconstructable from the
// list view, since the secret is never retained server-side.
const claudeAddCommand = computed(() =>
  mintedToken.value ? claudeMcpAddSnippet(brokerOrigin.value, mintedToken.value.token) : '',
);
const claudeAddCopyLabel = ref('Copy');

async function copyClaudeAddCommand() {
  await copyToClipboard(claudeAddCommand.value, claudeAddCopyLabel);
}

// "Request headers" value for Claude (Claude.ai, Claude Desktop) clients that
// predate OAuth discovery -- see docs/connecting-a-client.md's "Claude
// (Claude.ai, Claude Desktop)" section: Name "Authorization", Value
// "Bearer <token>", entered in the custom connector's own Request headers
// field. Same lifetime as claudeAddCommand above -- only ever constructible
// from `mintedToken`, scrubbed the moment the dialog closes.
const claudeHeaderValue = computed(() =>
  mintedToken.value ? `Bearer ${mintedToken.value.token}` : '',
);
const claudeHeaderCopyLabel = ref('Copy');

async function copyClaudeHeaderValue() {
  await copyToClipboard(claudeHeaderValue.value, claudeHeaderCopyLabel);
}

// ── Revoke ───────────────────────────────────────────────────────────────
const revokingLookupId = ref<string | null>(null);
const revokeError = ref<string | null>(null);

// Revoke-confirm dialog -- same native <dialog> pattern as IdentityLink.vue's
// revoke-confirm and IdentityLink.vue's unlink-confirm (real focus trap, ESC
// to close, inert siblings for free). Token revoke previously fired straight
// from the row's click handler with no confirmation at all, unlike those two
// other destructive actions in the app.
const revokeDialog = ref<HTMLDialogElement | null>(null);
const revokeTrigger = ref<HTMLButtonElement | null>(null);
const cancelRevokeBtn = ref<HTMLButtonElement | null>(null);
const pendingRevoke = ref<{ lookupId: string; name: string } | null>(null);

async function openRevokeConfirm(evt: Event, lookupId: string, name: string) {
  revokeTrigger.value = evt.currentTarget as HTMLButtonElement;
  pendingRevoke.value = { lookupId, name };
  await nextTick();
  revokeDialog.value?.showModal();
  // Move focus off the destructive "Revoke" button — start on Cancel.
  cancelRevokeBtn.value?.focus();
}

function closeRevokeConfirm() {
  revokeDialog.value?.close();
}

// Native <dialog> fires `close` whether it was closed by ESC, form method="dialog",
// or an explicit .close() call — this is our single place to restore focus.
function onRevokeDialogClose() {
  revokeTrigger.value?.focus();
  revokeTrigger.value = null;
  pendingRevoke.value = null;
}

async function handleRevoke() {
  if (!pendingRevoke.value) return;
  const { lookupId } = pendingRevoke.value;
  closeRevokeConfirm();
  revokingLookupId.value = lookupId;
  revokeError.value = null;
  try {
    await revokeToken(lookupId);
    // Revoking no longer removes the row (PR #28's behavior) -- it stays
    // listed with a "revoked" status, so patch it in place rather than
    // refetching the whole list.
    const row = tokens.value.find((t) => t.lookup_id === lookupId);
    if (row) row.revoked_at = new Date().toISOString();
  } catch (err) {
    revokeError.value = err instanceof Error ? err.message : 'Revoke failed.';
  } finally {
    revokingLookupId.value = null;
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

function isExpired(iso: string | null): boolean {
  return iso !== null && Date.parse(iso) <= Date.now();
}

const statusLabel: Record<ReturnType<typeof tokenStatus>, string> = {
  active: 'active',
  revoked: 'revoked',
  expired: 'expired',
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

    <!-- Access denied: a valid, unexpired credential that's missing the
         audience needed to use this platform -- a reload can't fix it, only
         an administrator granting access can (see identity.py's
         TokenAudienceError). -->
    <div v-else-if="accessDenied" class="tp__error" role="alert">
      <span class="tp__error-title">Access not yet granted</span>
      <span class="tp__error-body">{{ accessDenied.message }}</span>
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
              <th scope="col" class="tp__th">Name</th>
              <th scope="col" class="tp__th">Scope</th>
              <th scope="col" class="tp__th tp__th--secondary">Token ID</th>
              <th scope="col" class="tp__th tp__th--secondary">Created</th>
              <th scope="col" class="tp__th">Expires</th>
              <th scope="col" class="tp__th tp__th--secondary">Last used</th>
              <th scope="col" class="tp__th">Status</th>
              <th scope="col" class="tp__th tp__th--action">
                <span class="sr-only">Actions</span>
              </th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="row in sortedTokens" :key="row.lookup_id" class="tp__row">
              <td class="tp__td">
                <div class="tp__td-name-wrap">
                  <span class="tp__td-name">{{ row.name }}</span>
                  <button
                    v-if="row.note"
                    type="button"
                    class="tp__note-icon"
                    :aria-describedby="`tp-note-${row.lookup_id}`"
                    aria-label="Show note"
                  >
                    <span aria-hidden="true">ⓘ</span>
                  </button>
                  <span
                    v-if="row.note"
                    :id="`tp-note-${row.lookup_id}`"
                    class="tp__note-tooltip"
                    role="tooltip"
                  >
                    {{ truncateNote(row.note) }}
                  </span>
                </div>
              </td>
              <td
                class="tp__td tp__td--scope"
                :class="{ 'tp__td--scope-identity': row.capability_grant === null }"
                :title="capabilityGrantLabel(row.capability_grant)"
              >
                {{ capabilityGrantLabel(row.capability_grant) }}
              </td>
              <td class="tp__td tp__td--jti tp__td--secondary" :title="row.lookup_id">
                {{ shortLookupId(row.lookup_id) }}
              </td>
              <td class="tp__td tp__td--secondary" :title="formatAbsolute(row.created_at)">
                {{ formatAbsolute(row.created_at) }}
              </td>
              <td
                class="tp__td"
                :class="{ 'tp__td--expired': isExpired(row.expires_at) }"
                :title="row.expires_at ? formatAbsolute(row.expires_at) : 'Never expires'"
              >
                <template v-if="row.expires_at === null">Never</template>
                <template v-else>
                  {{ isExpired(row.expires_at) ? 'expired' : formatRelative(row.expires_at) }}
                </template>
              </td>
              <td
                class="tp__td tp__td--secondary"
                :title="row.last_used_at ? formatAbsolute(row.last_used_at) : 'Never used'"
              >
                {{ row.last_used_at ? formatRelative(row.last_used_at) : 'Never' }}
              </td>
              <td class="tp__td">
                <span class="tp__badge" :class="`tp__badge--status-${tokenStatus(row)}`">
                  {{ statusLabel[tokenStatus(row)] }}
                </span>
              </td>
              <td class="tp__td tp__td--action">
                <button
                  type="button"
                  class="tp__btn tp__btn--revoke"
                  :disabled="revokingLookupId === row.lookup_id || tokenStatus(row) !== 'active'"
                  @click="openRevokeConfirm($event, row.lookup_id, row.name)"
                >
                  {{ revokingLookupId === row.lookup_id ? 'Revoking…' : 'Revoke' }}
                </button>
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <!-- Empty state -->
      <div v-else class="tp__empty">
        <p class="tp__empty-title">No tokens yet</p>
        <p class="tp__empty-body">
          Mint one above to connect a client, like Claude Desktop, that can't sign in with a browser
          on its own.
        </p>
      </div>

      <p class="tp__gap-note">
        This list only shows PATs created through this page or automatically when you connect an MCP
        client — see
        <a
          href="https://maniaclab.github.io/af-mcp-platform/auth/"
          target="_blank"
          rel="noopener noreferrer"
          >Authentication</a
        >
        for the full credential model.
      </p>

      <!-- issue #122: copy-paste snippets for minting/using a token outside the browser.
           Shown by default, not collapsed -- a returning user setting up a script or CI
           job needs these on first glance, not behind a click. -->
      <div class="tp__cli">
        <h2 class="tp__cli-heading tp__cli-heading--top">Use from the command line</h2>
        <p class="tp__cli-intro">
          Mint and use a PAT without opening a browser — handy for scripts or CI. See
          <a
            href="https://maniaclab.github.io/af-mcp-platform/connecting-a-client/"
            target="_blank"
            rel="noopener noreferrer"
            >Connecting a Client</a
          >
          for the full setup guide.
        </p>

        <h3 class="tp__cli-heading">1. Mint a token with curl</h3>
        <div class="tp__cli-snippet">
          <pre class="tp__cli-pre"><code>{{ curlSnippet }}</code></pre>
          <button type="button" class="tp__btn tp__btn--copy" @click="copyCurlSnippet">
            {{ curlCopyLabel }}
          </button>
        </div>

        <h3 class="tp__cli-heading">2. Mint and connect from Python</h3>
        <div class="tp__cli-snippet">
          <pre class="tp__cli-pre"><code>{{ pythonSnippet }}</code></pre>
          <button type="button" class="tp__btn tp__btn--copy" @click="copyPythonSnippet">
            {{ pythonCopyLabel }}
          </button>
        </div>

        <p class="tp__cli-note">
          A PAT minted this way appears in the list above like any other, with a name, expiry, and a
          <strong>Revoke</strong> action.
        </p>
      </div>
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
          Creates a Personal Access Token (PAT) — a long-lived credential you paste into an MCP
          client's config (e.g. Claude Desktop) that can't sign in with a browser on its own. It
          will be shown exactly once, so copy it before closing this dialog.
        </p>

        <form class="tp__form" @submit.prevent="handleMint" novalidate>
          <div class="tp__form-row">
            <div class="tp__form-group tp__form-group--inline">
              <label for="tp-ttl" class="tp__form-label">Valid for</label>
              <select id="tp-ttl" v-model="expiryOption" class="tp__select" :disabled="minting">
                <option value="30">30 days</option>
                <option value="90">90 days (default)</option>
                <option value="365">1 year</option>
                <option value="never">Never expires</option>
              </select>
            </div>
          </div>

          <div class="tp__form-group">
            <label for="tp-name" class="tp__form-label">Name (optional)</label>
            <input
              id="tp-name"
              v-model="name"
              type="text"
              class="tp__input"
              placeholder="e.g. claude-desktop"
              maxlength="200"
              :disabled="minting"
            />
          </div>

          <div class="tp__form-group">
            <label for="tp-note" class="tp__form-label">Note (optional)</label>
            <textarea
              id="tp-note"
              v-model="note"
              class="tp__input tp__textarea"
              placeholder="e.g. used by the CI bot for nightly runs"
              :maxlength="NOTE_MAX_LENGTH"
              rows="2"
              :disabled="minting"
            ></textarea>
          </div>

          <!-- Capability PATs (issue #144 step 4): optional restriction below
               the caller's own CURRENT capabilities. Hidden entirely when
               availableCapabilities is empty (e.g. the /v1/capabilities fetch
               failed) -- an identity PAT remains mintable regardless. -->
          <div v-if="availableCapabilities.length > 0" class="tp__form-group">
            <label class="tp__checkbox-row">
              <input
                v-model="restrictCapabilities"
                type="checkbox"
                class="tp__checkbox"
                :disabled="minting"
              />
              <span class="tp__form-label tp__checkbox-label"
                >Restrict capabilities (optional)</span
              >
            </label>
            <p class="tp__scope-hint">
              Unchecked mints a token with your full account access, exactly as before. Checked
              scopes the token to at most the capabilities selected below — least privilege for CI
              or scripts.
            </p>
            <fieldset v-if="restrictCapabilities" class="tp__scope-fieldset">
              <legend class="sr-only">Capabilities to grant</legend>
              <label v-for="cap in availableCapabilities" :key="cap" class="tp__checkbox-row">
                <input
                  type="checkbox"
                  class="tp__checkbox"
                  :checked="selectedCapabilities.has(cap)"
                  :disabled="minting"
                  @change="
                    toggleSelectedCapability(cap, ($event.target as HTMLInputElement).checked)
                  "
                />
                <span class="tp__scope-cap-name">{{ cap }}</span>
              </label>
            </fieldset>
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

        <div class="tp__form-label tp__claude-add-label">
          Claude (Claude.ai, Claude Desktop) without OAuth support
        </div>
        <div class="tp__token-box">
          <code class="tp__token-value">{{ claudeHeaderValue }}</code>
          <button type="button" class="tp__btn tp__btn--copy" @click="copyClaudeHeaderValue">
            {{ claudeHeaderCopyLabel }}
          </button>
        </div>
        <p class="tp__claude-add-warn">
          In the custom connector's <strong>Request headers</strong>, add name
          <code>Authorization</code> and paste the value above. Skip this if your client supports
          OAuth discovery — add just the server URL instead and it authenticates itself.
        </p>

        <div class="tp__form-label tp__claude-add-label">Register with Claude Code</div>
        <div class="tp__token-box">
          <code class="tp__token-value">{{ claudeAddCommand }}</code>
          <button type="button" class="tp__btn tp__btn--copy" @click="copyClaudeAddCommand">
            {{ claudeAddCopyLabel }}
          </button>
        </div>
        <p class="tp__claude-add-warn">
          This command embeds the token above — pasting it into a terminal puts a working credential
          in your shell history. For the safer pattern (token read into an env var via
          <code>read -s</code>, never a literal), see the <strong>Claude Code</strong> section of
          <code>docs/connecting-a-client.md</code>.
        </p>

        <dl class="tp__token-meta">
          <div class="tp__token-meta-row">
            <dt>Name</dt>
            <dd>{{ mintedToken.name }}</dd>
          </div>
          <div v-if="mintedToken.note" class="tp__token-meta-row">
            <dt>Note</dt>
            <dd>{{ mintedToken.note }}</dd>
          </div>
          <div class="tp__token-meta-row">
            <dt>Scope</dt>
            <dd>{{ capabilityGrantLabel(mintedToken.capability_grant) }}</dd>
          </div>
          <div class="tp__token-meta-row">
            <dt>Expires</dt>
            <dd>
              {{ mintedToken.expires_at ? formatAbsolute(mintedToken.expires_at) : 'Never' }}
            </dd>
          </div>
        </dl>

        <div class="tp__modal-actions">
          <button type="button" class="tp__btn tp__btn--mint" @click="handleDone">Done</button>
        </div>
      </template>
    </dialog>

    <!--
      Revoke confirm dialog -- native <dialog> gives a real focus trap (TAB
      cycles inside), ESC to close, and inert siblings, same pattern as
      IdentityLink.vue's unlink-confirm.
      Focus returns to the row's trigger button in onRevokeDialogClose.
    -->
    <dialog
      ref="revokeDialog"
      class="tp__modal"
      aria-labelledby="tp-revoke-title"
      @close="onRevokeDialogClose"
    >
      <h2 id="tp-revoke-title" class="tp__modal-title">Revoke "{{ pendingRevoke?.name }}"?</h2>
      <p class="tp__modal-body">
        Any MCP client using this token will stop working immediately. This cannot be undone.
      </p>
      <div class="tp__modal-actions">
        <button
          ref="cancelRevokeBtn"
          type="button"
          class="tp__btn tp__btn--cancel"
          @click="closeRevokeConfirm"
        >
          Cancel
        </button>
        <button
          type="button"
          class="tp__btn tp__btn--confirm-revoke"
          :disabled="revokingLookupId !== null"
          @click="handleRevoke"
        >
          {{ revokingLookupId ? 'Revoking…' : 'Revoke' }}
        </button>
      </div>
    </dialog>
  </div>
</template>

<style scoped>
.tp {
  display: flex;
  flex-direction: column;
  gap: 1.25rem;
  /* Matches tokens.astro's .page-subtitle max-width -- without this the
     table stretched to the full content column while the intro text above
     it stayed narrow, reading as oversized and full of dead space. */
  max-width: 52rem;
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
  color: var(--color-af-dim);
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
/* width: fit-content (not the block default of stretching to fill .tp's
   full 52rem) -- with few short-content columns the boxed border otherwise
   stretched well past the actual table content, reading as a mostly-empty
   box rather than a compact list.
   overflow-y: hidden, set explicitly rather than left to its default --
   overflow-x: auto alone makes overflow-y compute to 'auto' too, and each
   row's (invisible, opacity:0/visibility:hidden) .tp__note-tooltip is
   `position: absolute`, which doesn't affect this box's own auto-height
   but DOES count toward its *scrollable overflow* once it's a scroll
   container -- which is what was inflating this box well past its actual
   rows. Tradeoff: a note tooltip on one of the last rows, if shown, can
   no longer float past this box's own bottom edge -- an acceptable cost
   for a hover-only affordance, versus a table that reads as mostly empty
   space by default. */
.tp__table {
  width: fit-content;
  max-width: 100%;
  height: fit-content;
  overflow-x: auto;
  overflow-y: hidden;
  border: 1px solid var(--color-af-border);
  border-radius: 4px;
}

.tp__table-el {
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

.tp__td-name {
  color: var(--color-af-text);
}

/* Name cell + (i) note icon (issue #152) -- the tooltip below is
 * `position: absolute`, so it never participates in table layout the way
 * the old inline note div did (which stretched this column while still
 * truncating its own text -- the bug this replaces).
 */
.tp__td-name-wrap {
  position: relative;
  display: inline-flex;
  align-items: center;
  gap: 0.375rem;
}

.tp__note-icon {
  display: inline-flex;
  align-items: center;
  background: none;
  border: none;
  padding: 0;
  font-size: 0.75rem;
  line-height: 1;
  color: var(--color-af-dim);
  cursor: help;
}
.tp__note-icon:hover,
.tp__note-icon:focus-visible {
  color: var(--color-af-teal);
}
.tp__note-icon:focus-visible {
  outline: 2px solid var(--color-af-teal);
  outline-offset: 2px;
}

/* Hidden via opacity/visibility, not `display: none` -- aria-describedby
 * still reaches this content for assistive tech regardless of the visual
 * hover/focus state below, which is what makes it keyboard-accessible and
 * not just hover-only. */
.tp__note-tooltip {
  position: absolute;
  top: 100%;
  left: 0;
  margin-top: 0.375rem;
  max-width: 18rem;
  padding: 0.5rem 0.625rem;
  background: var(--color-af-void);
  border: 1px solid var(--color-af-muted);
  border-radius: 4px;
  font-family: 'IBM Plex Sans', system-ui, sans-serif;
  font-size: 0.75rem;
  line-height: 1.5;
  color: var(--color-af-text);
  white-space: normal;
  word-break: break-word;
  opacity: 0;
  visibility: hidden;
  transition: opacity 120ms;
  pointer-events: none;
  z-index: 10;
}
.tp__note-icon:hover + .tp__note-tooltip,
.tp__note-icon:focus-visible + .tp__note-tooltip {
  opacity: 1;
  visibility: visible;
}

.tp__td--jti {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.75rem;
  color: var(--color-af-dim);
}

.tp__td--expired {
  color: var(--color-af-red);
}

/* Scope column (issue #144 step 4) -- a capability PAT's grant is
 * comma-joined plain text (capabilityGrantLabel), truncated by the column's
 * own max-width with the full value always available via `title`. An
 * identity PAT's "Full account access" is dimmed relative to a named grant,
 * the same visual weight tp__td--jti already uses for secondary detail. */
.tp__td--scope {
  max-width: 14rem;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.tp__td--scope-identity {
  color: var(--color-af-dim);
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

.tp__badge--status-active {
  background: rgb(from var(--color-af-teal) r g b / 0.12);
  color: var(--color-af-teal);
  border: 1px solid rgb(from var(--color-af-teal) r g b / 0.25);
}
.tp__badge--status-revoked {
  background: rgb(from var(--color-af-red) r g b / 0.12);
  color: var(--color-af-red);
  border: 1px solid rgb(from var(--color-af-red) r g b / 0.25);
}
.tp__badge--status-expired {
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
  color: var(--color-af-label);
  margin: 0 0 0.5rem;
}
.tp__empty-body {
  font-size: 0.875rem;
  color: var(--color-af-dim);
  margin: 0;
}

.tp__gap-note {
  font-size: 0.75rem;
  color: var(--color-af-dim);
  line-height: 1.6;
  margin: 0;
}
.tp__gap-note a {
  color: var(--color-af-teal);
}

/* "Use from the command line" (issue #122) */
.tp__cli {
  border: 1px solid var(--color-af-border);
  border-radius: 4px;
  padding: 1rem;
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
}
.tp__cli-heading--top {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.75rem;
  font-weight: 600;
  letter-spacing: 0.04em;
  color: var(--color-af-text);
  margin: 0;
}
.tp__cli-intro {
  font-size: 0.8125rem;
  color: var(--color-af-dim);
  line-height: 1.6;
  margin: 0;
}
.tp__cli-intro a {
  color: var(--color-af-teal);
}
.tp__cli-heading {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.75rem;
  font-weight: 600;
  letter-spacing: 0.04em;
  color: var(--color-af-dim);
  margin: 0.25rem 0 0;
}
.tp__cli-snippet {
  display: flex;
  align-items: flex-start;
  gap: 0.625rem;
}
.tp__cli-pre {
  flex: 1;
  min-width: 0;
  margin: 0;
  padding: 0.75rem;
  background: var(--color-af-void);
  border: 1px solid var(--color-af-muted);
  border-radius: 4px;
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.75rem;
  color: var(--color-af-text);
  white-space: pre-wrap;
  word-break: break-word;
  overflow-x: auto;
}
.tp__cli-note {
  font-size: 0.75rem;
  color: var(--color-af-dim);
  line-height: 1.6;
  margin: 0;
}

/* Buttons (shared shape with IdentityLink.vue) */
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

.tp__btn--confirm-revoke {
  background: rgb(from var(--color-af-red) r g b / 0.1);
  color: var(--color-af-red);
  border-color: rgb(from var(--color-af-red) r g b / 0.3);
}
.tp__btn--confirm-revoke:hover {
  background: rgb(from var(--color-af-red) r g b / 0.18);
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
  color: var(--color-af-dim);
}

/* Capability PATs (issue #144 step 4) -- "Restrict capabilities" toggle and
 * the checkbox list it reveals. */
.tp__checkbox-row {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  cursor: pointer;
}
.tp__checkbox {
  accent-color: var(--color-af-teal);
  width: 1rem;
  height: 1rem;
  flex-shrink: 0;
}
.tp__checkbox-label {
  text-transform: none;
  letter-spacing: 0.02em;
}
.tp__scope-hint {
  font-size: 0.75rem;
  color: var(--color-af-dim);
  line-height: 1.5;
  margin: 0.375rem 0 0;
}
.tp__scope-fieldset {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
  margin: 0.625rem 0 0;
  padding: 0.75rem;
  border: 1px solid var(--color-af-muted);
  border-radius: 4px;
}
.tp__scope-cap-name {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.8125rem;
  color: var(--color-af-text);
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

.tp__textarea {
  font-family: 'IBM Plex Sans', system-ui, sans-serif;
  resize: vertical;
}
.tp__input:disabled,
.tp__select:disabled {
  opacity: 0.5;
}

/* Modal — the native <dialog> element centers itself when opened via
 * showModal(), via the UA stylesheet's `margin: auto` on `dialog:modal`
 * (restored in global.css, where Tailwind's Preflight otherwise zeroes it
 * out -- see the comment there and issue #152). Here we only override the
 * box chrome and add our own ::backdrop with the AF ground tint.
 */
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
  color: var(--color-af-dim);
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

/* "Register with Claude Code" one-liner (issue #152) -- reuses
 * .tp__token-box/.tp__token-value/.tp__btn--copy for the same copy-target
 * shape as the raw token above it. */
.tp__claude-add-label {
  margin: 0 0 0.375rem;
}

.tp__claude-add-warn {
  font-size: 0.75rem;
  color: var(--color-af-dim);
  line-height: 1.6;
  margin: 0 0 1.25rem;
}
.tp__claude-add-warn code {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.6875rem;
  color: var(--color-af-dim);
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
  color: var(--color-af-dim);
}

@media (max-width: 640px) {
  .tp__toolbar {
    justify-content: stretch;
  }
  .tp__toolbar .tp__btn {
    width: 100%;
    justify-content: center;
  }
  /* Hide the columns that matter least for a quick glance or a revoke
     decision -- same hide-secondary-columns-not-horizontal-scroll pattern
     BackendCard.vue already uses. Name/Scope identify the token, Expires/
     Status are what you'd act on; Token ID/Created/Last used are dropped
     rather than forcing horizontal scroll for them. */
  .tp__th--secondary,
  .tp__td--secondary {
    display: none;
  }
}
</style>
