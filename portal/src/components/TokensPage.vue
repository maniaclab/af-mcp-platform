<script setup lang="ts">
/**
 * TokensPage.vue — mints broker-issued identity PATs for programmatic MCP
 * clients (issue #144 step 2a), backed by a durable, HA-safe registry with
 * enforced revocation. Interactive browser use never touches this page —
 * the portal's own OIDC login (see ../lib/auth.ts, docs/auth.md) handles that
 * transparently. This page exists for clients like Claude Desktop that can't
 * do OAuth discovery yet.
 *
 * CRITICAL SECURITY NOTE: the minted token value only ever lives in
 * `mintedToken` for the lifetime of the mint dialog. It is cleared the moment
 * the dialog closes (Done, ESC, or backdrop click all fire the native
 * `close` event) and is never written back into the token list — the list
 * always comes from GET /v1/tokens, which never echoes a token value.
 */
import { ref, computed, onBeforeUnmount, onMounted, nextTick } from 'vue';
import { Check, Copy, Plus } from '@lucide/vue';
import { mintToken, listTokens, revokeToken, fetchPermissions } from '../lib/api';
import type { MintedToken, TokenSummary } from '../lib/api';
import {
  EXPIRY_WARNING_DAYS,
  NOTE_MAX_LENGTH,
  expiresIn,
  expiresSoon,
  permissionGrantLabel,
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
import { copyText } from '../lib/clipboard';
import { formatDateTime, formatRelative } from '../lib/relativeTime';
import { useLoadState } from '../lib/useLoadState';
import AsyncState from './ui/AsyncState.vue';
import ConfirmDialog from './ui/ConfirmDialog.vue';
import CopyField from './ui/CopyField.vue';
import Disclosure from './ui/Disclosure.vue';
import InfoTip from './ui/InfoTip.vue';
import StatusMark from './ui/StatusMark.vue';

const tokens = ref<TokenSummary[]>([]);
const { loading, error, sessionExpired, accessDenied, run } = useLoadState();

const sortedTokens = computed(() =>
  [...tokens.value].sort((a, b) => Date.parse(b.created_at) - Date.parse(a.created_at)),
);

function loadTokens() {
  return run(async () => {
    tokens.value = await listTokens();
  }, 'Could not load tokens.');
}

onMounted(loadTokens);

// ── Token ID copy ────────────────────────────────────────────────────────
// The cell shows only the start of the id; the button copies all of it and
// swaps its icon for a check mark for a moment.
const COPIED_RESET_MS = 2000;
const copiedId = ref<string | null>(null);
let copiedTimer: ReturnType<typeof setTimeout> | undefined;

async function copyTokenId(lookupId: string): Promise<void> {
  if (!(await copyText(lookupId))) return;
  copiedId.value = lookupId;
  clearTimeout(copiedTimer);
  copiedTimer = setTimeout(() => (copiedId.value = null), COPIED_RESET_MS);
}

onBeforeUnmount(() => clearTimeout(copiedTimer));

// ── Expiry warning ───────────────────────────────────────────────────────
// Soonest first, so the banner names the most urgent token.
const expiringTokens = computed(() =>
  tokens.value
    .filter((row) => expiresSoon(row))
    .sort((a, b) => Date.parse(a.expires_at!) - Date.parse(b.expires_at!)),
);

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

// ── Permission PATs (issue #144 step 4) ─────────────────────────────────
// `availablePermissions` is the caller's CURRENT permissions (GET
// /v1/permissions), fetched once on mount -- never a static list, since
// the whole point of a permission PAT is that it can only ever narrow what
// its owner already holds *right now*. `restrictPermissions` is the mint
// form's opt-in: unchecked (the default) mints an ordinary identity PAT,
// exactly as before this field existed; checked reveals the checkbox list
// below and mints a permission PAT scoped to whatever's selected.
const availablePermissions = ref<string[]>([]);
const restrictPermissions = ref(false);
const selectedPermissions = ref<Set<string>>(new Set());

onMounted(async () => {
  try {
    const { grants } = await fetchPermissions();
    availablePermissions.value = grants.map((g) => g.permission).sort();
  } catch {
    // Best-effort: if this fails, the mint dialog simply offers no
    // permission restriction (identity PATs remain fully mintable, which
    // is the more important path to keep working) rather than blocking
    // the page load or the dialog itself over a secondary feature.
    availablePermissions.value = [];
  }
});

function toggleSelectedPermission(permission: string, checked: boolean) {
  if (checked) {
    selectedPermissions.value.add(permission);
  } else {
    selectedPermissions.value.delete(permission);
  }
}

async function openMintDialog(evt: Event) {
  mintTrigger.value = evt.currentTarget as HTMLButtonElement;
  mintedToken.value = null;
  mintError.value = null;
  name.value = '';
  note.value = '';
  expiryOption.value = '90';
  restrictPermissions.value = false;
  selectedPermissions.value = new Set();
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
      restrictPermissions.value ? [...selectedPermissions.value] : undefined,
    );
  } catch (err) {
    // Includes the 409 duplicate-name case (api/tokens.py's DuplicateNameError)
    // -- APIError's message already carries the broker's `detail` text.
    mintError.value = err instanceof Error ? err.message : 'Could not create the token. Try again.';
  } finally {
    minting.value = false;
  }
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
const cliOpen = ref(false);

// "Register as an MCP client" one-liner shown alongside the raw token in
// the "Token created" step above (issue #152) -- reuses the same
// brokerOrigin this section resolves. Only ever constructible from
// `mintedToken`, which onMintDialogClose scrubs the moment the dialog
// closes -- like the token itself, this is never reconstructable from the
// list view, since the secret is never retained server-side.
const claudeAddCommand = computed(() =>
  mintedToken.value ? claudeMcpAddSnippet(brokerOrigin.value, mintedToken.value.token) : '',
);

// "Request headers" value for Claude (Claude.ai, Claude Desktop) clients that
// predate OAuth discovery -- see docs/connecting-a-client.md's "Claude
// (Claude.ai, Claude Desktop)" section: Name "Authorization", Value
// "Bearer <token>", entered in the custom connector's own Request headers
// field. Same lifetime as claudeAddCommand above -- only ever constructible
// from `mintedToken`, scrubbed the moment the dialog closes.
const claudeHeaderValue = computed(() =>
  mintedToken.value ? `Bearer ${mintedToken.value.token}` : '',
);

// ── Revoke ───────────────────────────────────────────────────────────────
const revokingLookupId = ref<string | null>(null);
const revokeError = ref<string | null>(null);

// Revoke confirmation -- ConfirmDialog supplies the native <dialog> focus
// trap, ESC to close, Cancel-first focus and focus restore to the row's
// button, like IdentityLink.vue's revoke-confirm and unlink-confirm.
const revokeConfirmOpen = ref(false);
const pendingRevoke = ref<{ lookupId: string; name: string } | null>(null);

function openRevokeConfirm(lookupId: string, name: string) {
  pendingRevoke.value = { lookupId, name };
  revokeConfirmOpen.value = true;
}

async function handleRevoke() {
  if (!pendingRevoke.value) return;
  const { lookupId } = pendingRevoke.value;
  revokeConfirmOpen.value = false;
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
    revokeError.value = err instanceof Error ? err.message : 'Could not revoke the token.';
  } finally {
    revokingLookupId.value = null;
  }
}

// ── Formatting ───────────────────────────────────────────────────────────
function formatRelativeIso(iso: string): string {
  return formatRelative(Date.parse(iso));
}

function formatExact(iso: string): string {
  return formatDateTime(new Date(iso), { year: true });
}

const statusLabel: Record<ReturnType<typeof tokenStatus>, string> = {
  active: 'Active',
  revoked: 'Revoked',
  expired: 'Expired',
};
</script>

<template>
  <div class="af-page tp">
    <div class="af-page-head">
      <div>
        <h1>Tokens</h1>
        <p>Create and revoke tokens for clients that can't sign in with a browser.</p>
      </div>
      <button
        v-if="loading || tokens.length > 0 || error || sessionExpired || accessDenied"
        type="button"
        class="af-btn primary"
        @click="openMintDialog"
      >
        <Plus class="af-icon" :size="16" aria-hidden="true" />
        New token
      </button>
    </div>

    <!-- Banner slot: a failed revoke beats an expiring token. -->
    <div v-if="revokeError" class="af-banner bad" role="alert">
      <span class="af-mark bad" aria-hidden="true"></span>
      <div>
        <b>Revoke failed</b>
        {{ revokeError }}
      </div>
    </div>
    <div v-else-if="expiringTokens.length > 0" class="af-banner warn">
      <span class="af-mark warn" aria-hidden="true"></span>
      <div>
        <b>{{ expiringTokens[0].name }} expires {{ expiresIn(expiringTokens[0].expires_at!) }}</b>
        Create a replacement and update the client.
        <template v-if="expiringTokens.length > 1">
          {{ expiringTokens.length - 1 }} other
          {{ expiringTokens.length === 2 ? 'token expires' : 'tokens expire' }} within
          {{ EXPIRY_WARNING_DAYS }} days.
        </template>
      </div>
      <button type="button" class="af-btn s" @click="openMintDialog">New token</button>
    </div>

    <section class="af-sect" aria-labelledby="tp-list-heading">
      <h2 id="tp-list-heading">Your tokens</h2>
      <AsyncState
        :loading="loading"
        :error="error"
        error-title="Could not load tokens"
        :session-expired="sessionExpired"
        :access-denied="accessDenied"
        :empty="sortedTokens.length === 0"
        loading-label="Loading tokens…"
      >
        <template #empty>
          <b>No tokens yet</b>
          <p>
            Tokens let clients that can't sign in with a browser, such as Claude Desktop, reach the
            gateway as you. Most clients don't need one: they sign in themselves the first time you
            connect them.
          </p>
          <button type="button" class="af-btn primary" @click="openMintDialog">
            <Plus class="af-icon" :size="16" aria-hidden="true" />
            New token
          </button>
        </template>

        <div class="af-tbl-box" role="region" aria-label="Issued tokens" tabindex="0">
          <table class="af-tbl" aria-label="Your issued tokens">
            <thead>
              <tr>
                <th scope="col">Name</th>
                <th scope="col">Status</th>
                <th scope="col">Scope</th>
                <th scope="col">Token ID</th>
                <th scope="col">Created</th>
                <th scope="col">Expires</th>
                <th scope="col">Last used</th>
                <th scope="col" class="act"><span class="sr-only">Actions</span></th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="row in sortedTokens" :key="row.lookup_id">
                <td>
                  <div class="tp__name">
                    <span>{{ row.name }}</span>
                    <InfoTip
                      v-if="row.note"
                      :id="`tp-note-${row.lookup_id}`"
                      :text="truncateNote(row.note) ?? ''"
                      label="Show note"
                    />
                  </div>
                </td>
                <td>
                  <StatusMark
                    v-if="expiresSoon(row)"
                    tone="warn"
                    :label="`Expires ${expiresIn(row.expires_at!)}`"
                  />
                  <StatusMark
                    v-else
                    :tone="tokenStatus(row) === 'active' ? 'ok' : 'off'"
                    :label="statusLabel[tokenStatus(row)]"
                  />
                </td>
                <td class="sub tp__scope">{{ permissionGrantLabel(row.permission_grant) }}</td>
                <td class="sub tp__id" :title="row.lookup_id">
                  <span class="tp__idbox">
                    {{ shortLookupId(row.lookup_id) }}
                    <button
                      type="button"
                      class="af-btn quiet s tp__copy"
                      :aria-label="`Copy token ID ${row.lookup_id}`"
                      @click="copyTokenId(row.lookup_id)"
                    >
                      <Check
                        v-if="copiedId === row.lookup_id"
                        class="af-icon"
                        :size="16"
                        aria-hidden="true"
                      />
                      <Copy v-else class="af-icon" :size="16" aria-hidden="true" />
                    </button>
                  </span>
                </td>
                <td class="sub" :title="formatExact(row.created_at)">
                  {{ formatRelativeIso(row.created_at) }}
                </td>
                <td
                  class="sub"
                  :title="row.expires_at ? formatExact(row.expires_at) : 'Never expires'"
                >
                  {{ row.expires_at ? formatRelativeIso(row.expires_at) : 'Never' }}
                </td>
                <td
                  class="sub"
                  :title="row.last_used_at ? formatExact(row.last_used_at) : 'Never used'"
                >
                  {{ row.last_used_at ? formatRelativeIso(row.last_used_at) : 'Never' }}
                </td>
                <td class="act">
                  <button
                    type="button"
                    class="af-btn danger s"
                    :aria-label="`Revoke ${row.name}`"
                    :disabled="revokingLookupId === row.lookup_id || tokenStatus(row) !== 'active'"
                    @click="openRevokeConfirm(row.lookup_id, row.name)"
                  >
                    {{ revokingLookupId === row.lookup_id ? 'Revoking…' : 'Revoke' }}
                  </button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </AsyncState>
    </section>

    <div class="af-note info">
      <span class="af-mark info" aria-hidden="true"></span>
      <span>
        A token only grants access to the AF MCP platform. It is not the same as your identities
        with Rucio, CERN or other backend systems; see the
        <a href="/identities/">Identities page</a> for those. This list shows tokens created on this
        page, or automatically when you connect an MCP client. See
        <a
          href="https://maniaclab.github.io/af-mcp-platform/auth/"
          target="_blank"
          rel="noopener noreferrer"
          >Authentication</a
        >
        for the full credential model.
      </span>
    </div>

    <!-- issue #122: copy-paste snippets for creating/using a token outside the browser. -->
    <section class="af-sect" aria-labelledby="tp-cli-heading">
      <h2 id="tp-cli-heading">Use from the command line</h2>
      <p class="af-help">
        Create and use a token without opening a browser, for scripts or CI. See
        <a
          href="https://maniaclab.github.io/af-mcp-platform/connecting-a-client/"
          target="_blank"
          rel="noopener noreferrer"
          >Connecting a client</a
        >
        for the full setup guide.
      </p>
      <Disclosure v-model:open="cliOpen" label="Show curl and Python snippets">
        <div class="tp__cli">
          <h3 class="tp__label">Create a token with curl</h3>
          <CopyField :value="curlSnippet" label="Copy curl snippet" multiline />

          <h3 class="tp__label">Create a token and connect from Python</h3>
          <CopyField :value="pythonSnippet" label="Copy Python snippet" multiline />

          <p class="af-help">
            A token created this way appears in the list above like any other, with a name, an
            expiry and a <strong>Revoke</strong> action.
          </p>
        </div>
      </Disclosure>
    </section>

    <!-- New token dialog -->
    <dialog
      ref="mintDialog"
      class="af-dialog tp__dialog"
      aria-labelledby="tp-modal-title"
      @close="onMintDialogClose"
    >
      <template v-if="!mintedToken">
        <h4 id="tp-modal-title">New token</h4>
        <p class="af-help">
          A personal access token is a long-lived credential you paste into a client's config, such
          as Claude Desktop, that can't sign in with a browser. It is shown once, so copy it before
          you close this dialog.
        </p>

        <form class="tp__form" novalidate @submit.prevent="handleMint">
          <div class="af-field">
            <label for="tp-ttl">Expires after</label>
            <select id="tp-ttl" v-model="expiryOption" class="af-input" :disabled="minting">
              <option value="30">30 days</option>
              <option value="90">90 days (default)</option>
              <option value="365">1 year</option>
              <option value="never">Never expires</option>
            </select>
          </div>

          <div class="af-field">
            <label for="tp-name">Name (optional)</label>
            <input
              id="tp-name"
              v-model="name"
              type="text"
              class="af-input"
              placeholder="e.g. claude-desktop"
              maxlength="200"
              :disabled="minting"
            />
          </div>

          <div class="af-field">
            <label for="tp-note">Note (optional)</label>
            <textarea
              id="tp-note"
              v-model="note"
              class="af-input tp__textarea"
              placeholder="e.g. used by the CI bot for nightly runs"
              :maxlength="NOTE_MAX_LENGTH"
              rows="2"
              :disabled="minting"
            ></textarea>
          </div>

          <!-- Permission PATs (issue #144 step 4): optional restriction below
               the caller's own CURRENT permissions. Hidden entirely when
               availablePermissions is empty (e.g. the /v1/permissions fetch
               failed) -- an identity PAT remains mintable regardless. -->
          <div v-if="availablePermissions.length > 0" class="af-field">
            <label class="af-check">
              <input v-model="restrictPermissions" type="checkbox" :disabled="minting" />
              Restrict permissions (optional)
            </label>
            <span class="hint">
              Leave this unchecked for a token with your full account access. Check it to limit the
              token to the permissions you select below, which suits CI or scripts.
            </span>
            <fieldset v-if="restrictPermissions" class="tp__perms">
              <legend class="sr-only">Permissions to grant</legend>
              <label v-for="cap in availablePermissions" :key="cap" class="af-check">
                <input
                  type="checkbox"
                  :checked="selectedPermissions.has(cap)"
                  :disabled="minting"
                  @change="
                    toggleSelectedPermission(cap, ($event.target as HTMLInputElement).checked)
                  "
                />
                {{ cap }}
              </label>
            </fieldset>
          </div>

          <div v-if="mintError" class="af-note bad" role="alert">
            <span class="af-mark bad" aria-hidden="true"></span>
            <span>{{ mintError }}</span>
          </div>

          <footer>
            <button type="button" class="af-btn quiet" @click="mintDialog?.close()">Cancel</button>
            <button type="submit" class="af-btn primary" :disabled="minting" :aria-busy="minting">
              {{ minting ? 'Creating…' : 'Create token' }}
            </button>
          </footer>
        </form>
      </template>

      <template v-else>
        <h4 id="tp-modal-title">Token created</h4>

        <div class="af-note warn" role="alert">
          <span class="af-mark warn" aria-hidden="true"></span>
          <span>This is the only time this token is shown. Copy it now.</span>
        </div>

        <CopyField :value="mintedToken.token" label="Copy token" multiline />

        <h3 class="tp__label">Claude (Claude.ai, Claude Desktop) without OAuth support</h3>
        <CopyField :value="claudeHeaderValue" label="Copy request header value" multiline />
        <p class="af-help">
          In the custom connector's <strong>Request headers</strong>, add name
          <code>Authorization</code> and paste the value above. Skip this if your client supports
          OAuth discovery: add just the server URL instead and it authenticates itself.
        </p>

        <h3 class="tp__label">Register with Claude Code</h3>
        <CopyField :value="claudeAddCommand" label="Copy Claude Code command" multiline />
        <p class="af-help">
          This command embeds the token above, so pasting it into a terminal puts a working
          credential in your shell history. For the safer pattern (token read into an env var via
          <code>read -s</code>, never a literal), see the <strong>Claude Code</strong> section of
          <code>docs/connecting-a-client.md</code>.
        </p>

        <dl class="af-kv">
          <dt>Name</dt>
          <dd>{{ mintedToken.name }}</dd>
          <template v-if="mintedToken.note">
            <dt>Note</dt>
            <dd>{{ mintedToken.note }}</dd>
          </template>
          <dt>Scope</dt>
          <dd>{{ permissionGrantLabel(mintedToken.permission_grant) }}</dd>
          <dt>Expires</dt>
          <dd>{{ mintedToken.expires_at ? formatExact(mintedToken.expires_at) : 'Never' }}</dd>
        </dl>

        <footer>
          <button type="button" class="af-btn primary" @click="handleDone">Done</button>
        </footer>
      </template>
    </dialog>

    <ConfirmDialog
      v-model:open="revokeConfirmOpen"
      :title="pendingRevoke ? `Revoke &quot;${pendingRevoke.name}&quot;?` : ''"
      confirm-label="Revoke token"
      busy-label="Revoking…"
      danger
      :busy="revokingLookupId !== null"
      @confirm="handleRevoke"
    >
      <p>Clients using this token stop working immediately. This cannot be undone.</p>
    </ConfirmDialog>
  </div>
</template>

<style scoped>
.tp__label {
  margin: 0;
  font-size: var(--text-13);
  font-weight: 500;
}

.tp__name {
  display: flex;
  align-items: center;
  gap: var(--space-4);
}

.tp__id {
  font-family: var(--font-mono);
}

.tp__idbox {
  display: inline-flex;
  align-items: center;
  gap: var(--space-4);
}

.tp__copy {
  height: var(--space-24);
  padding: 0 var(--space-4);
}

/* A scope can list several permissions; let it wrap instead of widening the table. */
.tp__scope {
  white-space: normal;
  min-width: 10rem;
}

.tp__cli {
  display: flex;
  flex-direction: column;
  gap: var(--space-12);
}

.tp__dialog {
  width: min(100%, 560px);
}

.tp__form {
  display: flex;
  flex-direction: column;
  gap: var(--space-16);
}

.tp__dialog .af-field {
  max-width: none;
}

.tp__textarea {
  height: auto;
  padding-block: var(--space-8);
  resize: vertical;
}

.tp__perms {
  display: flex;
  flex-direction: column;
  gap: var(--space-8);
  margin: 0;
  padding: 0;
  border: 0;
}
</style>
