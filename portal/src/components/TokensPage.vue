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
import {
  mintToken,
  listTokens,
  revokeToken,
  deleteTokenRecord,
  clearInactiveTokens,
  fetchPermissions,
} from '../lib/api';
import type { MintedToken, PermissionGrant, TokenSummary } from '../lib/api';
import {
  EXPIRY_WARNING_DAYS,
  NOTE_MAX_LENGTH,
  expiresIn,
  expiresSoon,
  permissionGrantIdentifiers,
  permissionGrantLabel,
  shortLookupId,
  tokenStatus,
  truncateNote,
} from '../lib/tokenDisplay';
import { permissionLabel } from '../lib/permissionLabel';
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
// `availableGrants` is the caller's CURRENT permissions (GET
// /v1/permissions), fetched once on mount -- never a static list, since
// the whole point of a permission PAT is that it can only ever narrow what
// its owner already holds *right now*. `restrictPermissions` is the mint
// form's opt-in: unchecked (the default) mints an ordinary identity PAT,
// exactly as before this field existed; checked reveals the checkbox list
// below and mints a permission PAT scoped to whatever's selected.
const availableGrants = ref<PermissionGrant[]>([]);
const restrictPermissions = ref(false);
const selectedPermissions = ref<Set<string>>(new Set());

onMounted(async () => {
  try {
    const { grants } = await fetchPermissions();
    availableGrants.value = grants;
  } catch {
    // Best-effort: if this fails, the mint dialog simply offers no
    // permission restriction (identity PATs remain fully mintable, which
    // is the more important path to keep working) rather than blocking
    // the page load or the dialog itself over a secondary feature.
    availableGrants.value = [];
  }
});

// The picker lists read permissions apart from state-changing ones, each group
// sorted by name, and leaves out a group with nothing in it. A grant belongs
// to the state-changing group when the broker reports any state-changing
// action type for it, so the grouping rests on broker data alone.
const PERMISSION_GROUPS: { kind: 'read' | 'write'; label: string }[] = [
  { kind: 'read', label: 'Read' },
  { kind: 'write', label: 'State-changing' },
];

const permissionGroups = computed(() =>
  PERMISSION_GROUPS.map(({ kind, label }) => ({
    kind,
    label,
    permissions: availableGrants.value
      .filter((g) => (g.action_types.includes('state_change') ? 'write' : 'read') === kind)
      .map((g) => g.permission)
      .sort(),
  })).filter((group) => group.permissions.length > 0),
);

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

// ── Delete revoked and expired rows ──────────────────────────────────────
// Revoking keeps a tombstone row, so dead rows pile up; the broker deletes
// them only once they are revoked or expired. A single row is deleted without
// a confirmation (the token already stopped working); clearing them all asks
// first, since it removes a whole history in one click.
const deletingLookupId = ref<string | null>(null);
const clearing = ref(false);
const deleteError = ref<string | null>(null);
const clearConfirmOpen = ref(false);

const inactiveTokens = computed(() => tokens.value.filter((t) => tokenStatus(t) !== 'active'));

async function handleDelete(lookupId: string) {
  deletingLookupId.value = lookupId;
  deleteError.value = null;
  try {
    await deleteTokenRecord(lookupId);
    tokens.value = tokens.value.filter((t) => t.lookup_id !== lookupId);
  } catch (err) {
    deleteError.value = err instanceof Error ? err.message : 'Could not delete the token.';
  } finally {
    deletingLookupId.value = null;
  }
}

async function handleClear() {
  clearing.value = true;
  deleteError.value = null;
  try {
    await clearInactiveTokens();
    clearConfirmOpen.value = false;
    tokens.value = tokens.value.filter((t) => tokenStatus(t) === 'active');
  } catch (err) {
    clearConfirmOpen.value = false;
    deleteError.value = err instanceof Error ? err.message : 'Could not clear the tokens.';
  } finally {
    clearing.value = false;
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
        class="btn"
        @click="openMintDialog"
      >
        <Plus class="af-icon" :size="16" aria-hidden="true" />
        New token
      </button>
    </div>

    <!-- Banner slot: a failed revoke beats an expiring token. -->
    <div v-if="revokeError" class="alert af-banner bad" role="alert">
      <span class="af-mark bad" aria-hidden="true"></span>
      <div>
        <b>Revoke failed</b>
        {{ revokeError }}
      </div>
    </div>
    <div v-else-if="deleteError" class="alert af-banner bad" role="alert">
      <span class="af-mark bad" aria-hidden="true"></span>
      <div>
        <b>Delete failed</b>
        {{ deleteError }}
      </div>
    </div>
    <div v-else-if="expiringTokens.length > 0" class="alert af-banner warn" role="alert">
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
      <button
        type="button"
        class="btn"
        data-variant="outline"
        data-size="sm"
        @click="openMintDialog"
      >
        New token
      </button>
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
          <header>
            <h3>No tokens yet</h3>
            <p>
              Tokens let clients that can't sign in with a browser, such as Claude Desktop, reach
              the gateway as you. Most clients don't need one: they sign in themselves the first
              time you connect them.
            </p>
          </header>
          <section>
            <button type="button" class="btn" @click="openMintDialog">
              <Plus class="af-icon" :size="16" aria-hidden="true" />
              New token
            </button>
          </section>
        </template>

        <div class="table-container af-box" role="region" aria-label="Issued tokens" tabindex="0">
          <table class="table" aria-label="Your issued tokens">
            <thead>
              <tr>
                <th scope="col">Name</th>
                <th scope="col">Status</th>
                <th scope="col">Scope</th>
                <th scope="col">Expires</th>
                <th scope="col">Last used</th>
                <th scope="col" class="af-act af-sticky"><span class="sr-only">Actions</span></th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="row in sortedTokens" :key="row.lookup_id">
                <td class="tp__namecell">
                  <div class="tp__name">
                    <span>{{ row.name }}</span>
                    <InfoTip
                      v-if="row.note"
                      :id="`tp-note-${row.lookup_id}`"
                      :text="truncateNote(row.note) ?? ''"
                      label="Show note"
                    />
                  </div>
                  <!-- The id and creation time are secondary facts about the
                       token, so they sit under its name rather than in columns
                       of their own, which kept the table wider than the page. -->
                  <div class="af-sub tp__meta">
                    <span :title="formatExact(row.created_at)">
                      Created {{ formatRelativeIso(row.created_at) }}
                    </span>
                    <span class="tp__idbox" :title="row.lookup_id">
                      ID <code>{{ shortLookupId(row.lookup_id) }}</code>
                      <button
                        type="button"
                        class="btn tp__copy"
                        data-variant="ghost"
                        data-size="icon-sm"
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
                <td
                  class="af-sub tp__scope"
                  :title="permissionGrantIdentifiers(row.permission_grant)"
                >
                  {{ permissionGrantLabel(row.permission_grant) }}
                </td>
                <td
                  class="af-sub"
                  :title="row.expires_at ? formatExact(row.expires_at) : 'Never expires'"
                >
                  {{ row.expires_at ? formatRelativeIso(row.expires_at) : 'Never' }}
                </td>
                <td
                  class="af-sub"
                  :title="row.last_used_at ? formatExact(row.last_used_at) : 'Never used'"
                >
                  {{ row.last_used_at ? formatRelativeIso(row.last_used_at) : 'Never' }}
                </td>
                <td class="af-act af-sticky">
                  <button
                    v-if="tokenStatus(row) === 'active'"
                    type="button"
                    class="btn af-danger"
                    data-variant="outline"
                    data-size="sm"
                    :aria-label="`Revoke ${row.name}`"
                    :disabled="revokingLookupId === row.lookup_id"
                    @click="openRevokeConfirm(row.lookup_id, row.name)"
                  >
                    {{ revokingLookupId === row.lookup_id ? 'Revoking…' : 'Revoke' }}
                  </button>
                  <button
                    v-else
                    type="button"
                    class="btn"
                    data-variant="outline"
                    data-size="sm"
                    :aria-label="`Delete ${row.name}`"
                    :disabled="deletingLookupId === row.lookup_id"
                    @click="handleDelete(row.lookup_id)"
                  >
                    {{ deletingLookupId === row.lookup_id ? 'Deleting…' : 'Delete' }}
                  </button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
        <div v-if="inactiveTokens.length > 0" class="tp__clearbar">
          <button
            type="button"
            class="btn tp__clear"
            data-variant="outline"
            data-size="sm"
            @click="clearConfirmOpen = true"
          >
            Clear revoked and expired ({{ inactiveTokens.length }})
          </button>
        </div>
      </AsyncState>
    </section>

    <div class="alert af-note info">
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
      class="dialog af-modal"
      aria-labelledby="tp-modal-title"
      @close="onMintDialogClose"
    >
      <form v-if="!mintedToken" class="tp__panel" novalidate @submit.prevent="handleMint">
        <header>
          <h2 id="tp-modal-title">New token</h2>
          <p>
            A personal access token is a long-lived credential you paste into a client's config,
            such as Claude Desktop, that can't sign in with a browser. It is shown once, so copy it
            before you close this dialog.
          </p>
        </header>

        <section class="tp__fields">
          <div class="field">
            <label for="tp-ttl">Expires after</label>
            <select id="tp-ttl" v-model="expiryOption" class="select w-full" :disabled="minting">
              <option value="30">30 days</option>
              <option value="90">90 days (default)</option>
              <option value="365">1 year</option>
              <option value="never">Never expires</option>
            </select>
          </div>

          <div class="field">
            <label for="tp-name">Name (optional)</label>
            <input
              id="tp-name"
              v-model="name"
              type="text"
              class="input"
              placeholder="e.g. claude-desktop"
              maxlength="200"
              :disabled="minting"
            />
          </div>

          <div class="field">
            <label for="tp-note">Note (optional)</label>
            <textarea
              id="tp-note"
              v-model="note"
              class="textarea tp__textarea"
              placeholder="e.g. used by the CI bot for nightly runs"
              :maxlength="NOTE_MAX_LENGTH"
              rows="2"
              :disabled="minting"
            ></textarea>
          </div>

          <!-- Permission PATs (issue #144 step 4): optional restriction below
               the caller's own CURRENT permissions. Hidden entirely when
               availableGrants is empty (e.g. the /v1/permissions fetch
               failed) -- an identity PAT remains mintable regardless. -->
          <div v-if="availableGrants.length > 0" class="field">
            <div class="field" data-orientation="horizontal">
              <input
                id="tp-restrict"
                v-model="restrictPermissions"
                type="checkbox"
                class="input"
                :disabled="minting"
              />
              <label for="tp-restrict">Restrict permissions (optional)</label>
            </div>
            <p>
              Leave this unchecked for a token with your full account access. Check it to limit the
              token to the permissions you select below, which suits CI or scripts.
            </p>
            <div v-if="restrictPermissions" class="tp__permgrid">
              <fieldset v-for="group in permissionGroups" :key="group.kind" class="tp__perms">
                <legend>{{ group.label }}</legend>
                <div
                  v-for="cap in group.permissions"
                  :key="cap"
                  class="field"
                  data-orientation="horizontal"
                >
                  <input
                    :id="`tp-perm-${cap}`"
                    type="checkbox"
                    class="input"
                    :checked="selectedPermissions.has(cap)"
                    :disabled="minting"
                    @change="
                      toggleSelectedPermission(cap, ($event.target as HTMLInputElement).checked)
                    "
                  />
                  <label :for="`tp-perm-${cap}`" :title="cap">{{ permissionLabel(cap) }}</label>
                </div>
              </fieldset>
            </div>
          </div>

          <div v-if="mintError" class="alert af-note bad" role="alert">
            <span class="af-mark bad" aria-hidden="true"></span>
            <span>{{ mintError }}</span>
          </div>
        </section>

        <footer>
          <button type="button" class="btn" data-variant="ghost" @click="mintDialog?.close()">
            Cancel
          </button>
          <button type="submit" class="btn" :disabled="minting" :aria-busy="minting">
            {{ minting ? 'Creating…' : 'Create token' }}
          </button>
        </footer>
      </form>

      <div v-else class="tp__panel">
        <header>
          <h2 id="tp-modal-title">Token created</h2>
        </header>

        <section class="tp__fields">
          <div class="alert af-note warn" role="alert">
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
            <dd :title="permissionGrantIdentifiers(mintedToken.permission_grant)">
              {{ permissionGrantLabel(mintedToken.permission_grant) }}
            </dd>
            <dt>Expires</dt>
            <dd>{{ mintedToken.expires_at ? formatExact(mintedToken.expires_at) : 'Never' }}</dd>
          </dl>
        </section>

        <footer>
          <button type="button" class="btn" @click="handleDone">Done</button>
        </footer>
      </div>
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

    <ConfirmDialog
      v-model:open="clearConfirmOpen"
      :title="`Delete ${inactiveTokens.length} revoked and expired ${inactiveTokens.length === 1 ? 'token' : 'tokens'}?`"
      confirm-label="Delete"
      busy-label="Deleting…"
      danger
      :busy="clearing"
      @confirm="handleClear"
    >
      <p>
        They have already stopped working. This removes them from the list and cannot be undone.
        Active tokens are not affected.
      </p>
    </ConfirmDialog>
  </div>
</template>

<style scoped>
.tp__clearbar {
  display: flex;
  justify-content: flex-end;
}

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

.tp__namecell {
  max-width: 14rem;
  overflow-wrap: anywhere;
}

.tp__meta {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 0 var(--space-12);
  font-size: var(--text-12);
}

.tp__meta code {
  font-family: var(--font-mono);
}

.tp__idbox {
  display: inline-flex;
  align-items: center;
  gap: var(--space-4);
}

/* A scope can list several permissions; let it wrap between them, within a
   width range, instead of widening the table or breaking inside a name. */
.tp__scope {
  white-space: normal;
  min-width: 9rem;
  max-width: 12rem;
}

.tp__cli {
  display: flex;
  flex-direction: column;
  gap: var(--space-12);
}

/* The dialog panel is wider than Basecoat's default, and scrolls inside its
   own bounds when the form or the minted token outgrows a short window. */
.tp__panel {
  max-width: 40rem;
}

.tp__panel > section {
  min-height: 0;
  overflow-y: auto;
}

.tp__fields {
  display: flex;
  flex-direction: column;
  gap: var(--space-16);
}

.tp__textarea {
  resize: vertical;
}

/* Read and state-changing permissions are two labelled groups, each a grid
   that fills the dialog width, so a typical permission count fits a laptop
   window without scrolling inside the dialog. */
.tp__permgrid {
  display: flex;
  flex-direction: column;
  gap: var(--space-12);
}

.tp__perms {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(8.5rem, 1fr));
  gap: var(--space-8);
  margin: 0;
  padding: 0;
  border: 0;
}

.tp__perms legend {
  margin-bottom: var(--space-8);
  font-size: var(--text-13);
  color: var(--color-af-text-secondary);
}
</style>
