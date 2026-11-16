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
 * MintTokenDialog.vue's `mintedToken` for the lifetime of the mint dialog. It is cleared the moment
 * the dialog closes (Done, ESC, or backdrop click all fire the native
 * `close` event) and is never written back into the token list — the list
 * always comes from GET /v1/tokens, which never echoes a token value.
 */
import { ref, computed, onMounted } from 'vue';
import { Plus } from '@lucide/vue';
import { listTokens, revokeToken, deleteTokenRecord, clearInactiveTokens } from '../lib/api';
import type { TokenSummary } from '../lib/api';
import { EXPIRY_WARNING_DAYS, expiresIn, expiresSoon, tokenStatus } from '../lib/tokenDisplay';
import { errorMessage } from '../lib/apiError';
import { getBrokerOrigin } from '../lib/auth';
import { useLoadState } from '../lib/useLoadState';
import AsyncState from './ui/AsyncState.vue';
import ConfirmDialog from './ui/ConfirmDialog.vue';
import MintTokenDialog from './MintTokenDialog.vue';
import TokenCliSnippets from './TokenCliSnippets.vue';
import TokenList from './TokenList.vue';

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

// ── Expiry warning ───────────────────────────────────────────────────────
// Soonest first, so the banner names the most urgent token.
const expiringTokens = computed(() =>
  tokens.value
    .filter((row) => expiresSoon(row))
    .sort((a, b) => Date.parse(a.expires_at!) - Date.parse(b.expires_at!)),
);

// The mint dialog owns its form and the one-time token reveal.
const mintDialog = ref<InstanceType<typeof MintTokenDialog> | null>(null);

function openMintDialog(evt: Event) {
  mintDialog.value?.open(evt.currentTarget as HTMLButtonElement);
}

// Empty until onMounted resolves it -- never read `window` at setup() time,
// since Astro prerenders this component server-side (client:load) where
// there is no window (see the build's SSR pass). Shared by the mint dialog and
// the command-line snippets.
const brokerOrigin = ref('');
onMounted(async () => {
  brokerOrigin.value = await getBrokerOrigin();
});

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
    revokeError.value = errorMessage(err, 'Could not revoke the token.');
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
    deleteError.value = errorMessage(err, 'Could not delete the token.');
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
    deleteError.value = errorMessage(err, 'Could not clear the tokens.');
  } finally {
    clearing.value = false;
  }
}
</script>

<template>
  <div class="af-page af-wide tp">
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

        <TokenList
          :tokens="sortedTokens"
          :revoking-lookup-id="revokingLookupId"
          :deleting-lookup-id="deletingLookupId"
          @revoke="openRevokeConfirm"
          @delete="handleDelete"
        />
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

    <TokenCliSnippets :broker-origin="brokerOrigin" />

    <MintTokenDialog ref="mintDialog" :broker-origin="brokerOrigin" @done="loadTokens" />

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
</style>
