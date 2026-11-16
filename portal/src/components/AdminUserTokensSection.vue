<script setup lang="ts">
/**
 * AdminUserTokensSection.vue -- the admin page's "User tokens" panel.
 *
 * Pick a user with the UserPicker, see their tokens in TokenList (the table the
 * Tokens page renders), and revoke one token or all of the active ones, each
 * behind a ConfirmDialog. Revoking sets `revoked_at` on the broker, so the list
 * is fetched again afterwards rather than patched. An admin cannot delete
 * another user's rows (the broker has no such route), so the table offers no
 * Delete.
 */
import { computed, ref, watch } from 'vue';
import { listUserTokens, revokeAllUserTokens, revokeUserToken } from '../lib/api';
import type { AdminUser, TokenSummary } from '../lib/api';
import { errorMessage } from '../lib/apiError';
import { tokenStatus } from '../lib/tokenDisplay';
import { useAsyncAction } from '../lib/useAsyncAction';
import { useLoadState } from '../lib/useLoadState';
import AsyncState from './ui/AsyncState.vue';
import ConfirmDialog from './ui/ConfirmDialog.vue';
import TokenList from './TokenList.vue';
import UserPicker from './UserPicker.vue';

const selectedUser = ref<AdminUser | null>(null);
const tokens = ref<TokenSummary[]>([]);
const loadState = useLoadState();

/** Who the user is, for sentences: the display name, else the username, else the subject. */
const userName = computed(() => {
  const u = selectedUser.value;
  return u ? u.display_name || u.username || u.subject : '';
});
const activeTokens = computed(() => tokens.value.filter((t) => tokenStatus(t) === 'active'));

// Latest-wins: picking another user while a list is loading must not let the
// slower, earlier response replace the newer one.
let latestLoad = 0;

async function loadTokens(): Promise<void> {
  const user = selectedUser.value;
  if (!user) return;
  const loadNumber = ++latestLoad;
  await loadState.run(async () => {
    const rows = await listUserTokens(user.subject);
    if (loadNumber === latestLoad) tokens.value = rows;
  }, 'Failed to load tokens.');
}

watch(selectedUser, () => {
  tokens.value = [];
  result.value = null;
  revoke.error.value = null;
  void loadTokens();
});

// ── Revoke ───────────────────────────────────────────────────────────────
const result = ref<string | null>(null);
const revoke = useAsyncAction((err) => errorMessage(err, 'Could not revoke.'));

const revokeConfirmOpen = ref(false);
const pendingRevoke = ref<{ lookupId: string; name: string } | null>(null);
const revokeAllConfirmOpen = ref(false);

function openRevokeConfirm(lookupId: string, name: string): void {
  pendingRevoke.value = { lookupId, name };
  revokeConfirmOpen.value = true;
}

async function afterRevoke(message: string): Promise<void> {
  result.value = message;
  await loadTokens();
}

async function handleRevoke(): Promise<void> {
  if (!pendingRevoke.value) return;
  const { lookupId, name } = pendingRevoke.value;
  result.value = null;
  const ok = await revoke.run(() => revokeUserToken(lookupId));
  revokeConfirmOpen.value = false;
  if (ok) await afterRevoke(`Revoked "${name}".`);
}

async function handleRevokeAll(): Promise<void> {
  const user = selectedUser.value;
  if (!user) return;
  result.value = null;
  let count = 0;
  const ok = await revoke.run(async () => {
    count = (await revokeAllUserTokens(user.subject)).length;
  });
  revokeAllConfirmOpen.value = false;
  if (ok) await afterRevoke(`Revoked ${count} ${count === 1 ? 'token' : 'tokens'}.`);
}
</script>

<template>
  <section class="af-sect" aria-labelledby="ap-user-tokens-title">
    <h2 id="ap-user-tokens-title">User tokens</h2>
    <UserPicker v-model="selectedUser" label="User" />

    <template v-if="selectedUser">
      <div v-if="revoke.error.value" class="alert af-note bad" role="alert">
        <span class="af-mark bad" aria-hidden="true"></span>
        <span>
          <b>Revoke failed</b>
          {{ revoke.error.value }}
        </span>
      </div>
      <p v-else-if="result" class="aut__result" role="status" data-af-revoke-result>
        {{ result }}
      </p>

      <AsyncState
        inline
        :loading="loadState.loading.value"
        :error="loadState.error.value"
        error-title="Could not load tokens"
        :session-expired="loadState.sessionExpired.value"
        :access-denied="loadState.accessDenied.value"
        :empty="tokens.length === 0"
        loading-label="Loading tokens…"
      >
        <template #empty>
          <p class="aut__none">{{ userName }} has no tokens.</p>
        </template>
        <TokenList
          :tokens="tokens"
          :revoking-lookup-id="revoke.busy.value ? (pendingRevoke?.lookupId ?? null) : null"
          :deleting-lookup-id="null"
          :label="`Tokens of ${userName}`"
          :deletable="false"
          @revoke="openRevokeConfirm"
        />
        <div v-if="activeTokens.length > 0" class="aut__bar">
          <button
            type="button"
            class="btn af-danger"
            data-variant="outline"
            data-size="sm"
            data-af-revoke-all
            @click="revokeAllConfirmOpen = true"
          >
            Revoke all active tokens ({{ activeTokens.length }})
          </button>
        </div>
      </AsyncState>

      <ConfirmDialog
        v-model:open="revokeConfirmOpen"
        :title="pendingRevoke ? `Revoke &quot;${pendingRevoke.name}&quot;?` : ''"
        confirm-label="Revoke token"
        busy-label="Revoking…"
        danger
        :busy="revoke.busy.value"
        @confirm="handleRevoke"
      >
        <p>
          {{ userName }}'s clients using this token stop working immediately. This cannot be undone.
        </p>
      </ConfirmDialog>

      <ConfirmDialog
        v-model:open="revokeAllConfirmOpen"
        :title="`Revoke all ${activeTokens.length} active ${activeTokens.length === 1 ? 'token' : 'tokens'} of ${userName}?`"
        confirm-label="Revoke all"
        busy-label="Revoking…"
        danger
        :busy="revoke.busy.value"
        @confirm="handleRevokeAll"
      >
        <p>
          Every client using one of {{ userName }}'s active tokens stops working immediately. This
          cannot be undone. Revoked and expired tokens are not affected.
        </p>
      </ConfirmDialog>
    </template>
  </section>
</template>

<style scoped>
.aut__none,
.aut__result {
  margin: 0;
  font-size: var(--text-13);
}

.aut__bar {
  display: flex;
  justify-content: flex-end;
  margin-top: var(--space-12);
}
</style>
