<script setup lang="ts">
/**
 * MintTokenDialog.vue — the "New token" dialog: the mint form, then the
 * one-time reveal of the minted token.
 *
 * CRITICAL SECURITY NOTE: the minted token value only ever lives in
 * `mintedToken` for the lifetime of the dialog. It is cleared the moment
 * the dialog closes (Done, ESC, or backdrop click all fire the native
 * `close` event) and is never written back into the token list — the list
 * always comes from GET /v1/tokens, which never echoes a token value.
 *
 * The parent opens it through the exposed `open(trigger)`, which also takes
 * the button to return focus to on close, and reacts to `done` (the user
 * dismissed the reveal with Done) by refetching its list.
 */
import { computed, nextTick, onMounted, ref } from 'vue';
import { fetchPermissions, mintToken } from '../lib/api';
import type { MintedToken, PermissionGrant } from '../lib/api';
import {
  NOTE_MAX_LENGTH,
  permissionGrantIdentifiers,
  permissionGrantLabel,
} from '../lib/tokenDisplay';
import { permissionLabel } from '../lib/permissionLabel';
import { claudeMcpAddSnippet } from '../lib/tokenCliSnippets';
import { errorMessage } from '../lib/apiError';
import { formatIsoDateTime } from '../lib/relativeTime';
import { useAsyncAction } from '../lib/useAsyncAction';
import CopyField from './ui/CopyField.vue';

const props = defineProps<{
  /** The broker's origin, empty until the page has resolved it. */
  brokerOrigin: string;
}>();

const emit = defineEmits<{
  done: [];
}>();

// ── Mint dialog ──────────────────────────────────────────────────────────
// Native <dialog> gives a real focus trap, ESC to close, and inert siblings
// for free (see IdentityLink.vue for the same pattern).
const dialog = ref<HTMLDialogElement | null>(null);
const mintTrigger = ref<HTMLButtonElement | null>(null);

// '90' is the broker's own default (Settings.pat_default_expiry_days) --
// mirrored here only as the form's starting selection; the broker applies
// its own default regardless if expires_in_days is omitted from the
// request. 'never' maps to never_expires: true (an explicit opt-in per
// api/tokens.py's MintTokenRequest -- never silently the default).
const expiryOption = ref<'30' | '90' | '365' | 'never'>('90');
const name = ref('');
const note = ref('');
const {
  busy: minting,
  error: mintError,
  run: runMint,
} = useAsyncAction((err) => errorMessage(err, 'Could not create the token. Try again.'));
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

/** Open the dialog with a fresh form; *trigger* regains focus when it closes. */
async function open(trigger: HTMLButtonElement) {
  mintTrigger.value = trigger;
  mintedToken.value = null;
  mintError.value = null;
  name.value = '';
  note.value = '';
  expiryOption.value = '90';
  restrictPermissions.value = false;
  selectedPermissions.value = new Set();
  await nextTick();
  dialog.value?.showModal();
}

defineExpose({ open });

// Fires on ESC, backdrop click, or an explicit .close() — the single place
// that must scrub the minted token from memory once the dialog is gone.
function onMintDialogClose() {
  mintTrigger.value?.focus();
  mintTrigger.value = null;
  mintedToken.value = null;
}

async function handleMint(evt: Event) {
  evt.preventDefault();
  // A failure includes the 409 duplicate-name case (api/tokens.py's
  // DuplicateNameError) -- APIError's message already carries the broker's
  // `detail` text.
  await runMint(async () => {
    const neverExpires = expiryOption.value === 'never';
    mintedToken.value = await mintToken(
      name.value.trim() || undefined,
      note.value.trim() || undefined,
      neverExpires ? undefined : Number(expiryOption.value),
      neverExpires,
      restrictPermissions.value ? [...selectedPermissions.value] : undefined,
    );
  });
}

function handleDone() {
  dialog.value?.close(); // triggers onMintDialogClose, which clears mintedToken
  emit('done');
}

// "Register as an MCP client" one-liner shown alongside the raw token in
// the "Token created" step (issue #152). Only ever constructible from
// `mintedToken`, which onMintDialogClose scrubs the moment the dialog
// closes -- like the token itself, this is never reconstructable from the
// list view, since the secret is never retained server-side.
const claudeAddCommand = computed(() =>
  mintedToken.value ? claudeMcpAddSnippet(props.brokerOrigin, mintedToken.value.token) : '',
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
</script>

<template>
  <!-- New token dialog -->
  <dialog
    ref="dialog"
    class="dialog af-modal"
    aria-labelledby="tp-modal-title"
    @close="onMintDialogClose"
  >
    <form v-if="!mintedToken" class="tp__panel" novalidate @submit.prevent="handleMint">
      <header>
        <h2 id="tp-modal-title">New token</h2>
        <p>
          A personal access token is a long-lived credential you paste into a client's config, such
          as Claude Desktop, that can't sign in with a browser. It is shown once, so copy it before
          you close this dialog.
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
        <button type="button" class="btn" data-variant="ghost" @click="dialog?.close()">
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
          <dd>
            {{ mintedToken.expires_at ? formatIsoDateTime(mintedToken.expires_at) : 'Never' }}
          </dd>
        </dl>
      </section>

      <footer>
        <button type="button" class="btn" @click="handleDone">Done</button>
      </footer>
    </div>
  </dialog>
</template>

<style scoped>
.tp__label {
  margin: 0;
  font-size: var(--text-13);
  font-weight: 500;
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
