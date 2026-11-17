<script setup lang="ts">
/**
 * TokenList.vue — the table of a user's issued tokens, with a per-row Revoke
 * (active tokens) or Delete (revoked and expired ones). Presentational: the
 * parent owns the token data and the API calls, and reacts to `revoke` and
 * `delete`.
 */
import { onBeforeUnmount, ref } from 'vue';
import { Check, Copy } from '@lucide/vue';
import type { TokenSummary } from '../lib/api';
import {
  expiresIn,
  expiresSoon,
  permissionGrantIdentifiers,
  permissionGrantLabel,
  shortLookupId,
  tokenStatus,
  truncateNote,
} from '../lib/tokenDisplay';
import { copyText } from '../lib/clipboard';
import { formatIsoDateTime, formatRelative } from '../lib/relativeTime';
import InfoTip from './ui/InfoTip.vue';
import StatusMark from './ui/StatusMark.vue';

withDefaults(
  defineProps<{
    tokens: TokenSummary[];
    /** lookup_id of the row whose revoke is in flight, if any. */
    revokingLookupId: string | null;
    /** lookup_id of the row whose delete is in flight, if any. */
    deletingLookupId: string | null;
    /** Accessible name of the table. */
    label?: string;
    /** Whether a revoked or expired row offers Delete (a user's own list does; an admin's view of another user's does not). */
    deletable?: boolean;
  }>(),
  { label: 'Your issued tokens', deletable: true },
);

const emit = defineEmits<{
  revoke: [lookupId: string, name: string];
  delete: [lookupId: string];
}>();

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

// ── Formatting ───────────────────────────────────────────────────────────
function formatRelativeIso(iso: string): string {
  return formatRelative(Date.parse(iso));
}

// A revoked token no longer expires, so its original expiry would only
// mislead; the Status column already says "Revoked".
function expiresText(row: TokenSummary): string {
  if (tokenStatus(row) === 'revoked') return '—';
  return row.expires_at ? formatRelativeIso(row.expires_at) : 'Never';
}

function expiresTitle(row: TokenSummary): string {
  if (tokenStatus(row) === 'revoked') return 'Revoked';
  return row.expires_at ? formatIsoDateTime(row.expires_at) : 'Never expires';
}

const statusLabel: Record<ReturnType<typeof tokenStatus>, string> = {
  active: 'Active',
  revoked: 'Revoked',
  expired: 'Expired',
};
</script>

<template>
  <div class="table-container af-box" role="region" aria-label="Issued tokens" tabindex="0">
    <table class="tp__table table" :aria-label="label">
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
        <tr v-for="row in tokens" :key="row.lookup_id">
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
              <span :title="formatIsoDateTime(row.created_at)">
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
          <td data-label="Status">
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
            data-label="Scope"
            class="af-sub tp__scope"
            :title="permissionGrantIdentifiers(row.permission_grant)"
          >
            {{ permissionGrantLabel(row.permission_grant) }}
          </td>
          <td data-label="Expires" class="af-sub" :title="expiresTitle(row)">
            {{ expiresText(row) }}
          </td>
          <td
            data-label="Last used"
            class="af-sub"
            :title="row.last_used_at ? formatIsoDateTime(row.last_used_at) : 'Never used'"
          >
            {{ row.last_used_at ? formatRelativeIso(row.last_used_at) : 'Never' }}
          </td>
          <td class="af-act af-sticky tp__actcell">
            <button
              v-if="tokenStatus(row) === 'active'"
              type="button"
              class="btn af-danger"
              data-variant="outline"
              data-size="sm"
              :aria-label="`Revoke ${row.name}`"
              :disabled="revokingLookupId === row.lookup_id"
              @click="emit('revoke', row.lookup_id, row.name)"
            >
              {{ revokingLookupId === row.lookup_id ? 'Revoking…' : 'Revoke' }}
            </button>
            <button
              v-else-if="deletable"
              type="button"
              class="btn"
              data-variant="outline"
              data-size="sm"
              :aria-label="`Delete ${row.name}`"
              :disabled="deletingLookupId === row.lookup_id"
              @click="emit('delete', row.lookup_id)"
            >
              {{ deletingLookupId === row.lookup_id ? 'Deleting…' : 'Delete' }}
            </button>
          </td>
        </tr>
      </tbody>
    </table>
  </div>
</template>

<style scoped>
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

/* On a phone the six columns do not fit, and scrolling sideways hid the Scope
   column under the Revoke button. Each row becomes a block instead: the name
   and its action on the first line, then one "label  value" line per fact,
   the label taken from each cell's data-label. */
@media (max-width: 640px) {
  .tp__table thead {
    position: absolute;
    width: 1px;
    height: 1px;
    overflow: hidden;
    clip-path: inset(50%);
  }

  .tp__table,
  .tp__table tbody {
    display: block;
  }

  .tp__table tr {
    display: grid;
    grid-template-columns: 1fr auto;
    align-items: center;
    gap: var(--space-4) var(--space-12);
    padding: var(--space-12) var(--space-16);
  }

  .tp__table td {
    display: block;
    height: auto;
    padding: 0;
    white-space: normal;
  }

  .tp__table td[data-label] {
    display: flex;
    grid-column: 1 / -1;
    justify-content: space-between;
    gap: var(--space-12);
    min-width: 0;
    max-width: none;
    text-align: right;
  }

  .tp__table td[data-label]::before {
    content: attr(data-label);
    flex: none;
    color: var(--color-af-text-secondary);
    text-align: left;
  }

  .tp__namecell {
    grid-column: 1;
    max-width: none;
  }

  .tp__actcell {
    grid-column: 2;
    grid-row: 1;
    position: static;
    background: transparent;
  }
}
</style>
