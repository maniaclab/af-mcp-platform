<script setup lang="ts">
/**
 * EntitlementsPage.vue — "why do/don't I have access" in one place.
 *
 * Fetches both GET /v1/permissions (the caller's own groups + resolved
 * grants) and GET /v1/entitlements (the static group -> permission table,
 * same for every caller) in parallel, and renders a single permission x
 * group matrix: one row per permission, a pinned "You" column (the
 * caller's actual resolved grants — correct even for a permission-scoped
 * PAT, since it comes straight from /v1/permissions rather than being
 * re-derived here) frozen right after the row headers, then the full
 * reference table's group columns with the caller's own matching groups
 * highlighted. The raw Keycloak group list (up to ~25 org/workgroup paths
 * per user) is deliberately not shown in full — only the ones that
 * intersect a column in the reference table actually affect access; the
 * rest carry no permission and would just be noise. See
 * docs/plans/2026-09-01-ops-platform-usability.md.
 */
import { computed, onMounted, ref } from 'vue';
import {
  AccessDeniedError,
  fetchEntitlements,
  fetchPermissions,
  SessionExpiredError,
  type PermissionsResponse,
} from '../lib/api';
import InfoTooltip from './InfoTooltip.vue';

const groupPermissions = ref<Record<string, string[]>>({});
const myGroups = ref<string[]>([]);
const myGrants = ref<PermissionsResponse['grants']>([]);
const loading = ref(true);
const error = ref<string | null>(null);
const sessionExpired = ref(false);
const accessDenied = ref<AccessDeniedError | null>(null);

// Any authenticated caller gets this baseline regardless of Keycloak group
// membership (see authorization/base.py's get_principal_permissions) — it
// never appears in myGroups, but it always applies, so the matrix must
// still treat its row as "yours".
const AUTHENTICATED_SENTINEL = '__authenticated__';

function reload() {
  window.location.reload();
}

onMounted(async () => {
  try {
    const [entitlements, permissions] = await Promise.all([
      fetchEntitlements(),
      fetchPermissions(),
    ]);
    groupPermissions.value = entitlements.group_permissions;
    myGroups.value = permissions.groups;
    myGrants.value = permissions.grants;
  } catch (err) {
    if (err instanceof AccessDeniedError) {
      accessDenied.value = err;
    } else if (err instanceof SessionExpiredError) {
      sessionExpired.value = true;
    } else {
      error.value = err instanceof Error ? err.message : 'Could not load entitlements.';
    }
  } finally {
    loading.value = false;
  }
});

function isMineGroup(group: string): boolean {
  return group === AUTHENTICATED_SENTINEL || myGroups.value.includes(group);
}

function groupLabel(group: string): string {
  return group === AUTHENTICATED_SENTINEL ? 'Any authenticated user' : group;
}

// The caller's raw Keycloak groups that also happen to be a row in the
// reference table below — the only ones that actually affect their access.
// A real AF user carries ~25 org/workgroup groups; most map to nothing.
const matchedGroups = computed(() => myGroups.value.filter((g) => g in groupPermissions.value));

// Reference-table rows, caller's matching groups first (stable within each
// half) so a caller can find themselves without scanning the whole table.
const sortedGroups = computed(() => {
  const groups = Object.keys(groupPermissions.value);
  return [...groups].sort((a, b) => {
    const mineA = isMineGroup(a) ? 0 : 1;
    const mineB = isMineGroup(b) ? 0 : 1;
    return mineA !== mineB ? mineA - mineB : a.localeCompare(b);
  });
});

// Column order/coloring/description mirrors authorization/base.py's
// PERMISSIONS dict (action_type classification and description text)
// purely for display -- cosmetic only, not an enforcement decision. A
// permission the broker adds later that isn't in this list still renders
// correctly: it's appended alphabetically at the end, styled as "read", with
// no tooltip (there's no description to show for it here).
const KNOWN_PERMISSION_ORDER: Array<{ name: string; kind: 'read' | 'write'; description: string }> =
  [
    { name: 'read_data', kind: 'read', description: 'Read datasets from data stores.' },
    { name: 'read_metadata', kind: 'read', description: 'Read metadata catalogs.' },
    {
      name: 'read_monitoring',
      kind: 'read',
      description: 'Read monitoring dashboards and metrics.',
    },
    {
      name: 'read_gitlab',
      kind: 'read',
      description: 'Browse GitLab repos, issues, MRs, and pipelines.',
    },
    {
      name: 'read_files',
      kind: 'read',
      description: 'Browse and read files in a POSIX home directory.',
    },
    { name: 'submit_jobs', kind: 'write', description: 'Submit compute jobs.' },
    { name: 'manage_jobs', kind: 'write', description: 'Cancel or modify compute jobs.' },
    {
      name: 'launch_compute',
      kind: 'write',
      description: 'Launch interactive compute sessions.',
    },
    {
      name: 'manage_jupyter',
      kind: 'write',
      description: 'Start, stop, and configure Jupyter servers.',
    },
    { name: 'manage_gitlab', kind: 'write', description: 'Create MRs, open issues, retry CI.' },
    { name: 'manage_data', kind: 'write', description: 'Write or delete data (gated).' },
    { name: 'admin', kind: 'write', description: 'Platform administration.' },
  ];

interface Column {
  name: string;
  kind: 'read' | 'write';
  description: string | null;
}

const columns = computed<Column[]>(() => {
  const used = new Set<string>();
  for (const perms of Object.values(groupPermissions.value)) {
    for (const p of perms) used.add(p);
  }
  for (const grant of myGrants.value) used.add(grant.permission);

  const known = KNOWN_PERMISSION_ORDER.filter((p) => used.has(p.name));
  const knownNames = new Set(known.map((p) => p.name));
  const extra = [...used]
    .filter((p) => !knownNames.has(p))
    .sort()
    .map((name) => ({ name, kind: 'read' as const, description: null }));

  return [...known, ...extra];
});

// First index whose kind differs from the previous column's, so the
// template can drop a visual divider between the read and write blocks.
const firstWriteIndex = computed(() => columns.value.findIndex((c) => c.kind === 'write'));

function groupHasPermission(group: string, permission: string): boolean {
  return (groupPermissions.value[group] ?? []).includes(permission);
}

function meHasPermission(permission: string): boolean {
  return myGrants.value.some((grant) => grant.permission === permission);
}
</script>

<template>
  <div class="ep">
    <div v-if="loading" class="ep__loading" aria-live="polite">
      <span class="ep__spinner" aria-hidden="true"></span>
      Loading entitlements…
    </div>

    <div v-else-if="sessionExpired" class="ep__error" role="alert">
      <span class="ep__error-title">Session expired</span>
      <span class="ep__error-body">
        Your session has expired.
        <button type="button" class="ep__reload" @click="reload">Reload</button>
        to re-authenticate.
      </span>
    </div>

    <!-- Access denied here means the SAME platform-wide audience mismatch
         every other page would also hit (see identity.py's
         TokenAudienceError) -- this page can't help with that one, since it
         needs the same working credential every other /v1 route does. -->
    <div v-else-if="accessDenied" class="ep__error" role="alert">
      <span class="ep__error-title">Access not yet granted</span>
      <span class="ep__error-body">{{ accessDenied.message }}</span>
    </div>

    <div v-else-if="error" class="ep__error" role="alert">
      <span class="ep__error-title">Could not load entitlements</span>
      <span class="ep__error-body">{{ error }}</span>
    </div>

    <template v-else>
      <section class="ep__section" aria-labelledby="ep-table-heading">
        <h2 id="ep-table-heading" class="ep__heading">Entitlements matrix</h2>
        <p class="ep__desc">
          Every permission this platform grants, and which groups hold each one. Your own resolved
          access is pinned in the <strong>You</strong> column, highlighted in teal; your matching
          groups among the rest are marked
          <span class="ep__you-badge ep__you-badge--inline">you</span>. Missing something you need?
          Contact the AF admins.
        </p>

        <p v-if="matchedGroups.length > 0" class="ep__mine-summary">
          You belong to
          <span v-for="(g, i) in matchedGroups" :key="g">
            <code class="ep__group-pill">{{ g }}</code
            ><span v-if="i < matchedGroups.length - 1">, </span>
          </span>
          — recognized groups, plus the baseline every signed-in user gets.
        </p>
        <p v-else class="ep__mine-summary">
          None of your groups are recognized here — you only get the baseline every signed-in user
          gets.
        </p>

        <p class="ep__legend">
          <span class="ep__legend-item"
            ><span class="ep__mark ep__mark--yes ep__mark--read ep__legend-mark"
              ><svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
                <path
                  d="M4 12.5l5 5L20 6"
                  stroke="currentColor"
                  stroke-width="2.5"
                  stroke-linecap="round"
                  stroke-linejoin="round"
                /></svg></span
            >read</span
          >
          <span class="ep__legend-item"
            ><span class="ep__mark ep__mark--yes ep__mark--write ep__legend-mark"
              ><svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
                <path
                  d="M4 12.5l5 5L20 6"
                  stroke="currentColor"
                  stroke-width="2.5"
                  stroke-linecap="round"
                  stroke-linejoin="round"
                /></svg></span
            >state-changing</span
          >
          <span class="ep__legend-item"
            ><span class="ep__mark ep__mark--no ep__legend-mark"
              ><svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
                <path
                  d="M7 7l10 10M17 7L7 17"
                  stroke="currentColor"
                  stroke-width="2"
                  stroke-linecap="round"
                /></svg></span
            >not granted</span
          >
        </p>

        <div v-if="columns.length === 0" class="ep__empty">
          No permissions are declared in the policy yet.
        </div>

        <!-- Permissions run down the rows and groups run across the columns
             (not the reverse) because this axis only grows in one direction:
             services.yaml's per-tool required_permission (see
             mcp/registry.py) means the permission list gets longer as
             services split their tools more finely, while the group list
             stays whatever a handful of admins curated in policy.yaml. Rows
             grow the page down, which is a normal scroll; columns growing
             sideways is what produced the old vertical-text, always-scrolling
             layout this replaces. It also means every permission name reads
             horizontally now -- no writing-mode rotation anywhere. -->
        <div v-else class="ep__matrix-scroll">
          <table class="ep__matrix">
            <caption class="ep__sr-only">
              Permission to group entitlement matrix, with your resolved access pinned as the first
              column
            </caption>
            <thead>
              <tr>
                <th scope="col" class="ep__matrix-corner">Permission</th>
                <th scope="col" class="ep__matrix-colhead ep__matrix-colhead--you">You</th>
                <!-- Angled, not horizontal or vertical: a group path like
                     /connect/uchicago/admin set horizontally would force
                     every data column to its own text width, stretching the
                     table exactly as far right as the old permission-columns
                     layout did; set fully vertical (writing-mode) reads as
                     badly as the layout this page replaced. The label is
                     position: absolute, so it takes no part in the table's
                     automatic column-width calculation -- each data column
                     sizes to its own checkmark instead, and the label simply
                     overflows across however many narrow columns its own
                     length needs (see .ep__matrix-colhead--group). -->
                <th
                  v-for="group in sortedGroups"
                  :key="group"
                  scope="col"
                  class="ep__matrix-colhead ep__matrix-colhead--group"
                  :class="{ 'ep__matrix-colhead--mine': isMineGroup(group) }"
                >
                  <span class="ep__matrix-colhead-label" :title="groupLabel(group)">
                    {{ groupLabel(group) }}
                    <span v-if="isMineGroup(group)" class="ep__you-badge">you</span>
                  </span>
                </th>
              </tr>
            </thead>
            <tbody>
              <tr
                v-for="(col, i) in columns"
                :key="col.name"
                class="ep__matrix-row"
                :class="{ 'ep__matrix-row--divider': i === firstWriteIndex }"
              >
                <th scope="row" class="ep__matrix-rowhead">
                  <InfoTooltip v-if="col.description" :tooltip-id="`ep-perm-${col.name}`">
                    <button
                      type="button"
                      class="ep__matrix-rowhead-btn"
                      :aria-describedby="`ep-perm-${col.name}`"
                    >
                      {{ col.name }}
                    </button>
                    <template #tooltip>{{ col.description }}</template>
                  </InfoTooltip>
                  <span v-else class="ep__matrix-rowhead-plain">{{ col.name }}</span>
                </th>
                <td class="ep__matrix-cell ep__matrix-cell--you">
                  <span
                    v-if="meHasPermission(col.name)"
                    class="ep__mark ep__mark--yes"
                    :class="`ep__mark--${col.kind}`"
                    role="img"
                    :aria-label="`You hold ${col.name}`"
                  >
                    <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
                      <path
                        d="M4 12.5l5 5L20 6"
                        stroke="currentColor"
                        stroke-width="2.5"
                        stroke-linecap="round"
                        stroke-linejoin="round"
                      />
                    </svg>
                  </span>
                  <span
                    v-else
                    class="ep__mark ep__mark--no"
                    role="img"
                    :aria-label="`You do not hold ${col.name}`"
                  >
                    <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
                      <path
                        d="M7 7l10 10M17 7L7 17"
                        stroke="currentColor"
                        stroke-width="2"
                        stroke-linecap="round"
                      />
                    </svg>
                  </span>
                </td>
                <td
                  v-for="group in sortedGroups"
                  :key="group"
                  class="ep__matrix-cell"
                  :class="{ 'ep__matrix-cell--mine': isMineGroup(group) }"
                >
                  <span
                    v-if="groupHasPermission(group, col.name)"
                    class="ep__mark ep__mark--yes"
                    :class="`ep__mark--${col.kind}`"
                    role="img"
                    :aria-label="`${groupLabel(group)} grants ${col.name}`"
                  >
                    <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
                      <path
                        d="M4 12.5l5 5L20 6"
                        stroke="currentColor"
                        stroke-width="2.5"
                        stroke-linecap="round"
                        stroke-linejoin="round"
                      />
                    </svg>
                  </span>
                  <span
                    v-else
                    class="ep__mark ep__mark--no"
                    role="img"
                    :aria-label="`${groupLabel(group)} does not grant ${col.name}`"
                  >
                    <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
                      <path
                        d="M7 7l10 10M17 7L7 17"
                        stroke="currentColor"
                        stroke-width="2"
                        stroke-linecap="round"
                      />
                    </svg>
                  </span>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>
    </template>
  </div>
</template>

<style scoped>
/* Mirrors IdentitiesPage.vue's page-level error/loading treatment so the
   two pages read as siblings. */
.ep__loading,
.ep__error {
  padding: 1.25rem;
  border: 1px solid var(--color-af-border);
  border-radius: 4px;
  background: var(--color-af-surface);
}

.ep__error-title {
  display: block;
  font-family: 'IBM Plex Mono', monospace;
  font-weight: 600;
  margin-bottom: 0.375rem;
}

.ep__reload {
  background: none;
  border: none;
  padding: 0;
  color: var(--color-af-teal);
  text-decoration: underline;
  cursor: pointer;
  font: inherit;
}

.ep__section {
  margin-bottom: 2.5rem;
}

.ep__heading {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 1.0625rem;
  font-weight: 700;
  letter-spacing: 0.02em;
  margin: 0 0 0.75rem;
}

.ep__desc,
.ep__empty {
  font-size: 0.875rem;
  color: var(--color-af-dim);
  margin: 0 0 0.75rem;
}

.ep__mine-summary {
  font-size: 0.875rem;
  color: var(--color-af-text);
  margin: 0 0 1.25rem;
  line-height: 1.7;
}

.ep__group-pill {
  display: inline-block;
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.75rem;
  padding: 0.0625rem 0.375rem;
  border-radius: 3px;
  background: var(--color-af-surface);
  border: 1px solid var(--color-af-border);
}

.ep__sr-only {
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

/* Matrix table */

.ep__matrix-scroll {
  overflow-x: auto;
  border: 1px solid var(--color-af-border);
  border-radius: 4px;
}

.ep__matrix {
  border-collapse: collapse;
  font-size: 0.8125rem;
  width: 100%;
}

/* Permission column (row headers) is a fixed width so the sticky "You"
   column right after it (see .ep__matrix-colhead--you /
   .ep__matrix-cell--you) can rely on a predictable `left` offset -- a
   frozen second column needs to know exactly where the first one ends. */
.ep__matrix-corner,
.ep__matrix-rowhead {
  width: 11rem;
  min-width: 11rem;
}

.ep__matrix-corner {
  position: sticky;
  left: 0;
  z-index: 2;
  background: var(--color-af-surface);
}

.ep__matrix-colhead {
  background: var(--color-af-surface);
  vertical-align: bottom;
  text-align: left;
  padding: 0.625rem 0.75rem 0.625rem;
  border-bottom: 1px solid var(--color-af-border);
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.6875rem;
  font-weight: 600;
  letter-spacing: 0.06em;
  color: var(--color-af-label);
  white-space: nowrap;
}

.ep__matrix-colhead--mine {
  color: var(--color-af-text);
}

/* Angled group-name headers (see the template comment above). The label
   itself is position: absolute (out of flow, so it doesn't widen this
   column), anchored at this cell's own bottom-left corner and rotated
   -45deg so it reads bottom-to-top, left-to-right, overflowing across
   however many narrow data columns its own length needs. Every column's
   label starts at the same height and travels at the same angle, so
   adjacent labels stay parallel rather than colliding -- the standard
   spreadsheet-style diagonal header trick. */
.ep__matrix-colhead--group {
  position: relative;
  height: 7.5rem;
  padding: 0;
  /* A horizontal line here would cut across every label mid-flight as it
     crosses into a neighboring column's box. */
  border-bottom: none;
}

.ep__matrix-colhead-label {
  position: absolute;
  left: 0.5rem;
  bottom: 0.5rem;
  transform-origin: bottom left;
  transform: rotate(-45deg);
  white-space: nowrap;
}

.ep__matrix-colhead--you {
  position: sticky;
  /* Matches .ep__matrix-corner / .ep__matrix-rowhead's fixed width above. */
  left: 11rem;
  z-index: 2;
  color: var(--color-af-teal);
  background: rgb(from var(--color-af-teal) r g b / 0.12);
}

.ep__matrix-rowhead {
  position: sticky;
  left: 0;
  /* Higher than .ep__matrix-colhead--you / .ep__matrix-cell--you (z-index 2
     and 1): this cell's own InfoTooltip bubble overflows rightward past its
     11rem width into the You column's box, and the two are tied siblings in
     the row -- without this, the later-in-DOM You cell painted over the
     open tooltip instead of the tooltip showing on top of it. */
  z-index: 3;
  background: var(--color-af-void);
  text-align: left;
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.8125rem;
  font-weight: 400;
  padding: 0;
  border-bottom: 1px solid var(--color-af-border);
  border-right: 1px solid var(--color-af-border);
  white-space: nowrap;
}

/* InfoTooltip's own root element (leaked into this scope via Vue's scoped
   CSS, which reaches a child component's root node) defaults to
   inline-flex -- block here so the button inside fills the cell the same
   way .ep__matrix-rowhead-plain does in the no-description branch. */
.ep__matrix-rowhead :deep(.info-tooltip) {
  display: block;
}

.ep__matrix-rowhead-btn {
  display: block;
  width: 100%;
  background: none;
  border: none;
  margin: 0;
  padding: 0.5rem 0.75rem;
  font: inherit;
  text-align: left;
  color: inherit;
  cursor: help;
}

.ep__matrix-rowhead-btn:hover,
.ep__matrix-rowhead-btn:focus-visible {
  color: var(--color-af-teal);
}

.ep__matrix-rowhead-btn:focus-visible {
  outline: 2px solid var(--color-af-teal);
  outline-offset: -2px;
}

/* Every row shares the same z-index (3), so an open tooltip that overflows
   downward past its own row's height would otherwise lose to the very next
   row's rowhead -- a later sibling ties on z-index and wins on DOM order
   regardless of which row's tooltip is actually open. Elevate only the row
   whose tooltip is open above every other row (which all stay at 3). */
.ep__matrix-rowhead:has(.info-tooltip:hover),
.ep__matrix-rowhead:has(.info-tooltip:focus-within) {
  z-index: 20;
}

.ep__matrix-rowhead-plain {
  display: block;
  padding: 0.5rem 0.75rem;
}

/* Divider between the read and write permission blocks -- was a vertical
   border between columns before the transpose; now a horizontal one between
   rows. */
.ep__matrix-row--divider th,
.ep__matrix-row--divider td {
  border-top: 1px solid var(--color-af-border);
}

.ep__matrix-cell--you {
  background: rgb(from var(--color-af-teal) r g b / 0.06);
  position: sticky;
  left: 11rem;
  z-index: 1;
}

.ep__matrix-cell--mine {
  background: var(--color-af-surface);
}

.ep__matrix-cell {
  text-align: center;
  padding: 0.5rem;
  border-bottom: 1px solid var(--color-af-border);
}

.ep__you-badge {
  text-transform: uppercase;
  letter-spacing: 0.06em;
  color: var(--color-af-teal);
  margin-left: 0.5rem;
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.625rem;
}

.ep__you-badge--inline {
  margin-left: 0;
  border: 1px solid var(--color-af-teal);
  border-radius: 2px;
  padding: 0 0.25rem;
}

.ep__mark {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 1.25rem;
  height: 1.25rem;
}

.ep__mark svg {
  width: 100%;
  height: 100%;
}

.ep__mark--yes.ep__mark--read {
  color: var(--color-af-green);
}

.ep__mark--yes.ep__mark--write {
  color: var(--color-af-amber);
}

.ep__mark--no {
  /* af-muted is border/disabled-only (see DESIGN.md's Muted-Is-Never-Text
     Rule) and fails text contrast -- af-dim is the real AA-passing
     secondary-content token, appropriate for a deliberately de-emphasized
     but still legible "not granted" mark. */
  color: var(--color-af-dim);
}

.ep__legend {
  display: flex;
  gap: 1.25rem;
  margin: 0 0 1rem;
  font-size: 0.75rem;
  color: var(--color-af-dim);
}

.ep__legend-item {
  display: inline-flex;
  align-items: center;
  gap: 0.375rem;
}

.ep__legend-mark {
  width: 1rem;
  height: 1rem;
}
</style>
