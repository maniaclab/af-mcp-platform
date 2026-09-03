<script setup lang="ts">
/**
 * EntitlementsPage.vue — "why do/don't I have access" in one place.
 *
 * Fetches both GET /v1/permissions (the caller's own groups + resolved
 * grants) and GET /v1/entitlements (the static group -> permission table,
 * same for every caller) in parallel, and renders a single group x
 * permission matrix: a pinned "You" row (the caller's actual resolved
 * grants — correct even for a permission-scoped PAT, since it comes
 * straight from /v1/permissions rather than being re-derived here) above
 * the full reference table, with the caller's own matching groups
 * highlighted. The raw Keycloak group list (up to ~25 org/workgroup paths
 * per user) is deliberately not shown in full — only the ones that
 * intersect a row in the reference table actually affect access; the rest
 * carry no permission and would just be noise. See
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
          Every group this platform recognizes, and what each one grants. The
          <strong>You</strong> row is your own resolved access; rows below it are reference — your
          matching groups are marked <span class="ep__you-badge ep__you-badge--inline">you</span>.
          Missing something you need? Contact the AF admins.
        </p>

        <p v-if="matchedGroups.length > 0" class="ep__mine-summary">
          You belong to
          <span v-for="(g, i) in matchedGroups" :key="g">
            <code class="ep__group-pill">{{ g }}</code
            ><span v-if="i < matchedGroups.length - 1">, </span>
          </span>
          — recognized groups, plus the baseline every signed-in user gets. The
          <strong>You</strong> row above shows exactly what that resolves to.
        </p>
        <p v-else class="ep__mine-summary">
          None of your groups are recognized here — you only get the baseline every signed-in user
          gets. The <strong>You</strong> row above shows exactly what that resolves to.
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

        <div v-else class="ep__matrix-scroll">
          <table class="ep__matrix">
            <caption class="ep__sr-only">
              Group to permission entitlement matrix, with your resolved access pinned as the first
              row
            </caption>
            <thead>
              <tr>
                <th scope="col" class="ep__matrix-corner">Group</th>
                <th
                  v-for="(col, i) in columns"
                  :key="col.name"
                  scope="col"
                  class="ep__matrix-colhead"
                  :class="{ 'ep__matrix-colhead--divider': i === firstWriteIndex }"
                >
                  <InfoTooltip v-if="col.description" :tooltip-id="`ep-perm-${col.name}`">
                    <button
                      type="button"
                      class="ep__matrix-colhead-btn"
                      :aria-describedby="`ep-perm-${col.name}`"
                    >
                      <span class="ep__matrix-colhead-label">{{ col.name }}</span>
                    </button>
                    <template #tooltip>{{ col.description }}</template>
                  </InfoTooltip>
                  <span v-else class="ep__matrix-colhead-label">{{ col.name }}</span>
                </th>
              </tr>
            </thead>
            <tbody>
              <tr class="ep__matrix-row ep__matrix-row--you">
                <th scope="row" class="ep__matrix-rowhead">You</th>
                <td
                  v-for="(col, i) in columns"
                  :key="col.name"
                  class="ep__matrix-cell"
                  :class="{ 'ep__matrix-colhead--divider': i === firstWriteIndex }"
                >
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
              </tr>
              <tr
                v-for="group in sortedGroups"
                :key="group"
                class="ep__matrix-row"
                :class="{ 'ep__matrix-row--mine': isMineGroup(group) }"
              >
                <th scope="row" class="ep__matrix-rowhead" :title="groupLabel(group)">
                  {{ groupLabel(group) }}
                  <span v-if="isMineGroup(group)" class="ep__you-badge">you</span>
                </th>
                <td
                  v-for="(col, i) in columns"
                  :key="col.name"
                  class="ep__matrix-cell"
                  :class="{ 'ep__matrix-colhead--divider': i === firstWriteIndex }"
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
  padding: 0.625rem 0.5rem 0.75rem;
  border-bottom: 1px solid var(--color-af-border);
  min-height: 8rem;
  white-space: nowrap;
}

.ep__matrix-colhead-label {
  writing-mode: vertical-rl;
  transform: rotate(180deg);
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.6875rem;
  font-weight: 600;
  letter-spacing: 0.06em;
  color: var(--color-af-label);
}

.ep__matrix-colhead-btn {
  display: inline-flex;
  background: none;
  border: none;
  margin: 0;
  padding: 0;
  font: inherit;
  cursor: pointer;
}

.ep__matrix-colhead-btn:hover .ep__matrix-colhead-label,
.ep__matrix-colhead-btn:focus-visible .ep__matrix-colhead-label {
  color: var(--color-af-teal);
}

.ep__matrix-colhead-btn:focus-visible {
  outline: 2px solid var(--color-af-teal);
  outline-offset: 2px;
}

.ep__matrix-colhead--divider {
  border-left: 1px solid var(--color-af-border);
}

.ep__matrix-rowhead {
  position: sticky;
  left: 0;
  z-index: 1;
  background: var(--color-af-void);
  text-align: left;
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.8125rem;
  font-weight: 400;
  padding: 0.5rem 0.75rem;
  border-bottom: 1px solid var(--color-af-border);
  border-right: 1px solid var(--color-af-border);
  max-width: 16rem;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.ep__matrix-row--you .ep__matrix-rowhead {
  font-weight: 700;
  color: var(--color-af-teal);
}

.ep__matrix-row--you {
  background: rgb(from var(--color-af-teal) r g b / 0.06);
}

.ep__matrix-row--you .ep__matrix-cell {
  background: rgb(from var(--color-af-teal) r g b / 0.06);
}

.ep__matrix-row--you td,
.ep__matrix-row--you th {
  border-bottom: 1px solid var(--color-af-teal);
}

.ep__matrix-row--mine {
  background: var(--color-af-surface);
}

.ep__matrix-row--mine .ep__matrix-rowhead {
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
