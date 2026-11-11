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
  fetchEntitlements,
  fetchPermissions,
  type EntitlementsResponse,
  type PermissionsResponse,
} from '../lib/api';
import { useLoadState } from '../lib/useLoadState';
import EntitlementMark from './EntitlementMark.vue';
import AsyncState from './ui/AsyncState.vue';
import InfoTip from './ui/InfoTip.vue';

const groupPermissions = ref<Record<string, string[]>>({});
const catalog = ref<EntitlementsResponse['permissions']>([]);
const myGroups = ref<string[]>([]);
const myGrants = ref<PermissionsResponse['grants']>([]);
const { loading, error, sessionExpired, accessDenied, run } = useLoadState();

// Any authenticated caller gets this baseline regardless of Keycloak group
// membership (see authorization/base.py's get_principal_permissions) — it
// never appears in myGroups, but it always applies, so the matrix must
// still treat its row as "yours".
const AUTHENTICATED_SENTINEL = '__authenticated__';

onMounted(() =>
  run(async () => {
    const [entitlements, permissions] = await Promise.all([
      fetchEntitlements(),
      fetchPermissions(),
    ]);
    // The catalog is the only source of each permission's kind and
    // description; without it every row would be silently mislabelled, so
    // refuse to render rather than guess.
    if (!Array.isArray(entitlements.permissions)) {
      throw new Error(
        'The broker did not send its permission catalog (permissions), so permission kinds are unknown. Portal and broker may be out of step.',
      );
    }
    groupPermissions.value = entitlements.group_permissions;
    catalog.value = entitlements.permissions;
    myGroups.value = permissions.groups;
    myGrants.value = permissions.grants;
  }, 'Could not load entitlements.'),
);

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

interface Column {
  name: string;
  kind: 'read' | 'write';
  description: string;
}

// Shown for a permission the broker sends without a description (a
// site-defined one), so every row has an info affordance.
const SITE_DEFINED_DESCRIPTION = 'Site-defined permission';

// Rows are the permissions some group (or the caller) holds, taken from the
// broker's catalog: reads first, then state-changing, each in broker order.
const columns = computed<Column[]>(() => {
  const used = new Set<string>();
  for (const perms of Object.values(groupPermissions.value)) {
    for (const p of perms) used.add(p);
  }
  for (const grant of myGrants.value) used.add(grant.permission);

  const rows = catalog.value
    .filter((p) => used.has(p.name))
    .map((p) => ({
      name: p.name,
      kind: p.action_type === 'state_change' ? ('write' as const) : ('read' as const),
      description: p.description ?? SITE_DEFINED_DESCRIPTION,
    }));
  return [...rows.filter((c) => c.kind === 'read'), ...rows.filter((c) => c.kind === 'write')];
});

// First index whose kind differs from the previous column's, so the
// template can drop a visual divider between the read and write blocks.
const firstWriteIndex = computed(() => columns.value.findIndex((c) => c.kind === 'write'));

// The mark's accessible name carries the grant kind, since shape and colour
// alone must not be the only difference between the two granted states.
const KIND_WORDS = { read: 'read', write: 'state-changing' } as const;

function groupMarkLabel(group: string, col: Column): string {
  return groupHasPermission(group, col.name)
    ? `${groupLabel(group)} grants ${col.name} (${KIND_WORDS[col.kind]})`
    : `${groupLabel(group)} does not grant ${col.name}`;
}

function meMarkLabel(col: Column): string {
  return meHasPermission(col.name)
    ? `You hold ${col.name} (${KIND_WORDS[col.kind]})`
    : `You do not hold ${col.name}`;
}

function groupHasPermission(group: string, permission: string): boolean {
  return (groupPermissions.value[group] ?? []).includes(permission);
}

function meHasPermission(permission: string): boolean {
  return myGrants.value.some((grant) => grant.permission === permission);
}
</script>

<template>
  <AsyncState
    :loading="loading"
    :error="error"
    error-title="Could not load entitlements"
    :session-expired="sessionExpired"
    :access-denied="accessDenied"
    :empty="columns.length === 0"
    loading-label="Loading entitlements…"
  >
    <template #empty>
      <header>
        <h2>No permissions declared</h2>
        <p>No permissions are declared in the policy yet.</p>
      </header>
    </template>

    <section class="af-sect ep" aria-labelledby="ep-table-heading">
      <h2 id="ep-table-heading">Permissions by group</h2>
      <p class="af-help">
        Every permission this platform grants, and which groups hold each one. The You column is
        your own resolved access. Columns for your groups are marked “you”. Missing something you
        need? Contact the AF admins.
      </p>

      <p class="ep__summary" data-testid="ep-summary">
        <template v-if="matchedGroups.length > 0">
          You belong to
          <span v-for="(g, i) in matchedGroups" :key="g">
            <code>{{ g }}</code
            ><span v-if="i < matchedGroups.length - 1">, </span>
          </span>
          — recognized groups, plus the baseline every signed-in user gets.
        </template>
        <template v-else>
          None of your groups are recognized here — you only get the baseline every signed-in user
          gets.
        </template>
      </p>

      <p class="ep__legend">
        <span><EntitlementMark kind="read" /> Granted (read)</span>
        <span><EntitlementMark kind="write" /> Granted (state-changing)</span>
        <span><EntitlementMark kind="none" /> Not granted</span>
      </p>

      <!-- Permissions run down the rows and groups run across the columns
           (not the reverse) because this axis only grows in one direction:
           services.yaml's per-tool required_permission (see
           mcp/registry.py) means the permission list gets longer as
           services split their tools more finely, while the group list
           stays whatever a handful of admins curated in policy.yaml. Rows
           grow the page down, which is a normal scroll; columns growing
           sideways scroll inside the box, with the permission column pinned
           so every mark stays readable against its row. -->
      <div class="table-container af-box">
        <table class="af-compact ep__matrix table">
          <caption class="sr-only">
            Permission to group entitlement matrix, with your resolved access as the first column
          </caption>
          <thead>
            <tr>
              <th scope="col" class="ep__pin">Permission</th>
              <th scope="col" class="ep__mark-col ep__you">You</th>
              <th
                v-for="group in sortedGroups"
                :key="group"
                scope="col"
                class="ep__mark-col"
                :class="{ ep__mine: isMineGroup(group) }"
              >
                {{ groupLabel(group) }}
                <span v-if="isMineGroup(group)" class="badge" data-variant="outline">you</span>
              </th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="(col, i) in columns"
              :key="col.name"
              :class="{ ep__divider: i === firstWriteIndex }"
            >
              <th scope="row" class="ep__pin">
                <span class="ep__perm">
                  <code>{{ col.name }}</code>
                  <InfoTip
                    :id="`ep-perm-${col.name}`"
                    :text="col.description"
                    :label="`About ${col.name}`"
                  />
                </span>
              </th>
              <td class="ep__mark-col ep__you">
                <EntitlementMark
                  :kind="meHasPermission(col.name) ? col.kind : 'none'"
                  :label="meMarkLabel(col)"
                />
              </td>
              <td
                v-for="group in sortedGroups"
                :key="group"
                class="ep__mark-col"
                :class="{ ep__mine: isMineGroup(group) }"
              >
                <EntitlementMark
                  :kind="groupHasPermission(group, col.name) ? col.kind : 'none'"
                  :label="groupMarkLabel(group, col)"
                />
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>
  </AsyncState>
</template>

<style scoped>
.ep__summary,
.ep__legend {
  margin: 0;
  font-size: var(--text-13);
}

.ep__legend {
  color: var(--color-af-text-secondary);
}

.ep__legend {
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-4) var(--space-16);
  font-size: var(--text-12);
}

.ep__legend > span {
  display: inline-flex;
  align-items: center;
  gap: var(--space-4);
}

/* The permission column stays put while the group columns scroll under it. */
.ep__pin {
  position: sticky;
  left: 0;
  z-index: 1;
  background: var(--color-af-bg);
  border-right: 1px solid var(--color-af-border);
}

/* Centre the info button on the name's own line box; vertical-align cannot,
   since the tooltip trigger is a flex container. */
.ep__perm {
  display: inline-flex;
  align-items: center;
  gap: var(--space-4);
}

.ep__mark-col {
  text-align: center;
}

.ep__you {
  font-weight: 600;
}

.ep__mine,
.ep__you {
  background: var(--color-af-bg-subtle);
}

/* Boundary between the read and state-changing permission blocks. */
.ep__divider th,
.ep__divider td {
  border-top: 1px solid var(--color-af-border-strong);
}
</style>
