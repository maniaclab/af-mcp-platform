<script setup lang="ts">
/**
 * EntitlementsPage.vue — "why do/don't I have access" in one place.
 *
 * Fetches both GET /v1/permissions (the caller's own groups + resolved
 * grants) and GET /v1/entitlements (the static group -> permission table,
 * same for every caller) in parallel, and renders the reference table with
 * the caller's own groups marked -- so a denied user can see both "what I'm
 * in" and "what any group would grant" without contacting an admin first.
 * See docs/plans/2026-09-01-ops-platform-usability.md.
 */
import { onMounted, ref } from 'vue';
import {
  AccessDeniedError,
  fetchEntitlements,
  fetchPermissions,
  SessionExpiredError,
  type PermissionsResponse,
} from '../lib/api';

const groupPermissions = ref<Record<string, string[]>>({});
const myGroups = ref<string[]>([]);
const myGrants = ref<PermissionsResponse['grants']>([]);
const loading = ref(true);
const error = ref<string | null>(null);
const sessionExpired = ref(false);
const accessDenied = ref<AccessDeniedError | null>(null);

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
      <section class="ep__section" aria-labelledby="ep-mine-heading">
        <h2 id="ep-mine-heading" class="ep__heading">Your access</h2>
        <p v-if="myGroups.length === 0" class="ep__empty">
          You're not currently in any group this platform recognizes — see the reference table below
          for what each one grants, and ask your AF administrators to add you to one.
        </p>
        <template v-else>
          <p class="ep__mine-groups">
            You're in:
            <span v-for="g in myGroups" :key="g" class="ep__group-pill">{{ g }}</span>
          </p>
          <p v-if="myGrants.length === 0" class="ep__empty">
            Those groups don't currently grant any permission this platform checks.
          </p>
          <ul v-else class="ep__grant-list">
            <li v-for="grant in myGrants" :key="grant.permission">
              <code>{{ grant.permission }}</code> — {{ grant.targets.join(', ') }}
            </li>
          </ul>
        </template>
      </section>

      <section class="ep__section" aria-labelledby="ep-table-heading">
        <h2 id="ep-table-heading" class="ep__heading">Entitlements reference</h2>
        <p class="ep__desc">Every group this platform recognizes, and what each one grants.</p>
        <table class="ep__table">
          <thead>
            <tr>
              <th scope="col">Group</th>
              <th scope="col">Permissions</th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="(perms, group) in groupPermissions"
              :key="group"
              :class="{ 'ep__row--mine': myGroups.includes(group) }"
            >
              <td>
                {{ group }}
                <span v-if="myGroups.includes(group)" class="ep__mine-badge">you</span>
              </td>
              <td>
                <code v-for="perm in perms" :key="perm" class="ep__perm-chip">{{ perm }}</code>
              </td>
            </tr>
          </tbody>
        </table>
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

.ep__mine-groups {
  font-size: 0.875rem;
  margin: 0 0 0.75rem;
}

.ep__group-pill {
  display: inline-block;
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.75rem;
  padding: 0.125rem 0.5rem;
  margin-left: 0.375rem;
  border-radius: 999px;
  background: var(--color-af-surface);
  border: 1px solid var(--color-af-border);
}

.ep__grant-list {
  font-size: 0.875rem;
  line-height: 1.7;
  margin: 0;
  padding-left: 1.25rem;
}

.ep__table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.875rem;
}

.ep__table th,
.ep__table td {
  text-align: left;
  padding: 0.5rem 0.75rem;
  border-bottom: 1px solid var(--color-af-border);
  vertical-align: top;
}

.ep__row--mine {
  background: var(--color-af-surface);
}

.ep__mine-badge {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.625rem;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  color: var(--color-af-teal);
  margin-left: 0.375rem;
}

.ep__perm-chip {
  display: inline-block;
  font-size: 0.75rem;
  padding: 0.0625rem 0.375rem;
  margin: 0.125rem 0.25rem 0.125rem 0;
  border-radius: 3px;
  background: var(--color-af-surface);
}
</style>
