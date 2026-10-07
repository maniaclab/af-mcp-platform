<script setup lang="ts">
/**
 * AdminPage.vue -- body of the /admin page, reachable only once GET
 * /v1/identities reports `is_admin: true` (gated client-side in
 * Base.astro's nav script -- this is a static build with no per-request
 * server auth state).
 *
 * Lets an admin view another subject's usage: a dropdown fed by GET
 * /v1/usage/subjects (only subjects with recorded activity -- never a full
 * Keycloak user directory), and selecting one renders that subject's usage
 * via UsagePage.vue's existing rendering (its `subject` prop), rather than
 * duplicating any of that markup here.
 */
import { ref, onMounted } from 'vue';
import {
  AccessDeniedError,
  fetchAnnotationMismatches,
  fetchCredmonStatus,
  fetchMaintenanceStatus,
  fetchToolMappingDrift,
  fetchUsageSubjects,
  runCredmonSync,
  SessionExpiredError,
  setMaintenanceStatus,
} from '../lib/api';
import type {
  AnnotationMismatch,
  CredmonStatus,
  MaintenanceStatus,
  ToolMappingDrift,
  UsageSubject,
} from '../lib/api';
import {
  credmonHealth,
  credmonKindRows,
  credmonNextRunAt,
  credmonSyncErrorMessage,
} from '../lib/credmonStatus';
import type { CredmonHealth } from '../lib/credmonStatus';
import { maintenanceErrorMessage } from '../lib/maintenanceBanner';
import { formatRelative } from '../lib/relativeTime';
import UsagePage from './UsagePage.vue';

const subjects = ref<UsageSubject[]>([]);
const loading = ref(true);
const error = ref<string | null>(null);
const sessionExpired = ref(false);
const accessDenied = ref<AccessDeniedError | null>(null);
const selectedSubject = ref<string>('');

/** unixname is the most recognizable label to an operator; fall back to
 * email, then the bare subject, for a principal the cache couldn't resolve. */
function subjectLabel(s: UsageSubject): string {
  return s.unixname || s.email || s.subject;
}

/** Same fallback chain as subjectLabel, applied to MaintenanceStatus's
 * enabled_by/enabled_by_unixname/enabled_by_email trio instead of a
 * UsageSubject -- kept separate since the two response shapes differ. */
function enabledByLabel(status: MaintenanceStatus): string {
  return status.enabled_by_unixname || status.enabled_by_email || status.enabled_by || '';
}

onMounted(async () => {
  try {
    const res = await fetchUsageSubjects();
    subjects.value = res.subjects;
  } catch (err) {
    if (err instanceof AccessDeniedError) {
      accessDenied.value = err;
    } else if (err instanceof SessionExpiredError) {
      sessionExpired.value = true;
    } else {
      error.value = err instanceof Error ? err.message : 'Failed to load subjects.';
    }
  } finally {
    loading.value = false;
  }
});

function reload(): void {
  location.reload();
}

// ── Maintenance mode ────────────────────────────────────────────────────
// GET is unauthenticated (see fetchMaintenanceStatus's docstring), so this
// onMounted never sees AccessDeniedError/SessionExpiredError -- only a
// generic fetch failure, surfaced the same way `error` above is. The POST
// (setMaintenanceStatus) DOES require a real Bearer, so its own errors are
// handled separately below.
const maintenanceStatus = ref<MaintenanceStatus | null>(null);
const maintenanceLoading = ref(true);
const maintenanceError = ref<string | null>(null);
const maintenanceReason = ref('');
const maintenanceSaving = ref(false);
const maintenanceToggleError = ref<string | null>(null);
const maintenanceSessionExpired = ref(false);

onMounted(async () => {
  try {
    maintenanceStatus.value = await fetchMaintenanceStatus();
  } catch (err) {
    maintenanceError.value =
      err instanceof Error ? err.message : 'Could not load maintenance status.';
  } finally {
    maintenanceLoading.value = false;
  }
});

/**
 * Shared by enable/disableMaintenance: a SessionExpiredError from
 * setMaintenanceStatus (apiFetch's silent-renew-then-401 path, e.g. an
 * admin's token expiring mid-edit) gets the Usage section's own dedicated
 * "Reload" button UI rather than maintenanceErrorMessage's plain sentence --
 * same distinct-state treatment the sessionExpired ref above already gives
 * the identical condition on the usage-subjects fetch.
 */
function handleMaintenanceToggleError(err: unknown): void {
  if (err instanceof SessionExpiredError) {
    maintenanceSessionExpired.value = true;
  } else {
    maintenanceToggleError.value = maintenanceErrorMessage(err);
  }
}

async function enableMaintenance(): Promise<void> {
  maintenanceSaving.value = true;
  maintenanceToggleError.value = null;
  try {
    maintenanceStatus.value = await setMaintenanceStatus(
      true,
      maintenanceReason.value.trim() || undefined,
    );
  } catch (err) {
    handleMaintenanceToggleError(err);
  } finally {
    maintenanceSaving.value = false;
  }
}

async function disableMaintenance(): Promise<void> {
  maintenanceSaving.value = true;
  maintenanceToggleError.value = null;
  try {
    maintenanceStatus.value = await setMaintenanceStatus(false);
    maintenanceReason.value = '';
  } catch (err) {
    handleMaintenanceToggleError(err);
  } finally {
    maintenanceSaving.value = false;
  }
}

function formatEnabledAt(epochSeconds: number): string {
  return new Date(epochSeconds * 1000).toLocaleString('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    timeZoneName: 'short',
  });
}

// ── Annotation/policy mismatches (issue #238 B.8) ───────────────────────
// Admin-only (require_admin), same as fetchUsageSubjects above, so the
// same AccessDeniedError/SessionExpiredError handling applies.
const mismatches = ref<AnnotationMismatch[]>([]);
const mismatchesLoading = ref(true);
const mismatchesError = ref<string | null>(null);
const mismatchesSessionExpired = ref(false);
const mismatchesAccessDenied = ref<AccessDeniedError | null>(null);

onMounted(async () => {
  try {
    mismatches.value = await fetchAnnotationMismatches();
  } catch (err) {
    if (err instanceof AccessDeniedError) {
      mismatchesAccessDenied.value = err;
    } else if (err instanceof SessionExpiredError) {
      mismatchesSessionExpired.value = true;
    } else {
      mismatchesError.value =
        err instanceof Error ? err.message : 'Failed to load annotation mismatches.';
    }
  } finally {
    mismatchesLoading.value = false;
  }
});

function resolvedViaLabel(m: AnnotationMismatch): string {
  if (m.resolved_via === 'target_action_types') return 'target_action_types glob override';
  if (m.resolved_via === 'permission') return `permission ${m.permission}`;
  return 'default fallback (read)';
}

// ── Tool mapping drift (issue #330) ─────────────────────────────────────
// Admin-only like the sections above; one error string is enough here since
// the mismatches section already shows the dedicated session/access states
// for the same credential.
const drifts = ref<ToolMappingDrift[]>([]);
const driftsLoading = ref(true);
const driftsError = ref<string | null>(null);

onMounted(async () => {
  try {
    drifts.value = await fetchToolMappingDrift();
  } catch (err) {
    driftsError.value = err instanceof Error ? err.message : 'Failed to load tool mapping drift.';
  } finally {
    driftsLoading.value = false;
  }
});

// ── HTCondor credmon sync (docs/credmon.md) ─────────────────────────────
// Admin-only like the sections above; the mismatches section already shows
// the dedicated session/access states for the same credential, so a load
// failure here is one error string.
const credmon = ref<CredmonStatus | null>(null);
const credmonLoading = ref(true);
const credmonError = ref<string | null>(null);
const credmonSyncing = ref(false);
const credmonSyncError = ref<string | null>(null);
// Errors list starts expanded only when short enough to scan at a glance.
const CREDMON_ERRORS_OPEN_MAX = 3;

async function loadCredmon(): Promise<void> {
  try {
    credmon.value = await fetchCredmonStatus();
    credmonError.value = null;
  } catch (err) {
    credmonError.value = err instanceof Error ? err.message : 'Failed to load credmon status.';
  } finally {
    credmonLoading.value = false;
  }
}

onMounted(loadCredmon);

async function syncCredmonNow(): Promise<void> {
  credmonSyncing.value = true;
  credmonSyncError.value = null;
  try {
    await runCredmonSync();
    await loadCredmon();
  } catch (err) {
    credmonSyncError.value = credmonSyncErrorMessage(err);
  } finally {
    credmonSyncing.value = false;
  }
}

const CREDMON_HEALTH_LABELS: Record<CredmonHealth, string> = {
  disabled: 'Disabled',
  pending: 'No runs yet',
  healthy: 'Healthy',
  warning: 'Needs attention',
  error: 'Failing',
};

function nowSeconds(): number {
  return Date.now() / 1000;
}
</script>

<template>
  <div class="ap">
    <section class="ap__section" aria-label="Usage by subject">
      <h2 class="ap__section-title">Usage</h2>

      <div v-if="loading" class="ap__loading" aria-live="polite" aria-label="Loading subjects">
        Loading subjects…
      </div>

      <!-- Session expired -->
      <div v-else-if="sessionExpired" class="ap__error" role="alert">
        <span class="ap__error-title">Session expired</span>
        <span class="ap__error-body">
          Your session has expired.
          <button type="button" class="ap__reload" @click="reload">Reload</button>
          to re-authenticate.
        </span>
      </div>

      <!-- Access denied: covers a stale client-side is_admin (the broker's
           require_admin 403s a caller demoted out of the admin group since
           the nav last checked), same wording as sibling pages. -->
      <div v-else-if="accessDenied" class="ap__error" role="alert">
        <span class="ap__error-title">Access not yet granted</span>
        <span class="ap__error-body">{{ accessDenied.message }}</span>
      </div>

      <!-- Error -->
      <div v-else-if="error" class="ap__error" role="alert">
        <span class="ap__error-title">Could not load subjects</span>
        <span class="ap__error-body">{{ error }}</span>
      </div>

      <div v-else-if="subjects.length === 0" class="ap__placeholder">
        No subjects with recorded usage yet.
      </div>

      <template v-else>
        <div class="ap__form-group">
          <label for="ap-usage-subject" class="ap__form-label">Subject</label>
          <select id="ap-usage-subject" v-model="selectedSubject" class="ap__select">
            <option value="" disabled>Select a subject…</option>
            <option v-for="s in subjects" :key="s.subject" :value="s.subject">
              {{ subjectLabel(s) }}
            </option>
          </select>
        </div>

        <!-- Keyed on the selection so switching subjects remounts UsagePage,
             the same way it already reloads when its own window selector
             changes -- no separate refetch wiring needed here. -->
        <UsagePage v-if="selectedSubject" :key="selectedSubject" :subject="selectedSubject" />
      </template>
    </section>

    <section class="ap__section" aria-label="Maintenance mode">
      <h2 class="ap__section-title">Maintenance mode</h2>

      <div
        v-if="maintenanceLoading"
        class="ap__loading"
        aria-live="polite"
        aria-label="Loading maintenance status"
      >
        Loading maintenance status…
      </div>

      <div v-else-if="maintenanceError" class="ap__error" role="alert">
        <span class="ap__error-title">Could not load maintenance status</span>
        <span class="ap__error-body">{{ maintenanceError }}</span>
      </div>

      <template v-else-if="maintenanceStatus">
        <p class="ap__maintenance-status">
          Status:
          <strong>{{ maintenanceStatus.enabled ? 'Enabled' : 'Disabled' }}</strong>
        </p>
        <dl v-if="maintenanceStatus.enabled" class="ap__maintenance-details">
          <dt>Reason</dt>
          <dd>{{ maintenanceStatus.reason || '(none given)' }}</dd>
          <dt>Enabled by</dt>
          <dd>{{ enabledByLabel(maintenanceStatus) }}</dd>
          <dt>Enabled at</dt>
          <dd>
            {{ maintenanceStatus.enabled_at ? formatEnabledAt(maintenanceStatus.enabled_at) : '—' }}
          </dd>
        </dl>

        <div class="ap__form-group">
          <label for="ap-maintenance-reason" class="ap__form-label"
            >Reason (shown to every visitor)</label
          >
          <input
            id="ap-maintenance-reason"
            v-model="maintenanceReason"
            data-af-maintenance-reason
            type="text"
            class="ap__input"
            placeholder="e.g. Scheduled Postgres upgrade, back by 14:00 UTC"
          />
        </div>

        <!-- Session expired mid-edit: same dedicated "Reload" UI as the
             Usage section's identical condition above. -->
        <div v-if="maintenanceSessionExpired" class="ap__error" role="alert">
          <span class="ap__error-title">Session expired</span>
          <span class="ap__error-body">
            Your session has expired.
            <button type="button" class="ap__reload" @click="reload">Reload</button>
            to re-authenticate.
          </span>
        </div>

        <div v-else-if="maintenanceToggleError" class="ap__error" role="alert">
          <span class="ap__error-body">{{ maintenanceToggleError }}</span>
        </div>

        <div class="ap__maintenance-actions">
          <button
            type="button"
            data-af-maintenance-enable
            class="ap__btn ap__btn--danger"
            :disabled="maintenanceSaving || maintenanceStatus.enabled"
            @click="enableMaintenance"
          >
            Enable maintenance mode
          </button>
          <button
            type="button"
            data-af-maintenance-disable
            class="ap__btn ap__btn--confirm"
            :disabled="maintenanceSaving || !maintenanceStatus.enabled"
            @click="disableMaintenance"
          >
            Disable maintenance mode
          </button>
        </div>
      </template>
    </section>

    <section class="ap__section" aria-label="Annotation/policy mismatches">
      <h2 class="ap__section-title">Annotation mismatches</h2>
      <p class="ap__legend">
        Visibility only; enforcement is unchanged. A row means the backend's
        <code>readOnlyHint</code> disagrees with the broker's <code>action_type</code>. To resolve
        it, set a <code>target_action_types</code> glob for the service (keys are service names;
        globs match the prefixed tool name), declare the permission under
        <code>custom_permissions</code> if it is site-defined, or ask the backend to correct its
        annotation.
      </p>

      <div
        v-if="mismatchesLoading"
        class="ap__loading"
        aria-live="polite"
        aria-label="Loading annotation mismatches"
      >
        Loading annotation mismatches…
      </div>

      <div v-else-if="mismatchesSessionExpired" class="ap__error" role="alert">
        <span class="ap__error-title">Session expired</span>
        <span class="ap__error-body">
          Your session has expired.
          <button type="button" class="ap__reload" @click="reload">Reload</button>
          to re-authenticate.
        </span>
      </div>

      <div v-else-if="mismatchesAccessDenied" class="ap__error" role="alert">
        <span class="ap__error-title">Access not yet granted</span>
        <span class="ap__error-body">{{ mismatchesAccessDenied.message }}</span>
      </div>

      <div v-else-if="mismatchesError" class="ap__error" role="alert">
        <span class="ap__error-title">Could not load annotation mismatches</span>
        <span class="ap__error-body">{{ mismatchesError }}</span>
      </div>

      <div v-else-if="mismatches.length === 0" class="ap__placeholder">No mismatches.</div>

      <table v-else class="ap__mismatch-table">
        <thead>
          <tr>
            <th scope="col">Service</th>
            <th scope="col">Tool</th>
            <th scope="col">Backend readOnlyHint</th>
            <th scope="col">Broker action_type</th>
            <th scope="col">Resolved via</th>
            <th scope="col">Permission</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="m in mismatches" :key="`${m.service}.${m.tool}`">
            <td>{{ m.service }}</td>
            <td>{{ m.tool }}</td>
            <td>readOnlyHint={{ m.declared_read_only_hint }}</td>
            <td>{{ m.resolved_action_type }}</td>
            <td>{{ resolvedViaLabel(m) }}</td>
            <td>{{ m.permission }}</td>
          </tr>
        </tbody>
      </table>
    </section>

    <section class="ap__section" aria-label="Tool mapping drift">
      <h2 class="ap__section-title">Tool mapping drift</h2>
      <p class="ap__legend">
        Visibility only. <strong>Unmapped</strong> tools are advertised by the backend but have no
        <code>required_permission</code> entry and no <code>__default__</code>, so they are
        disabled: add them to the service's <code>required_permission</code>.
        <strong>Stale</strong> entries are mapped keys the backend no longer advertises (usually a
        backend rename): rename or remove them.
      </p>

      <div
        v-if="driftsLoading"
        class="ap__loading"
        aria-live="polite"
        aria-label="Loading tool mapping drift"
      >
        Loading tool mapping drift…
      </div>

      <div v-else-if="driftsError" class="ap__error" role="alert">
        <span class="ap__error-title">Could not load tool mapping drift</span>
        <span class="ap__error-body">{{ driftsError }}</span>
      </div>

      <div v-else-if="drifts.length === 0" class="ap__placeholder">No tool mapping drift.</div>

      <table v-else class="ap__mismatch-table">
        <thead>
          <tr>
            <th scope="col">Service</th>
            <th scope="col">Unmapped (advertised, disabled)</th>
            <th scope="col">Stale (mapped, not advertised)</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="d in drifts" :key="d.service">
            <td>{{ d.service }}</td>
            <td>{{ d.unmapped.join(', ') }}</td>
            <td>{{ d.stale.join(', ') }}</td>
          </tr>
        </tbody>
      </table>
    </section>

    <section class="ap__section" aria-label="HTCondor credmon sync">
      <h2 class="ap__section-title">HTCondor credmon sync</h2>
      <p class="ap__legend">
        The broker stores a short-lived token per user and credential type in the facility's credd,
        so jobs that request <code>use_oauth_services = af_krb5, af_x509</code> get the user's
        credentials on the worker node. Only one broker replica runs each sync.
      </p>

      <div
        v-if="credmonLoading"
        class="ap__loading"
        aria-live="polite"
        aria-label="Loading credmon status"
      >
        Loading credmon status…
      </div>

      <div v-else-if="credmonError" class="ap__error" role="alert">
        <span class="ap__error-title">Could not load credmon status</span>
        <span class="ap__error-body">{{ credmonError }}</span>
      </div>

      <div v-else-if="credmon && !credmon.enabled" class="ap__placeholder">
        Not enabled on this broker (<code>CREDMON_ENABLED</code>).
      </div>

      <template v-else-if="credmon">
        <div class="ap__credmon-summary">
          <span
            class="ap__credmon-pill"
            :class="`ap__credmon-pill--${credmonHealth(credmon, nowSeconds())}`"
            data-af-credmon-health
          >
            {{ CREDMON_HEALTH_LABELS[credmonHealth(credmon, nowSeconds())] }}
          </span>
          <button
            type="button"
            data-af-credmon-sync
            class="ap__btn ap__btn--confirm"
            :disabled="credmonSyncing"
            @click="syncCredmonNow"
          >
            {{ credmonSyncing ? 'Syncing…' : 'Run sync now' }}
          </button>
        </div>

        <div v-if="credmonSyncError" class="ap__error" role="alert">
          <span class="ap__error-body">{{ credmonSyncError }}</span>
        </div>

        <dl class="ap__maintenance-details">
          <dt>Last run</dt>
          <dd v-if="credmon.last_run">
            <span :title="formatEnabledAt(credmon.last_run.finished_at)">
              {{ formatRelative(credmon.last_run.finished_at * 1000) }}
            </span>
            ({{ credmon.last_run.trigger === 'manual' ? 'run by an admin' : 'scheduled' }}, on
            {{ credmon.last_run.holder }})
          </dd>
          <dd v-else>No sync has run yet.</dd>
          <dt>Last success</dt>
          <dd>
            <span
              v-if="credmon.last_run?.last_success_at"
              :title="formatEnabledAt(credmon.last_run.last_success_at)"
            >
              {{ formatRelative(credmon.last_run.last_success_at * 1000) }}
            </span>
            <template v-else>Never</template>
          </dd>
          <dt>Next run</dt>
          <dd v-if="credmonNextRunAt(credmon) !== null">
            <span :title="formatEnabledAt(credmonNextRunAt(credmon) as number)">
              {{ formatRelative((credmonNextRunAt(credmon) as number) * 1000) }}
            </span>
          </dd>
          <dd v-else>Within a minute of startup.</dd>
        </dl>

        <table class="ap__mismatch-table">
          <thead>
            <tr>
              <th scope="col">Credential</th>
              <th scope="col">credd service</th>
              <th scope="col">Stored</th>
              <th scope="col">Skipped: not linked</th>
              <th scope="col">Skipped: no POSIX user</th>
              <th scope="col">Failed</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="row in credmonKindRows(credmon)" :key="row.kind">
              <td>{{ row.kind }}</td>
              <td>
                <code>{{ row.service }}</code>
              </td>
              <td>{{ row.stored }}</td>
              <td>{{ row.notLinked }}</td>
              <td>{{ row.noPosix }}</td>
              <td>{{ row.failed }}</td>
            </tr>
          </tbody>
        </table>

        <details
          v-if="credmon.last_run && credmon.last_run.errors.length > 0"
          class="ap__credmon-errors"
          :open="credmon.last_run.errors.length <= CREDMON_ERRORS_OPEN_MAX"
        >
          <summary>
            Errors from the last run ({{
              credmon.last_run.errors.length + credmon.last_run.errors_truncated
            }})
          </summary>
          <ul>
            <li v-for="(e, i) in credmon.last_run.errors" :key="i">{{ e }}</li>
          </ul>
          <p v-if="credmon.last_run.errors_truncated > 0" class="ap__legend">
            +{{ credmon.last_run.errors_truncated }} more not shown.
          </p>
        </details>
      </template>
    </section>
  </div>
</template>

<style scoped>
.ap {
  display: flex;
  flex-direction: column;
  gap: 1.25rem;
}

.ap__section {
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

.ap__section-title {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.8125rem;
  font-weight: 600;
  letter-spacing: 0.05em;
  text-transform: uppercase;
  color: var(--color-af-text);
  margin: 0;
}

.ap__form-group {
  display: flex;
  flex-direction: column;
  gap: 0.375rem;
  max-width: 24rem;
}

.ap__form-label {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.6875rem;
  font-weight: 600;
  letter-spacing: 0.06em;
  text-transform: uppercase;
  color: var(--color-af-dim);
}

.ap__select {
  background: var(--color-af-void);
  border: 1px solid var(--color-af-muted);
  border-radius: 3px;
  color: var(--color-af-text);
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.875rem;
  padding: 0.5rem 0.75rem;
  transition: border-color 150ms;
  width: 100%;
}
.ap__select:focus {
  outline: none;
  border-color: var(--color-af-teal);
  box-shadow: 0 0 0 2px rgb(from var(--color-af-teal) r g b / 0.15);
}

.ap__loading {
  padding: 2rem;
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.8125rem;
  color: var(--color-af-dim);
}

.ap__error {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
  padding: 1.25rem;
  border: 1px solid rgb(from var(--color-af-red) r g b / 0.2);
  border-radius: 4px;
  background: rgb(from var(--color-af-red) r g b / 0.05);
}

.ap__error-title {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.8125rem;
  font-weight: 600;
  color: var(--color-af-red);
}

.ap__error-body {
  font-size: 0.875rem;
  color: var(--color-af-dim);
}

.ap__reload {
  font: inherit;
  color: var(--color-af-teal);
  background: none;
  border: none;
  padding: 0;
  cursor: pointer;
  text-decoration: underline;
}

.ap__placeholder {
  padding: 3rem 1.5rem;
  text-align: center;
  border: 1px dashed var(--color-af-border);
  border-radius: 4px;
  color: var(--color-af-dim);
  font-size: 0.875rem;
  margin: 0;
}

.ap__maintenance-status {
  font-size: 0.875rem;
  color: var(--color-af-text);
  margin: 0;
}

.ap__maintenance-details {
  display: grid;
  grid-template-columns: auto 1fr;
  gap: 0.375rem 1rem;
  margin: 0;
  font-size: 0.875rem;
}
.ap__maintenance-details dt {
  color: var(--color-af-dim);
}
.ap__maintenance-details dd {
  margin: 0;
  color: var(--color-af-text);
  word-break: break-word;
}

.ap__input {
  background: var(--color-af-void);
  border: 1px solid var(--color-af-muted);
  border-radius: 3px;
  color: var(--color-af-text);
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.875rem;
  padding: 0.5rem 0.75rem;
  transition: border-color 150ms;
  width: 100%;
}
.ap__input:focus {
  outline: none;
  border-color: var(--color-af-teal);
  box-shadow: 0 0 0 2px rgb(from var(--color-af-teal) r g b / 0.15);
}

.ap__maintenance-actions {
  display: flex;
  gap: 0.75rem;
}

.ap__btn {
  display: inline-flex;
  align-items: center;
  padding: 0.5rem 1rem;
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.6875rem;
  font-weight: 600;
  letter-spacing: 0.06em;
  text-transform: uppercase;
  border-radius: 3px;
  border: 1px solid;
  cursor: pointer;
  transition:
    background 120ms,
    color 120ms,
    border-color 120ms;
  white-space: nowrap;
}
.ap__btn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}
.ap__btn:focus-visible {
  outline: 2px solid var(--color-af-teal);
  outline-offset: 2px;
}

.ap__btn--danger {
  background: rgb(from var(--color-af-red) r g b / 0.1);
  color: var(--color-af-red);
  border-color: rgb(from var(--color-af-red) r g b / 0.3);
}
.ap__btn--danger:not(:disabled):hover {
  background: rgb(from var(--color-af-red) r g b / 0.18);
}

.ap__btn--confirm {
  background: rgb(from var(--color-af-teal) r g b / 0.12);
  color: var(--color-af-teal);
  border-color: rgb(from var(--color-af-teal) r g b / 0.3);
}
.ap__btn--confirm:not(:disabled):hover {
  background: rgb(from var(--color-af-teal) r g b / 0.2);
  border-color: rgb(from var(--color-af-teal) r g b / 0.5);
}

.ap__legend {
  margin: 0;
  font-size: 0.8125rem;
  color: var(--color-af-dim);
}

.ap__mismatch-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.875rem;
}
.ap__mismatch-table th {
  text-align: left;
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.6875rem;
  font-weight: 600;
  letter-spacing: 0.06em;
  text-transform: uppercase;
  color: var(--color-af-dim);
  padding: 0.5rem 0.75rem;
  border-bottom: 1px solid var(--color-af-border);
}
.ap__mismatch-table td {
  padding: 0.5rem 0.75rem;
  color: var(--color-af-text);
  border-bottom: 1px solid var(--color-af-border);
  word-break: break-word;
}
.ap__credmon-summary {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 0.75rem;
}

.ap__credmon-pill {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.6875rem;
  font-weight: 600;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  padding: 0.1875rem 0.5rem;
  border-radius: 2px;
  border: 1px solid;
}
.ap__credmon-pill--healthy {
  background: rgb(from var(--color-af-green) r g b / 0.08);
  color: var(--color-af-green);
  border-color: rgb(from var(--color-af-green) r g b / 0.2);
}
.ap__credmon-pill--pending,
.ap__credmon-pill--disabled {
  background: rgb(from var(--color-af-teal) r g b / 0.08);
  color: var(--color-af-teal);
  border-color: rgb(from var(--color-af-teal) r g b / 0.2);
}
.ap__credmon-pill--warning {
  background: rgb(from var(--color-af-amber) r g b / 0.08);
  color: var(--color-af-amber);
  border-color: rgb(from var(--color-af-amber) r g b / 0.2);
}
.ap__credmon-pill--error {
  background: rgb(from var(--color-af-red) r g b / 0.08);
  color: var(--color-af-red);
  border-color: rgb(from var(--color-af-red) r g b / 0.2);
}

.ap__credmon-errors {
  font-size: 0.8125rem;
  color: var(--color-af-text);
}
.ap__credmon-errors summary {
  cursor: pointer;
  color: var(--color-af-red);
}
.ap__credmon-errors ul {
  margin: 0.5rem 0 0;
  padding-left: 1.25rem;
  font-family: 'IBM Plex Mono', monospace;
  word-break: break-word;
}
</style>
