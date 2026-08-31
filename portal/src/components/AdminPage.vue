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
  fetchMaintenanceStatus,
  fetchUsageSubjects,
  SessionExpiredError,
  setMaintenanceStatus,
} from '../lib/api';
import type { MaintenanceStatus, UsageSubject } from '../lib/api';
import { maintenanceErrorMessage } from '../lib/maintenanceBanner';
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
          <dd>{{ maintenanceStatus.enabled_by }}</dd>
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
</style>
