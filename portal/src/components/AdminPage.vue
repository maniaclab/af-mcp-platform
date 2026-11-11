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
import { computed, onMounted, ref } from 'vue';
import {
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
import { formatDateTime, formatRelative } from '../lib/relativeTime';
import { useLoadState } from '../lib/useLoadState';
import AsyncState from './ui/AsyncState.vue';
import ConfirmDialog from './ui/ConfirmDialog.vue';
import Disclosure from './ui/Disclosure.vue';
import StatusMark from './ui/StatusMark.vue';
import UsagePage from './UsagePage.vue';

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

/** Exact local time for a unix-seconds timestamp, shown on hover next to a relative one. */
function exactTime(epochSeconds: number): string {
  return formatDateTime(new Date(epochSeconds * 1000), { year: true });
}

function plural(n: number, one: string, many: string): string {
  return `${n} ${n === 1 ? one : many}`;
}

function nowSeconds(): number {
  return Date.now() / 1000;
}

// One load state per independently fetched panel, so one failing endpoint
// leaves the others usable.
const usageState = useLoadState();
const maintenanceState = useLoadState();
const mismatchState = useLoadState();
const driftState = useLoadState();
const credmonState = useLoadState();

// ── Usage by subject ────────────────────────────────────────────────────
const subjects = ref<UsageSubject[]>([]);
const selectedSubject = ref<string>('');

// ── Maintenance mode ────────────────────────────────────────────────────
// GET is unauthenticated (see fetchMaintenanceStatus's docstring), so its
// load never sees AccessDeniedError/SessionExpiredError -- only a generic
// fetch failure. The POST (setMaintenanceStatus) DOES require a real Bearer,
// so its own errors are handled separately below.
const maintenanceStatus = ref<MaintenanceStatus | null>(null);
const maintenanceReason = ref('');
const maintenanceSaving = ref(false);
const maintenanceToggleError = ref<string | null>(null);
const maintenanceSessionExpired = ref(false);
const confirmingEnable = ref(false);

/**
 * Shared by enable/disableMaintenance: a SessionExpiredError from
 * setMaintenanceStatus (apiFetch's silent-renew-then-401 path, e.g. an
 * admin's token expiring mid-edit) gets AsyncState's dedicated "Reload"
 * button rather than maintenanceErrorMessage's plain sentence.
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
  maintenanceSessionExpired.value = false;
  try {
    maintenanceStatus.value = await setMaintenanceStatus(
      true,
      maintenanceReason.value.trim() || undefined,
    );
  } catch (err) {
    handleMaintenanceToggleError(err);
  } finally {
    maintenanceSaving.value = false;
    confirmingEnable.value = false;
  }
}

async function disableMaintenance(): Promise<void> {
  maintenanceSaving.value = true;
  maintenanceToggleError.value = null;
  maintenanceSessionExpired.value = false;
  try {
    maintenanceStatus.value = await setMaintenanceStatus(false);
    maintenanceReason.value = '';
  } catch (err) {
    handleMaintenanceToggleError(err);
  } finally {
    maintenanceSaving.value = false;
  }
}

// ── Annotation/policy mismatches (issue #238 B.8) ───────────────────────
const mismatches = ref<AnnotationMismatch[]>([]);

function resolvedViaLabel(m: AnnotationMismatch): string {
  if (m.resolved_via === 'target_action_types') return 'target_action_types glob override';
  if (m.resolved_via === 'permission') return `permission ${m.permission}`;
  return 'default fallback (read)';
}

// ── Tool mapping drift (issue #330) ─────────────────────────────────────
const drifts = ref<ToolMappingDrift[]>([]);

// ── HTCondor credmon sync (docs/credmon.md) ─────────────────────────────
const credmon = ref<CredmonStatus | null>(null);
const credmonSyncing = ref(false);
const credmonSyncError = ref<string | null>(null);
// Errors list starts expanded only when short enough to scan at a glance.
const CREDMON_ERRORS_OPEN_MAX = 3;
const credmonErrorsOpen = ref(false);

async function refreshCredmon(): Promise<void> {
  credmon.value = await fetchCredmonStatus();
  credmonErrorsOpen.value = (credmon.value.last_run?.errors.length ?? 0) <= CREDMON_ERRORS_OPEN_MAX;
}

async function syncCredmonNow(): Promise<void> {
  credmonSyncing.value = true;
  credmonSyncError.value = null;
  try {
    await runCredmonSync();
    await refreshCredmon();
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

const CREDMON_HEALTH_TONES: Record<CredmonHealth, 'ok' | 'busy' | 'off' | 'warn' | 'bad'> = {
  disabled: 'off',
  pending: 'busy',
  healthy: 'ok',
  warning: 'warn',
  error: 'bad',
};

onMounted(() => {
  void usageState.run(async () => {
    subjects.value = (await fetchUsageSubjects()).subjects;
  }, 'Failed to load subjects.');
  void maintenanceState.run(async () => {
    maintenanceStatus.value = await fetchMaintenanceStatus();
  }, 'Could not load maintenance status.');
  void mismatchState.run(async () => {
    mismatches.value = await fetchAnnotationMismatches();
  }, 'Failed to load annotation mismatches.');
  void driftState.run(async () => {
    drifts.value = await fetchToolMappingDrift();
  }, 'Failed to load tool mapping drift.');
  void credmonState.run(refreshCredmon, 'Failed to load credmon status.');
});

// ── Page banner: the single most urgent message ─────────────────────────
// Problem beats warning; maintenance mode is reported by the shell's bar and
// in its own section below.
const issueCount = computed(() => mismatches.value.length + drifts.value.length);

const driftBannerText = computed(() => {
  const parts: string[] = [];
  if (mismatches.value.length > 0) {
    parts.push(plural(mismatches.value.length, 'annotation mismatch', 'annotation mismatches'));
  }
  if (drifts.value.length > 0) {
    parts.push(`${plural(drifts.value.length, 'service', 'services')} with tool mapping drift`);
  }
  return `${parts.join(' and ')}. Enforcement is unchanged; review them below.`;
});
</script>

<template>
  <div class="af-page compact ap">
    <!-- Page banner: the single most urgent message. -->
    <div v-if="issueCount > 0" class="af-banner warn" role="status" data-af-admin-banner>
      <span class="af-mark warn" aria-hidden="true"></span>
      <div>
        <b
          >{{
            plural(issueCount, 'tool configuration issue', 'tool configuration issues')
          }}
          found</b
        >
        {{ driftBannerText }}
      </div>
      <a class="af-btn s" :href="mismatches.length > 0 ? '#ap-mismatches' : '#ap-drift'"
        >Review issues</a
      >
    </div>

    <section class="af-sect" aria-labelledby="ap-usage-title">
      <h2 id="ap-usage-title">Usage across users</h2>
      <AsyncState
        inline
        :loading="usageState.loading.value"
        :error="usageState.error.value"
        error-title="Could not load subjects"
        :session-expired="usageState.sessionExpired.value"
        :access-denied="usageState.accessDenied.value"
        loading-label="Loading subjects…"
      >
        <p v-if="subjects.length === 0" class="ap__none">
          <StatusMark tone="off">No subjects with recorded usage yet.</StatusMark>
        </p>
        <template v-else>
          <div class="af-field">
            <label for="ap-usage-subject">Subject</label>
            <select id="ap-usage-subject" v-model="selectedSubject" class="af-input">
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
      </AsyncState>
    </section>

    <section id="ap-maintenance" class="af-sect" aria-labelledby="ap-maintenance-title">
      <h2 id="ap-maintenance-title">Maintenance mode</h2>
      <AsyncState
        inline
        :loading="maintenanceState.loading.value"
        :error="maintenanceState.error.value"
        error-title="Could not load maintenance status"
        :session-expired="maintenanceState.sessionExpired.value"
        :access-denied="maintenanceState.accessDenied.value"
        loading-label="Loading maintenance status…"
      >
        <template v-if="maintenanceStatus">
          <dl class="af-kv ap__kv">
            <dt>Status</dt>
            <dd data-af-maintenance-status>
              <StatusMark :tone="maintenanceStatus.enabled ? 'info' : 'off'">{{
                maintenanceStatus.enabled ? 'On' : 'Off'
              }}</StatusMark>
              <span
                v-if="maintenanceStatus.enabled && maintenanceStatus.enabled_at"
                class="ap__sub"
              >
                since
                <span :title="exactTime(maintenanceStatus.enabled_at)">{{
                  formatRelative(maintenanceStatus.enabled_at * 1000)
                }}</span>
              </span>
            </dd>
            <template v-if="maintenanceStatus.enabled">
              <dt>Reason</dt>
              <dd>{{ maintenanceStatus.reason || '(none given)' }}</dd>
              <dt>Enabled by</dt>
              <dd>{{ enabledByLabel(maintenanceStatus) }}</dd>
              <dt>Enabled at</dt>
              <dd>
                {{ maintenanceStatus.enabled_at ? exactTime(maintenanceStatus.enabled_at) : '—' }}
              </dd>
              <dt>Effect</dt>
              <dd>Everyone outside the admin group is refused and sees the message above.</dd>
            </template>
          </dl>

          <div class="af-field ap__message">
            <label for="ap-maintenance-reason">Message shown to users</label>
            <input
              id="ap-maintenance-reason"
              v-model="maintenanceReason"
              data-af-maintenance-reason
              type="text"
              class="af-input"
              placeholder="e.g. Scheduled Postgres upgrade, back by 14:00 UTC"
            />
          </div>

          <!-- A toggle failure (session expired mid-edit, 403, 409) shows in
               the same note AsyncState gives every panel. -->
          <AsyncState
            inline
            :loading="false"
            :error="maintenanceToggleError"
            error-title="Could not change maintenance mode"
            :session-expired="maintenanceSessionExpired"
            :access-denied="null"
          />

          <div class="ap__actions">
            <button
              v-if="!maintenanceStatus.enabled"
              type="button"
              data-af-maintenance-enable
              class="af-btn danger"
              :disabled="maintenanceSaving"
              @click="confirmingEnable = true"
            >
              Enable maintenance mode
            </button>
            <button
              v-else
              type="button"
              data-af-maintenance-disable
              class="af-btn secondary"
              :disabled="maintenanceSaving"
              @click="disableMaintenance"
            >
              {{ maintenanceSaving ? 'Disabling…' : 'Disable maintenance mode' }}
            </button>
          </div>

          <ConfirmDialog
            v-model:open="confirmingEnable"
            title="Enable maintenance mode?"
            confirm-label="Enable maintenance mode"
            busy-label="Enabling…"
            :busy="maintenanceSaving"
            danger
            @confirm="enableMaintenance"
          >
            <p>
              Everyone outside the admin group is refused on the portal API and the MCP endpoint,
              and sees
              {{
                maintenanceReason.trim()
                  ? `"${maintenanceReason.trim()}"`
                  : 'that the broker is in maintenance mode'
              }}. Their clients stop working until you disable it.
            </p>
          </ConfirmDialog>
        </template>
      </AsyncState>
    </section>

    <section id="ap-mismatches" class="af-sect" aria-labelledby="ap-mismatches-title">
      <h2 id="ap-mismatches-title">Annotation mismatches</h2>
      <p class="ap__legend">
        Visibility only; enforcement is unchanged. A row means the backend's
        <code>readOnlyHint</code> disagrees with the broker's <code>action_type</code>. To resolve
        it, set a <code>target_action_types</code> glob for the service (keys are service names;
        globs match the prefixed tool name), declare the permission under
        <code>custom_permissions</code> if it is site-defined, or ask the backend to correct its
        annotation.
      </p>
      <AsyncState
        inline
        :loading="mismatchState.loading.value"
        :error="mismatchState.error.value"
        error-title="Could not load annotation mismatches"
        :session-expired="mismatchState.sessionExpired.value"
        :access-denied="mismatchState.accessDenied.value"
        loading-label="Loading annotation mismatches…"
      >
        <p v-if="mismatches.length === 0" class="ap__none">
          <StatusMark tone="ok">No mismatches.</StatusMark>
        </p>
        <div v-else class="af-tbl-box">
          <table class="af-tbl compact">
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
                <td>
                  <code>{{ m.tool }}</code>
                </td>
                <td>readOnlyHint={{ m.declared_read_only_hint }}</td>
                <td>{{ m.resolved_action_type }}</td>
                <td class="sub">{{ resolvedViaLabel(m) }}</td>
                <td class="sub">{{ m.permission }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </AsyncState>
    </section>

    <section id="ap-drift" class="af-sect" aria-labelledby="ap-drift-title">
      <h2 id="ap-drift-title">Tool mapping drift</h2>
      <p class="ap__legend">
        Visibility only. <strong>Unmapped</strong> tools are advertised by the backend but have no
        <code>required_permission</code> entry and no <code>__default__</code>, so they are
        disabled: add them to the service's <code>required_permission</code>.
        <strong>Stale</strong> entries are mapped keys the backend no longer advertises (usually a
        backend rename): rename or remove them. <strong>Unroutable</strong> tools are advertised
        without the service's <code>prefix</code> (an <code>apply_namespace: false</code> backend
        that renamed its tools), so no caller sees them: update the service's
        <code>prefix</code> and <code>required_permission</code> keys to the backend's names.
      </p>
      <AsyncState
        inline
        :loading="driftState.loading.value"
        :error="driftState.error.value"
        error-title="Could not load tool mapping drift"
        :session-expired="driftState.sessionExpired.value"
        :access-denied="driftState.accessDenied.value"
        loading-label="Loading tool mapping drift…"
      >
        <p v-if="drifts.length === 0" class="ap__none">
          <StatusMark tone="ok">No tool mapping drift.</StatusMark>
        </p>
        <div v-else class="af-tbl-box">
          <table class="af-tbl compact">
            <thead>
              <tr>
                <th scope="col">Service</th>
                <th scope="col" class="num">Routable / advertised</th>
                <th scope="col">Unroutable (prefix mismatch)</th>
                <th scope="col">Unmapped (advertised, disabled)</th>
                <th scope="col">Stale (mapped, not advertised)</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="d in drifts" :key="d.service">
                <td>{{ d.service }}</td>
                <td class="num">{{ d.routable }} / {{ d.advertised }}</td>
                <td class="ap__wrap">
                  <code v-if="d.unroutable.length > 0">
                    expected {{ d.prefix }}_*: {{ d.unroutable.join(', ') }}
                  </code>
                </td>
                <td class="ap__wrap">
                  <code>{{ d.unmapped.join(', ') }}</code>
                </td>
                <td class="ap__wrap">
                  <code>{{ d.stale.join(', ') }}</code>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </AsyncState>
    </section>

    <section class="af-sect" aria-labelledby="ap-credmon-title">
      <h2 id="ap-credmon-title">HTCondor credmon sync</h2>
      <p class="ap__legend">
        The broker stores a short-lived token per user and credential type in the facility's credd,
        so jobs that request <code>use_oauth_services = af_krb5, af_x509</code> get the user's
        credentials on the worker node. Only one broker replica runs each sync.
      </p>
      <AsyncState
        inline
        :loading="credmonState.loading.value"
        :error="credmonState.error.value"
        error-title="Could not load credmon status"
        :session-expired="credmonState.sessionExpired.value"
        :access-denied="credmonState.accessDenied.value"
        loading-label="Loading credmon status…"
      >
        <p v-if="credmon && !credmon.enabled" class="ap__none">
          <StatusMark tone="off">
            Not enabled on this broker (<code>CREDMON_ENABLED</code>).
          </StatusMark>
        </p>

        <template v-else-if="credmon">
          <div class="ap__summary">
            <span data-af-credmon-health>
              <StatusMark
                :tone="CREDMON_HEALTH_TONES[credmonHealth(credmon, nowSeconds())]"
                :label="CREDMON_HEALTH_LABELS[credmonHealth(credmon, nowSeconds())]"
              />
            </span>
            <button
              type="button"
              data-af-credmon-sync
              class="af-btn secondary s"
              :disabled="credmonSyncing"
              :aria-busy="credmonSyncing"
              @click="syncCredmonNow"
            >
              {{ credmonSyncing ? 'Syncing…' : 'Run sync now' }}
            </button>
          </div>

          <AsyncState
            inline
            :loading="false"
            :error="credmonSyncError"
            error-title="Could not run sync"
            :session-expired="false"
            :access-denied="null"
          />

          <dl class="af-kv ap__kv">
            <dt>Last run</dt>
            <dd v-if="credmon.last_run">
              <span :title="exactTime(credmon.last_run.finished_at)">
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
                :title="exactTime(credmon.last_run.last_success_at)"
              >
                {{ formatRelative(credmon.last_run.last_success_at * 1000) }}
              </span>
              <template v-else>Never</template>
            </dd>
            <dt>Next run</dt>
            <dd v-if="credmonNextRunAt(credmon) !== null">
              <span :title="exactTime(credmonNextRunAt(credmon) as number)">
                {{ formatRelative((credmonNextRunAt(credmon) as number) * 1000) }}
              </span>
            </dd>
            <dd v-else>Within a minute of startup.</dd>
          </dl>

          <div class="af-tbl-box">
            <table class="af-tbl compact">
              <thead>
                <tr>
                  <th scope="col">Credential</th>
                  <th scope="col">credd service</th>
                  <th scope="col" class="num">Stored</th>
                  <th scope="col" class="num">Skipped: not linked</th>
                  <th scope="col" class="num">Skipped: no POSIX user</th>
                  <th scope="col" class="num">Failed</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="row in credmonKindRows(credmon)" :key="row.kind">
                  <td>{{ row.kind }}</td>
                  <td>
                    <code>{{ row.service }}</code>
                  </td>
                  <td class="num">{{ row.stored }}</td>
                  <td class="num">{{ row.notLinked }}</td>
                  <td class="num">{{ row.noPosix }}</td>
                  <td class="num">{{ row.failed }}</td>
                </tr>
              </tbody>
            </table>
          </div>

          <Disclosure
            v-if="credmon.last_run && credmon.last_run.errors.length > 0"
            v-model:open="credmonErrorsOpen"
            :label="`Errors from the last run (${
              credmon.last_run.errors.length + credmon.last_run.errors_truncated
            })`"
          >
            <ul class="ap__errors">
              <li v-for="(e, i) in credmon.last_run.errors" :key="i">{{ e }}</li>
            </ul>
            <p v-if="credmon.last_run.errors_truncated > 0" class="ap__legend">
              +{{ credmon.last_run.errors_truncated }} more not shown.
            </p>
          </Disclosure>
        </template>
      </AsyncState>
    </section>
  </div>
</template>

<style scoped>
.ap__legend {
  margin: 0;
  max-width: 80ch;
  font-size: var(--text-13);
  color: var(--color-af-text-secondary);
}

.ap__none {
  margin: 0;
  font-size: var(--text-13);
}

.ap__sub {
  margin-left: var(--space-8);
  color: var(--color-af-text-secondary);
}

.ap code {
  font-family: var(--font-mono);
  font-size: var(--text-13);
}

/* Key-value rows sit tighter than the shared 12px: operators read many. */
.ap__kv dt,
.ap__kv dd {
  padding: var(--space-4) 0;
}

.ap__message {
  max-width: 560px;
}

.ap__actions,
.ap__summary {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: var(--space-12);
}

.ap__summary {
  justify-content: space-between;
}

/* Lists of tool names wrap inside the cell instead of widening the table. */
.ap__wrap {
  white-space: normal;
  min-width: 14rem;
  overflow-wrap: anywhere;
}

.ap__errors {
  margin: 0;
  padding-left: var(--space-16);
  font: var(--text-13) / 1.5 var(--font-mono);
  overflow-wrap: anywhere;
}
</style>
