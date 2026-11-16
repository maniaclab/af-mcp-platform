<script setup lang="ts">
/**
 * AdminMaintenanceSection.vue -- the admin page's "Maintenance mode" panel:
 * current status, and enable/disable with a confirmation for enabling.
 */
import { onMounted, ref } from 'vue';
import { fetchMaintenanceStatus, SessionExpiredError, setMaintenanceStatus } from '../lib/api';
import type { MaintenanceStatus } from '../lib/api';
import { maintenanceErrorMessage } from '../lib/maintenanceBanner';
import { formatEpochSeconds, formatRelative } from '../lib/relativeTime';
import { useLoadState } from '../lib/useLoadState';
import AsyncState from './ui/AsyncState.vue';
import ConfirmDialog from './ui/ConfirmDialog.vue';
import StatusMark from './ui/StatusMark.vue';

/** Same fallback chain as subjectLabel, applied to MaintenanceStatus's
 * enabled_by/enabled_by_unixname/enabled_by_email trio instead of a
 * UsageSubject -- kept separate since the two response shapes differ. */
function enabledByLabel(status: MaintenanceStatus): string {
  return status.enabled_by_unixname || status.enabled_by_email || status.enabled_by || '';
}

const maintenanceState = useLoadState();

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

onMounted(() => {
  void maintenanceState.run(async () => {
    maintenanceStatus.value = await fetchMaintenanceStatus();
  }, 'Could not load maintenance status.');
});
</script>

<template>
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
            <span v-if="maintenanceStatus.enabled && maintenanceStatus.enabled_at" class="ap__sub">
              since
              <span :title="formatEpochSeconds(maintenanceStatus.enabled_at)">{{
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
              {{
                maintenanceStatus.enabled_at
                  ? formatEpochSeconds(maintenanceStatus.enabled_at)
                  : '—'
              }}
            </dd>
            <dt>Effect</dt>
            <dd>Everyone outside the admin group is refused and sees the message above.</dd>
          </template>
        </dl>

        <div class="field af-narrow ap__message">
          <label for="ap-maintenance-reason">Message shown to users</label>
          <input
            id="ap-maintenance-reason"
            v-model="maintenanceReason"
            data-af-maintenance-reason
            type="text"
            class="input"
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
            class="btn af-danger"
            data-variant="outline"
            :disabled="maintenanceSaving"
            @click="confirmingEnable = true"
          >
            Enable maintenance mode
          </button>
          <button
            v-else
            type="button"
            data-af-maintenance-disable
            class="btn"
            data-variant="outline"
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
            Everyone outside the admin group is refused on the portal API and the MCP endpoint, and
            sees
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
</template>

<style scoped>
.ap__sub {
  margin-left: var(--space-8);
  color: var(--color-af-text-secondary);
}

/* Key-value rows sit tighter than the shared 12px: operators read many. */
.ap__kv dt,
.ap__kv dd {
  padding: var(--space-4) 0;
}

.ap__message {
  max-width: 560px;
}

.ap__actions {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: var(--space-12);
}
</style>
