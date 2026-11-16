<script setup lang="ts">
/**
 * AdminCredmonSection.vue -- the admin page's "HTCondor credmon sync" panel
 * (docs/credmon.md): sync health, the last run, per-credential counts, and a
 * manual "Run sync now".
 */
import { onMounted, ref } from 'vue';
import { fetchCredmonStatus, runCredmonSync } from '../lib/api';
import type { CredmonStatus } from '../lib/api';
import {
  credmonHealth,
  credmonKindRows,
  credmonNextRunAt,
  credmonSyncErrorMessage,
} from '../lib/credmonStatus';
import type { CredmonHealth } from '../lib/credmonStatus';
import { formatEpochSeconds, formatRelative } from '../lib/relativeTime';
import { useAsyncAction } from '../lib/useAsyncAction';
import { useLoadState } from '../lib/useLoadState';
import AsyncState from './ui/AsyncState.vue';
import Disclosure from './ui/Disclosure.vue';
import StatusMark from './ui/StatusMark.vue';

function nowSeconds(): number {
  return Date.now() / 1000;
}

const credmonState = useLoadState();

const credmon = ref<CredmonStatus | null>(null);
const {
  busy: credmonSyncing,
  error: credmonSyncError,
  run: runSync,
} = useAsyncAction(credmonSyncErrorMessage);
// Errors list starts expanded only when short enough to scan at a glance.
const CREDMON_ERRORS_OPEN_MAX = 3;
const credmonErrorsOpen = ref(false);

async function refreshCredmon(): Promise<void> {
  credmon.value = await fetchCredmonStatus();
  credmonErrorsOpen.value = (credmon.value.last_run?.errors.length ?? 0) <= CREDMON_ERRORS_OPEN_MAX;
}

async function syncCredmonNow(): Promise<void> {
  await runSync(async () => {
    await runCredmonSync();
    await refreshCredmon();
  });
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
  void credmonState.run(refreshCredmon, 'Failed to load credmon status.');
});
</script>

<template>
  <section class="af-sect ap__sect" aria-labelledby="ap-credmon-title">
    <h2 id="ap-credmon-title">HTCondor credmon sync</h2>
    <p class="af-help">
      The broker stores a short-lived token per user and credential type in the facility's credd, so
      jobs that request <code>use_oauth_services = af_krb5, af_x509</code> get the user's
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
            class="btn"
            data-variant="outline"
            data-size="sm"
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
            <span :title="formatEpochSeconds(credmon.last_run.finished_at)">
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
              :title="formatEpochSeconds(credmon.last_run.last_success_at)"
            >
              {{ formatRelative(credmon.last_run.last_success_at * 1000) }}
            </span>
            <template v-else>Never</template>
          </dd>
          <dt>Next run</dt>
          <dd v-if="credmonNextRunAt(credmon) !== null">
            <span :title="formatEpochSeconds(credmonNextRunAt(credmon) as number)">
              {{ formatRelative((credmonNextRunAt(credmon) as number) * 1000) }}
            </span>
          </dd>
          <dd v-else>Within a minute of startup.</dd>
        </dl>

        <div class="table-container af-box">
          <table class="af-compact table">
            <thead>
              <tr>
                <th scope="col">Credential</th>
                <th scope="col">credd service</th>
                <th scope="col" class="af-num">Stored</th>
                <th scope="col" class="af-num">Skipped: not linked</th>
                <th scope="col" class="af-num">Skipped: no POSIX user</th>
                <th scope="col" class="af-num">Failed</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="row in credmonKindRows(credmon)" :key="row.kind">
                <td>{{ row.kind }}</td>
                <td>
                  <code>{{ row.service }}</code>
                </td>
                <td class="af-num">{{ row.stored }}</td>
                <td class="af-num">{{ row.notLinked }}</td>
                <td class="af-num">{{ row.noPosix }}</td>
                <td class="af-num">{{ row.failed }}</td>
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
          <p v-if="credmon.last_run.errors_truncated > 0" class="af-help">
            +{{ credmon.last_run.errors_truncated }} more not shown.
          </p>
        </Disclosure>
      </template>
    </AsyncState>
  </section>
</template>

<style scoped>
.ap__none {
  margin: 0;
  font-size: var(--text-13);
}

.ap__sect code {
  font-family: var(--font-mono);
  font-size: var(--text-13);
}

/* Key-value rows sit tighter than the shared 12px: operators read many. */
.ap__kv dt,
.ap__kv dd {
  padding: var(--space-4) 0;
}

.ap__summary {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: var(--space-12);
  justify-content: space-between;
}

.ap__errors {
  margin: 0;
  padding-left: var(--space-16);
  font: var(--text-13) / 1.5 var(--font-mono);
  overflow-wrap: anywhere;
}
</style>
