<script setup lang="ts">
/**
 * UsagePage.vue — the full /usage page behind the overview's usage summary.
 * Renders GET /v1/usage's whole payload: window totals, the per-service
 * table, and a per-day activity chart, with a 7/30/90-day window selector
 * that refetches on change. Token counts here are an ESTIMATE (tokenized
 * tool-result text, not provider-reported usage) and are labeled as such — see the broker's GET /v1/usage caveats.
 *
 * `subject` is optional and only meaningful for an admin caller: passing it
 * views that subject's usage instead of the caller's own (AdminPage.vue's
 * usage-for-other-users dropdown; see api/usage.py::get_usage). Self-service
 * usage.astro renders this with no `subject`, unchanged from before.
 */
import { ref, computed, onMounted } from 'vue';
import { fetchCatalog, fetchUsage } from '../lib/api';
import type { UsageResponse } from '../lib/api';
import { useLoadState } from '../lib/useLoadState';
import { TOKEN_DOCS_URL } from '../lib/tokenExplainer';
import { contentTypeRows, UNATTRIBUTED } from '../lib/usageContent';
import { formatBytes, formatShare, formatCount } from '../lib/usageFormat';
import TokenEstimateTip from './TokenEstimateTip.vue';
import AsyncState from './ui/AsyncState.vue';
import BarChart from './ui/BarChart.vue';
import SegmentedControl from './ui/SegmentedControl.vue';

const props = defineProps<{ subject?: string }>();

const WINDOWS = [7, 30, 90] as const;
const WINDOW_OPTIONS = WINDOWS.map((n) => ({ value: String(n), label: `${n} days` }));

const usage = ref<UsageResponse | null>(null);
const days = ref<number>(30);
const { loading, error, sessionExpired, accessDenied, run } = useLoadState();

function load(): Promise<void> {
  // `subject` is expected to be static for this component's lifetime --
  // AdminPage.vue remounts us (via :key) rather than changing it on a
  // live instance, so there's no watcher reloading on a `subject` change.
  return run(async () => {
    try {
      usage.value = await fetchUsage(days.value, props.subject);
    } catch (err) {
      usage.value = null;
      throw err;
    }
  }, 'Failed to load usage.');
}

// Display names for the per-service table, keyed by service id. Fetched once:
// the window selector reloads usage only. A failed fetch leaves the map empty
// and the table shows ids, since names are a convenience, not the data.
const displayNames = ref<Map<string, string>>(new Map());

function loadDisplayNames(): Promise<void> {
  return fetchCatalog()
    .then((catalog) => {
      displayNames.value = new Map(catalog.servers.map((s) => [s.name, s.display_name]));
    })
    .catch(() => {});
}

/** The catalog's name for a service, or null when it is unknown or just repeats the id. */
function displayName(id: string): string | null {
  const name = displayNames.value.get(id);
  return name && name !== id ? name : null;
}

onMounted(() => {
  void load();
  void loadDisplayNames();
});

function selectWindow(value: string): void {
  const n = Number(value);
  if (days.value === n) return;
  days.value = n;
  void load();
}

const isEmpty = computed<boolean>(() => usage.value !== null && usage.value.totals.calls === 0);

/** One row per content type, plus the unattributed remainder (see contentTypeRows). */
const contentRows = computed(() =>
  usage.value ? contentTypeRows(usage.value.totals, usage.value.by_content_type) : [],
);

/** Share of calls that failed, e.g. "7.1%"; null when there were no calls. */
const errorRate = computed<string | null>(() => {
  const totals = usage.value?.totals;
  if (!totals || totals.calls === 0) return null;
  return `${((totals.errors / totals.calls) * 100).toLocaleString('en-US', { maximumFractionDigits: 1 })}%`;
});

/**
 * One entry per UTC calendar day of the current window (today inclusive),
 * zero-filled — by_day only reports days that had calls, but the activity
 * strip must show the gaps too or a quiet month looks busy.
 */
const dayBars = computed<{ date: string; calls: number; tokens: number }[]>(() => {
  if (!usage.value) return [];
  const byDate = new Map(usage.value.by_day.map((d) => [d.date, d]));
  const now = new Date();
  const todayUtc = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate());
  const bars: { date: string; calls: number; tokens: number }[] = [];
  for (let i = usage.value.window_days - 1; i >= 0; i--) {
    const date = new Date(todayUtc - i * 86_400_000).toISOString().slice(0, 10);
    const day = byDate.get(date);
    bars.push({ date, calls: day?.calls ?? 0, tokens: day?.result_tokens_est ?? 0 });
  }
  return bars;
});

const dayLabels = computed<string[]>(() => dayBars.value.map((b) => b.date));

// Estimated tokens are listed in the chart's text table, not drawn: calls and
// tokens differ by orders of magnitude and would share one axis.
const daySeries = computed(() => [
  { label: 'Calls', values: dayBars.value.map((b) => b.calls) },
  { label: 'Tokens (estimated)', values: dayBars.value.map((b) => b.tokens), plot: false },
]);

const chartLabel = computed<string>(() => {
  const busiest = dayBars.value.reduce((a, b) => (b.calls > a.calls ? b : a), dayBars.value[0]);
  return `Calls per day over the last ${dayBars.value.length} days; busiest day ${busiest.date} with ${formatCount(busiest.calls)} calls`;
});
</script>

<template>
  <div class="af-page af-wide">
    <div class="up__toolbar">
      <SegmentedControl
        :model-value="String(days)"
        :options="WINDOW_OPTIONS"
        ariaLabel="Trailing window"
        @update:model-value="selectWindow"
      />
    </div>

    <AsyncState
      :loading="loading"
      :error="error"
      error-title="Usage unavailable"
      :session-expired="sessionExpired"
      :access-denied="accessDenied"
      :empty="isEmpty"
      loading-label="Loading usage…"
    >
      <template #empty>
        <header>
          <h2>No tool calls in the last {{ usage?.window_days }} days</h2>
          <p>
            Once your AI assistant calls tools through this platform, its estimated context usage
            shows up here. Try a wider window above.
          </p>
        </header>
      </template>

      <template v-if="usage">
        <div class="af-stats" role="list" aria-label="Window totals">
          <div class="af-stat" role="listitem">
            <span>Calls</span>
            <b>{{ formatCount(usage.totals.calls) }}</b>
            <small>Last {{ usage.window_days }} days</small>
          </div>
          <div class="af-stat" role="listitem">
            <span>Errors</span>
            <b>{{ formatCount(usage.totals.errors) }}</b>
            <small>
              of {{ formatCount(usage.totals.calls) }} calls<template v-if="errorRate">
                ({{ errorRate }})</template
              >
            </small>
          </div>
          <div class="af-stat" role="listitem">
            <span>Tokens (estimated) <TokenEstimateTip id="up-token-tip" /></span>
            <b>{{ formatCount(usage.totals.result_tokens_est) }}</b>
            <small>{{ formatBytes(usage.totals.result_bytes) }} of results</small>
          </div>
        </div>

        <section class="af-sect" aria-labelledby="up-daily">
          <h2 id="up-daily">Daily activity</h2>
          <BarChart
            :labels="dayLabels"
            :series="daySeries"
            :ariaLabel="chartLabel"
            :format-value="formatCount"
          />
        </section>

        <section
          v-if="contentRows.length > 0"
          id="up-content"
          class="af-sect"
          aria-labelledby="up-content-h"
        >
          <h2 id="up-content-h">By content type</h2>
          <p class="af-help">
            Estimated tokens split by what a tool result contained.
            <TokenEstimateTip id="up-content-tip" />
            <a :href="TOKEN_DOCS_URL" target="_blank" rel="noopener"
              >How token counts are estimated</a
            >.
          </p>
          <div class="table-container af-box">
            <table class="table">
              <thead>
                <tr>
                  <th scope="col">Content type</th>
                  <th scope="col" class="af-num">Blocks</th>
                  <th scope="col" class="af-num">Result size</th>
                  <th scope="col" class="af-num">Tokens (est.)</th>
                  <th scope="col" class="af-num">Share</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="row in contentRows" :key="row.contentType">
                  <td>
                    {{ row.label }}
                    <span v-if="row.contentType === UNATTRIBUTED" class="af-sub up__note">
                      calls recorded without a breakdown
                    </span>
                  </td>
                  <td class="af-num af-sub">
                    {{ row.blocks === null ? '—' : formatCount(row.blocks) }}
                  </td>
                  <td class="af-num af-sub">{{ formatBytes(row.bytes) }}</td>
                  <td class="af-num">{{ formatCount(row.tokens) }}</td>
                  <td class="af-num af-sub">{{ formatShare(row.share) }}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </section>

        <section class="af-sect" aria-labelledby="up-service">
          <h2 id="up-service">By service</h2>
          <p class="af-help">
            What your AI assistant's tool calls put into its context through this platform — counted
            as estimated tokens. Estimates only: these are not provider-reported counts.
          </p>
          <div class="table-container af-box">
            <table class="table">
              <thead>
                <tr>
                  <th scope="col">Service</th>
                  <th scope="col" class="af-num">Calls</th>
                  <th scope="col" class="af-num">Errors</th>
                  <th scope="col" class="af-num">Result size</th>
                  <th scope="col" class="af-num">Tokens (est.)</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="svc in usage.by_service" :key="svc.service">
                  <td v-if="displayName(svc.service)">
                    <span class="up__service">{{ displayName(svc.service) }}</span>
                    <code class="af-sub up__id">{{ svc.service }}</code>
                  </td>
                  <td v-else>{{ svc.service }}</td>
                  <td class="af-num">{{ formatCount(svc.calls) }}</td>
                  <td class="af-num af-sub">{{ formatCount(svc.errors) }}</td>
                  <td class="af-num af-sub">{{ formatBytes(svc.result_bytes) }}</td>
                  <td class="af-num">{{ formatCount(svc.result_tokens_est) }}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </section>
      </template>
    </AsyncState>
  </div>
</template>

<style scoped>
.up__toolbar {
  display: flex;
  align-items: center;
  gap: var(--space-16);
  flex-wrap: wrap;
}

.up__id {
  font-family: var(--font-mono);
}

.up__note {
  margin-left: var(--space-8);
  font-size: var(--text-13);
}

.up__id {
  margin-left: var(--space-8);
  font-size: var(--text-13);
}
</style>
