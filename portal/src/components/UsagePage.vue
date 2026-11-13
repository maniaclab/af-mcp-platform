<script setup lang="ts">
/**
 * UsagePage.vue — the full /usage page behind the overview's usage summary.
 * Renders GET /v1/usage's whole payload: window totals, the per-service
 * table, and a per-day activity chart, with a 7/30/90-day window selector
 * that refetches on change. Everything here is an ESTIMATE (tokenized
 * tool-result text priced at one model's input rate, not provider-reported
 * spend) and is labeled as such — see the broker's GET /v1/usage caveats.
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
import { formatBytes, formatCost, formatTokens } from '../lib/usageFormat';
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
  return `Calls per day over the last ${dayBars.value.length} days; busiest day ${busiest.date} with ${formatTokens(busiest.calls)} calls`;
});
</script>

<template>
  <div class="af-page af-wide">
    <div class="up__toolbar">
      <SegmentedControl
        :model-value="String(days)"
        :options="WINDOW_OPTIONS"
        aria-label="Trailing window"
        @update:model-value="selectWindow"
      />
      <span v-if="usage" class="up__model">
        Priced at <code>{{ usage.cost_model }}</code> input rate
      </span>
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
            <b>{{ formatTokens(usage.totals.calls) }}</b>
            <small>Last {{ usage.window_days }} days</small>
          </div>
          <div class="af-stat" role="listitem">
            <span>Errors</span>
            <b>{{ formatTokens(usage.totals.errors) }}</b>
            <small>
              of {{ formatTokens(usage.totals.calls) }} calls<template v-if="errorRate">
                ({{ errorRate }})</template
              >
            </small>
          </div>
          <div class="af-stat" role="listitem">
            <span>Tokens (estimated)</span>
            <b>{{ formatTokens(usage.totals.result_tokens_est) }}</b>
            <small>{{ formatBytes(usage.totals.result_bytes) }} of results</small>
          </div>
          <div class="af-stat" role="listitem">
            <span>Cost (estimated)</span>
            <b>{{ formatCost(usage.totals.estimated_cost_usd) }}</b>
            <small>at {{ usage.cost_model }} input rate</small>
          </div>
        </div>

        <section class="af-sect" aria-labelledby="up-daily">
          <h2 id="up-daily">Daily activity</h2>
          <BarChart
            :labels="dayLabels"
            :series="daySeries"
            :aria-label="chartLabel"
            :format-value="formatTokens"
          />
        </section>

        <section class="af-sect" aria-labelledby="up-service">
          <h2 id="up-service">By service</h2>
          <p class="af-help">
            What your AI assistant's tool calls put into its context through this platform — counted
            as estimated tokens and priced, for scale, at a reference model's input rate. Estimates
            only: this is not your provider bill.
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
                  <th scope="col" class="af-num">Cost (est.)</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="svc in usage.by_service" :key="svc.service">
                  <td v-if="displayName(svc.service)">
                    <span class="up__service">{{ displayName(svc.service) }}</span>
                    <code class="af-sub up__id">{{ svc.service }}</code>
                  </td>
                  <td v-else>{{ svc.service }}</td>
                  <td class="af-num">{{ formatTokens(svc.calls) }}</td>
                  <td class="af-num af-sub">{{ formatTokens(svc.errors) }}</td>
                  <td class="af-num af-sub">{{ formatBytes(svc.result_bytes) }}</td>
                  <td class="af-num">{{ formatTokens(svc.result_tokens_est) }}</td>
                  <td class="af-num">{{ formatCost(svc.estimated_cost_usd) }}</td>
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

.up__model {
  font-size: var(--text-13);
  color: var(--color-af-text-secondary);
  margin-left: auto;
}
.up__model code,
.up__id {
  font-family: var(--font-mono);
}

.up__id {
  margin-left: var(--space-8);
  font-size: var(--text-13);
}
</style>
