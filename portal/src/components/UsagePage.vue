<script setup lang="ts">
/**
 * UsagePage.vue — the full /usage page behind the overview's UsageCard.
 * Renders GET /v1/usage's whole payload: window totals, the per-service
 * table, and a per-day activity strip, with a 7/30/90-day window selector
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
import { fetchUsage } from '../lib/api';
import type { UsageResponse } from '../lib/api';
import { useLoadState } from '../lib/useLoadState';
import { formatBytes, formatCost, formatTokens } from '../lib/usageFormat';
import AsyncState from './ui/AsyncState.vue';
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

onMounted(load);

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

function barLabel(bar: { date: string; calls: number; tokens: number }): string {
  return `${bar.date}: ${formatTokens(bar.calls)} calls, ${formatTokens(bar.tokens)} tokens (estimated)`;
}

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

const maxDayCalls = computed<number>(() => Math.max(1, ...dayBars.value.map((b) => b.calls)));

function barHeight(calls: number): string {
  // Bars scale to the busiest day; a nonzero day never rounds below 4% so
  // it stays visible next to a big spike.
  return calls === 0 ? '0%' : `${Math.max(4, (calls / maxDayCalls.value) * 100)}%`;
}
</script>

<template>
  <div class="up">
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
        <b>No tool calls in the last {{ usage?.window_days }} days</b>
        <p>
          Once your AI assistant calls tools through this platform, its estimated context usage
          shows up here. Try a wider window above.
        </p>
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
          <h2 id="up-daily" class="up__heading">Daily activity</h2>
          <div class="up__chart-box">
            <span class="up__chart-max">{{ formatTokens(maxDayCalls) }} calls</span>
            <div class="up__chart" role="group" aria-label="Calls per day over the window">
              <div
                v-for="bar in dayBars"
                :key="bar.date"
                class="up__bar-slot"
                role="img"
                :aria-label="barLabel(bar)"
                :title="barLabel(bar)"
                data-testid="usage-day-bar"
                :data-calls="bar.calls"
              >
                <div class="up__bar" :style="{ height: barHeight(bar.calls) }"></div>
              </div>
            </div>
            <div class="up__chart-axis" aria-hidden="true">
              <span>{{ dayBars[0]?.date }}</span>
              <span>{{ dayBars[dayBars.length - 1]?.date }}</span>
            </div>
          </div>
        </section>

        <section class="af-sect" aria-labelledby="up-service">
          <h2 id="up-service" class="up__heading">By service</h2>
          <div class="af-tbl-box">
            <table class="af-tbl">
              <thead>
                <tr>
                  <th scope="col">Service</th>
                  <th scope="col" class="num">Calls</th>
                  <th scope="col" class="num">Errors</th>
                  <th scope="col" class="num">Result size</th>
                  <th scope="col" class="num">Tokens (est.)</th>
                  <th scope="col" class="num">Cost (est.)</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="svc in usage.by_service" :key="svc.service">
                  <td>{{ svc.service }}</td>
                  <td class="num">{{ formatTokens(svc.calls) }}</td>
                  <td class="num sub">{{ formatTokens(svc.errors) }}</td>
                  <td class="num sub">{{ formatBytes(svc.result_bytes) }}</td>
                  <td class="num">{{ formatTokens(svc.result_tokens_est) }}</td>
                  <td class="num">{{ formatCost(svc.estimated_cost_usd) }}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </section>
      </template>
    </AsyncState>

    <!-- Caveat — same wording as the overview's UsageCard -->
    <p class="up__caveat">
      What your AI assistant's tool calls put into its context through this platform — counted as
      estimated tokens and priced, for scale, at a reference model's input rate. Estimates only:
      this is not your provider bill.
    </p>
  </div>
</template>

<style scoped>
.up {
  display: flex;
  flex-direction: column;
  gap: var(--space-24);
}

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
.up__model code {
  font-family: var(--font-mono);
}

.up__heading {
  font: 600 var(--text-16) / 1.4 var(--font-sans);
  margin: 0;
}

/* Daily activity: plain CSS bars, a 1px baseline and a 1px line at the
   busiest day's value, labelled so the bar heights have a scale. */
.up__chart-box {
  display: flex;
  flex-direction: column;
  gap: var(--space-4);
}

.up__chart-max,
.up__chart-axis {
  font-size: var(--text-12);
  color: var(--color-af-text-secondary);
  font-variant-numeric: tabular-nums;
}

.up__chart-axis {
  display: flex;
  justify-content: space-between;
}

.up__chart {
  display: flex;
  align-items: flex-end;
  gap: var(--space-2);
  height: 120px;
  border-top: 1px solid var(--color-af-border);
  border-bottom: 1px solid var(--color-af-border);
}

.up__bar-slot {
  flex: 1;
  height: 100%;
  display: flex;
  align-items: flex-end;
  min-width: 2px;
}

.up__bar {
  width: 100%;
  background: var(--color-af-text-secondary);
}

.up__bar-slot:hover .up__bar {
  background: var(--color-af-text);
}

.up__caveat {
  margin: 0;
  font-size: var(--text-13);
  color: var(--color-af-text-secondary);
  max-width: 52rem;
}
</style>
