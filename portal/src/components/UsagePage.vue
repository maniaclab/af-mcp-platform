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
import { AccessDeniedError, fetchUsage, SessionExpiredError } from '../lib/api';
import type { UsageResponse } from '../lib/api';
import { formatBytes, formatCost, formatTokens } from '../lib/usageFormat';

const props = defineProps<{ subject?: string }>();

const WINDOWS = [7, 30, 90] as const;

const usage = ref<UsageResponse | null>(null);
const days = ref<number>(30);
const loading = ref(true);
const error = ref<string | null>(null);
const sessionExpired = ref(false);
const accessDenied = ref<AccessDeniedError | null>(null);

async function load(): Promise<void> {
  loading.value = true;
  error.value = null;
  try {
    // `subject` is expected to be static for this component's lifetime --
    // AdminPage.vue remounts us (via :key) rather than changing it on a
    // live instance, so there's no watcher reloading on a `subject` change.
    usage.value = await fetchUsage(days.value, props.subject);
  } catch (err) {
    usage.value = null;
    if (err instanceof AccessDeniedError) {
      accessDenied.value = err;
    } else if (err instanceof SessionExpiredError) {
      sessionExpired.value = true;
    } else {
      error.value = err instanceof Error ? err.message : 'Failed to load usage.';
    }
  } finally {
    loading.value = false;
  }
}

onMounted(load);

function selectWindow(n: number): void {
  if (days.value === n) return;
  days.value = n;
  void load();
}

function reload(): void {
  location.reload();
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
    <!-- Toolbar: window selector -->
    <div class="up__toolbar" role="toolbar" aria-label="Usage window">
      <div class="up__windows" role="group" aria-label="Trailing window">
        <button
          v-for="n in WINDOWS"
          :key="n"
          class="up__window-btn"
          :class="{ 'up__window-btn--active': days === n }"
          :aria-pressed="days === n"
          @click="selectWindow(n)"
        >
          {{ n }}d
        </button>
      </div>
      <span v-if="usage" class="up__model">
        priced at <code>{{ usage.cost_model }}</code> input rate
      </span>
    </div>

    <!-- Loading -->
    <div v-if="loading" class="up__loading" aria-live="polite" aria-label="Loading usage">
      <span class="up__spinner" aria-hidden="true"></span>
      <span>Loading usage…</span>
    </div>

    <!-- Session expired -->
    <div v-else-if="sessionExpired" class="up__error" role="alert">
      <span class="up__error-title">Session expired</span>
      <span class="up__error-body">
        Your session has expired.
        <button type="button" class="up__reload" @click="reload">Reload</button>
        to re-authenticate.
      </span>
    </div>

    <!-- Access denied -->
    <div v-else-if="accessDenied" class="up__error" role="alert">
      <span class="up__error-title">Access not yet granted</span>
      <span class="up__error-body">{{ accessDenied.message }}</span>
    </div>

    <!-- Error -->
    <div v-else-if="error" class="up__error" role="alert">
      <span class="up__error-title">Usage unavailable</span>
      <span class="up__error-body">{{ error }}</span>
    </div>

    <!-- Empty window -->
    <div v-else-if="usage && usage.totals.calls === 0" class="up__empty">
      <p class="up__empty-title">No tool calls in the last {{ usage.window_days }} days</p>
      <p class="up__empty-body">
        Once your AI assistant calls tools through this platform, its estimated context usage shows
        up here. Try a wider window above.
      </p>
    </div>

    <!-- Usage -->
    <template v-else-if="usage">
      <!-- Totals -->
      <div class="up__totals" role="list" aria-label="Window totals">
        <div class="up__stat" role="listitem">
          <span class="up__stat-label">Calls</span>
          <span class="up__stat-value">{{ formatTokens(usage.totals.calls) }}</span>
          <span class="up__stat-sub">last {{ usage.window_days }} days</span>
        </div>
        <div class="up__stat" role="listitem">
          <span class="up__stat-label">Errors</span>
          <span class="up__stat-value">{{ formatTokens(usage.totals.errors) }}</span>
          <span class="up__stat-sub">of {{ formatTokens(usage.totals.calls) }} calls</span>
        </div>
        <div class="up__stat" role="listitem">
          <span class="up__stat-label">Tokens (estimated)</span>
          <span class="up__stat-value">{{ formatTokens(usage.totals.result_tokens_est) }}</span>
          <span class="up__stat-sub">{{ formatBytes(usage.totals.result_bytes) }} of results</span>
        </div>
        <div class="up__stat" role="listitem">
          <span class="up__stat-label">Cost (estimated)</span>
          <span class="up__stat-value">{{ formatCost(usage.totals.estimated_cost_usd) }}</span>
          <span class="up__stat-sub">at {{ usage.cost_model }} input rate</span>
        </div>
      </div>

      <!-- Per-day activity -->
      <section class="up__section" aria-label="Daily activity">
        <h2 class="up__section-title">Daily activity</h2>
        <div class="up__chart" role="img" aria-label="Calls per day over the window">
          <div
            v-for="bar in dayBars"
            :key="bar.date"
            class="up__bar-slot"
            :title="`${bar.date}: ${formatTokens(bar.calls)} calls, ${formatTokens(bar.tokens)} tokens (estimated)`"
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
      </section>

      <!-- Per-service table -->
      <section class="up__section" aria-label="Usage by service">
        <h2 class="up__section-title">By service</h2>
        <div class="up__table-wrap">
          <table class="up__table">
            <thead>
              <tr>
                <th scope="col">Service</th>
                <th scope="col" class="up__num">Calls</th>
                <th scope="col" class="up__num">Errors</th>
                <th scope="col" class="up__num">Result size</th>
                <th scope="col" class="up__num">Tokens (est.)</th>
                <th scope="col" class="up__num">Cost (est.)</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="svc in usage.by_service" :key="svc.service">
                <td class="up__svc">{{ svc.service }}</td>
                <td class="up__num">{{ formatTokens(svc.calls) }}</td>
                <td class="up__num">{{ formatTokens(svc.errors) }}</td>
                <td class="up__num">{{ formatBytes(svc.result_bytes) }}</td>
                <td class="up__num">{{ formatTokens(svc.result_tokens_est) }}</td>
                <td class="up__num">{{ formatCost(svc.estimated_cost_usd) }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>
    </template>

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
  gap: 1.25rem;
}

/* Toolbar — mirrors CatalogPage's filter-button grammar */
.up__toolbar {
  display: flex;
  align-items: center;
  gap: 1rem;
  flex-wrap: wrap;
}

.up__windows {
  display: flex;
  gap: 0;
  border: 1px solid var(--color-af-muted);
  border-radius: 3px;
  overflow: hidden;
}

.up__window-btn {
  padding: 0.375rem 0.875rem;
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.6875rem;
  font-weight: 600;
  letter-spacing: 0.05em;
  text-transform: uppercase;
  color: var(--color-af-dim);
  background: transparent;
  border: none;
  border-right: 1px solid var(--color-af-muted);
  cursor: pointer;
  transition:
    color 120ms,
    background 120ms;
  white-space: nowrap;
}
.up__window-btn:last-child {
  border-right: none;
}
.up__window-btn:hover {
  color: var(--color-af-text);
  background: rgba(255, 255, 255, 0.04);
}
.up__window-btn:focus-visible {
  outline: 2px solid var(--color-af-teal);
  outline-offset: -2px;
}
.up__window-btn--active {
  color: var(--color-af-teal);
  background: rgb(from var(--color-af-teal) r g b / 0.08);
}

.up__model {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.6875rem;
  color: var(--color-af-label);
  margin-left: auto;
}
.up__model code {
  color: var(--color-af-dim);
}

/* Totals */
.up__totals {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(11rem, 1fr));
  gap: 0.5rem;
}

.up__stat {
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
  padding: 1rem 1.25rem;
  border: 1px solid var(--color-af-border);
  border-radius: 4px;
  background: var(--color-af-surface);
}

.up__stat-label {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.6875rem;
  font-weight: 600;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  color: var(--color-af-label);
}

.up__stat-value {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 1.375rem;
  font-weight: 700;
  color: var(--color-af-text);
}

.up__stat-sub {
  font-size: 0.75rem;
  color: var(--color-af-dim);
}

/* Sections */
.up__section {
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
}

.up__section-title {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.8125rem;
  font-weight: 600;
  letter-spacing: 0.05em;
  text-transform: uppercase;
  color: var(--color-af-text);
  margin: 0;
}

/* Daily activity — plain CSS bars, no chart library */
.up__chart {
  display: flex;
  align-items: flex-end;
  gap: 2px;
  height: 5rem;
  padding: 0.75rem;
  border: 1px solid var(--color-af-border);
  border-radius: 4px;
  background: var(--color-af-surface);
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
  background: var(--color-af-teal);
  border-radius: 1px 1px 0 0;
}

.up__chart-axis {
  display: flex;
  justify-content: space-between;
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.625rem;
  color: var(--color-af-label);
}

/* Per-service table */
.up__table-wrap {
  overflow-x: auto;
  border: 1px solid var(--color-af-border);
  border-radius: 4px;
  background: var(--color-af-surface);
}

.up__table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.8125rem;
}

.up__table th {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.6875rem;
  font-weight: 600;
  letter-spacing: 0.05em;
  text-transform: uppercase;
  color: var(--color-af-label);
  text-align: left;
  padding: 0.625rem 1rem;
  border-bottom: 1px solid var(--color-af-border);
}

.up__table td {
  padding: 0.625rem 1rem;
  border-bottom: 1px solid var(--color-af-border);
  color: var(--color-af-dim);
}

.up__table tbody tr:last-child td {
  border-bottom: none;
}

.up__svc {
  font-family: 'IBM Plex Mono', monospace;
  color: var(--color-af-text);
}

.up__num {
  text-align: right;
  font-variant-numeric: tabular-nums;
  white-space: nowrap;
}

/* Caveat */
.up__caveat {
  margin: 0;
  font-size: 0.8125rem;
  color: var(--color-af-dim);
  line-height: 1.55;
  max-width: 52rem;
}

/* Loading */
.up__loading {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  padding: 2rem;
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.8125rem;
  color: var(--color-af-dim);
}

.up__spinner {
  width: 16px;
  height: 16px;
  border: 2px solid var(--color-af-border);
  border-top-color: var(--color-af-teal);
  border-radius: 50%;
  animation: spin 600ms linear infinite;
}

@keyframes spin {
  to {
    transform: rotate(360deg);
  }
}

@media (prefers-reduced-motion: reduce) {
  .up__spinner {
    animation: none;
    border-top-color: var(--color-af-dim);
  }
}

/* Error */
.up__error {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
  padding: 1.25rem;
  border: 1px solid rgb(from var(--color-af-red) r g b / 0.2);
  border-radius: 4px;
  background: rgb(from var(--color-af-red) r g b / 0.05);
}

.up__error-title {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.8125rem;
  font-weight: 600;
  color: var(--color-af-red);
}

.up__error-body {
  font-size: 0.875rem;
  color: var(--color-af-dim);
}

.up__reload {
  font: inherit;
  color: var(--color-af-teal);
  background: none;
  border: none;
  padding: 0;
  cursor: pointer;
  text-decoration: underline;
}

/* Empty */
.up__empty {
  padding: 3rem 1.5rem;
  text-align: center;
  border: 1px dashed var(--color-af-border);
  border-radius: 4px;
}

.up__empty-title {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 1rem;
  font-weight: 600;
  color: var(--color-af-label);
  margin: 0 0 0.5rem;
}

.up__empty-body {
  font-size: 0.875rem;
  color: var(--color-af-dim);
  margin: 0;
  max-width: 32rem;
  margin-inline: auto;
  line-height: 1.6;
}
</style>
