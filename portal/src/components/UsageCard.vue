<script setup lang="ts">
/**
 * UsageCard.vue — the overview page's usage summary, following
 * DashboardCards.vue's card pattern (same visual grammar, its own island so
 * a slow /v1/usage never blocks the get-started cards). Shows the caller's
 * trailing-window tool-call totals: calls, estimated tokens, and estimated
 * cost with the model whose input rate priced it. Everything here is an
 * ESTIMATE (tokenized tool-result text, not provider-reported spend) and is
 * labeled as such — see the broker's GET /v1/usage caveats.
 */
import { ref, onMounted } from 'vue';
import { fetchUsage } from '../lib/api';
import type { UsageResponse } from '../lib/api';
import { formatCost, formatTokens } from '../lib/usageFormat';

const usage = ref<UsageResponse | null>(null);
const loading = ref(true);

onMounted(async () => {
  try {
    usage.value = await fetchUsage();
  } catch {
    // Degrades gracefully to the plain explanation with no live numbers --
    // same non-critical failure handling as DashboardCards.
  } finally {
    loading.value = false;
  }
});
</script>

<template>
  <div class="uc" role="region" aria-label="Usage">
    <div class="uc__card">
      <svg
        class="uc__icon"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        stroke-width="1.5"
        aria-hidden="true"
      >
        <path d="M4 19.5V10" />
        <path d="M10 19.5V4.5" />
        <path d="M16 19.5v-8" />
        <path d="M4 19.5h16" />
      </svg>
      <span class="uc__label">Usage</span>
      <p class="uc__desc">
        What your AI assistant's tool calls put into its context through this platform — counted as
        estimated tokens and priced, for scale, at a reference model's input rate. Estimates only:
        this is not your provider bill.
      </p>
      <span v-if="loading" class="uc__status uc__status--loading">Loading…</span>
      <span v-else-if="usage && usage.totals.calls === 0" class="uc__status uc__status--empty">
        No tool calls in the last {{ usage.window_days }} days
      </span>
      <span v-else-if="usage" class="uc__status">
        {{ usage.totals.calls }} calls ({{ usage.window_days }}d) ·
        {{ formatTokens(usage.totals.result_tokens_est) }} tokens (estimated) ·
        {{ formatCost(usage.totals.estimated_cost_usd) }} estimated at {{ usage.cost_model }} input
        rate
      </span>
      <a class="uc__link" href="/usage/">View usage details →</a>
    </div>
  </div>
</template>

<style scoped>
/* Mirrors DashboardCards.vue's .dc card styling so the usage card reads as
   a sibling of the get-started cards above it. */
.uc {
  margin-bottom: 2.5rem;
}

.uc__card {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
  padding: 1.25rem;
  border: 1px solid var(--color-af-border);
  border-radius: 4px;
  background: var(--color-af-surface);
}

.uc__icon {
  width: 20px;
  height: 20px;
  color: var(--color-af-teal);
}

.uc__label {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.6875rem;
  font-weight: 600;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  color: var(--color-af-text);
}

.uc__desc {
  margin: 0;
  font-size: 0.8125rem;
  color: var(--color-af-dim);
  line-height: 1.55;
}

.uc__status {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.75rem;
  color: var(--color-af-green);
}

.uc__status--loading,
.uc__status--empty {
  color: var(--color-af-dim);
}

.uc__link {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.75rem;
  font-weight: 600;
  color: var(--color-af-teal);
  text-decoration: none;
  letter-spacing: 0.04em;
}
.uc__link:hover {
  text-decoration: underline;
}
</style>
