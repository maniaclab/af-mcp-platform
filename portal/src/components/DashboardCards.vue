<script setup lang="ts">
/**
 * DashboardCards.vue — fetches the three summary values for the landing page
 * status cards and renders them as a three-column grid.
 */
import { ref, onMounted } from 'vue';
import { fetchDashboardSummary } from '../lib/api';
import type { DashboardSummary } from '../lib/api';

const summary = ref<DashboardSummary | null>(null);
const loading = ref(true);

onMounted(async () => {
  try {
    summary.value = await fetchDashboardSummary();
  } catch {
    // Cards degrade gracefully to dashes — not a critical failure path
  } finally {
    loading.value = false;
  }
});
</script>

<template>
  <div class="dc" role="region" aria-label="Quick status">
    <!-- Identities card -->
    <div class="dc__card" :class="!loading && summary && summary.linkedCount > 0 ? 'dc__card--ok' : 'dc__card--neutral'">
      <span class="dc__label">Linked identities</span>
      <span class="dc__value" :class="{ 'dc__value--loading': loading }">
        {{ loading ? '—' : `${summary?.linkedCount ?? 0} linked` }}
      </span>
      <a href="/identities" class="dc__link">Manage →</a>
    </div>

    <!-- Tools card -->
    <div class="dc__card" :class="!loading && summary && summary.toolCount > 0 ? 'dc__card--ok' : 'dc__card--neutral'">
      <span class="dc__label">Tools available</span>
      <span class="dc__value" :class="{ 'dc__value--loading': loading }">
        {{ loading ? '—' : `${summary?.toolCount ?? 0} tools` }}
      </span>
      <a href="/catalog" class="dc__link">Browse →</a>
    </div>

    <!-- Proxy card -->
    <div
      class="dc__card"
      :class="!loading && summary?.proxyStatus.has_proxy ? 'dc__card--ok' : 'dc__card--neutral'"
    >
      <span class="dc__label">AMI proxy</span>
      <span class="dc__value" :class="{ 'dc__value--loading': loading }">
        {{ loading ? '—' : (summary?.proxyStatus.has_proxy ? 'Active' : 'No proxy') }}
      </span>
      <a href="/status" class="dc__link">Manage →</a>
    </div>
  </div>
</template>

<style scoped>
.dc {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 1rem;
  margin-bottom: 2.5rem;
}

.dc__card {
  display: flex;
  flex-direction: column;
  gap: 0.375rem;
  padding: 1.125rem 1.25rem;
  border: 1px solid #1F2937;
  border-radius: 4px;
  background: #111827;
  border-left-width: 2px;
}

.dc__card--ok      { border-left-color: #10B981; }
.dc__card--warn    { border-left-color: #F59E0B; }
.dc__card--neutral { border-left-color: #374151; }

.dc__label {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.5625rem;
  font-weight: 600;
  letter-spacing: 0.1em;
  text-transform: uppercase;
  color: #4B5563;
}

.dc__value {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 1.375rem;
  font-weight: 700;
  color: #E8ECF0;
  line-height: 1;
}

.dc__value--loading { color: #374151; }

.dc__link {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.6875rem;
  color: #374151;
  text-decoration: none;
  margin-top: 0.25rem;
  transition: color 150ms;
}
.dc__card:hover .dc__link,
.dc__link:focus-visible { color: #00D4C8; }

@media (max-width: 640px) {
  .dc { grid-template-columns: 1fr; }
}
</style>
