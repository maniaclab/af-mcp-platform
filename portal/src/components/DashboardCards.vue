<script setup lang="ts">
/**
 * DashboardCards.vue — introduces the three things a new user needs to
 * understand (Services, Identities, Tokens) with a plain-language
 * explanation of each, plus its own live status pulled from the same
 * summary endpoint the old four-tile stat grid used. Replaces that grid:
 * three of its four numbers already duplicated the sidebar nav's own count
 * badges, and the fourth (VOMS proxy) is really just one identity's status,
 * not a peer of the other three -- it's folded into the Identities card here.
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
    // Cards degrade gracefully to their plain explanation with no live
    // status line -- not a critical failure path.
  } finally {
    loading.value = false;
  }
});
</script>

<template>
  <div class="dc" role="region" aria-label="Get started">
    <!-- Services -->
    <div class="dc__card">
      <svg
        class="dc__icon"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        stroke-width="1.5"
        aria-hidden="true"
      >
        <path d="M4 4.5h16v6.5H4z" />
        <path d="M4 13h16v6.5H4z" />
        <path d="M7.5 7.75h.01" />
        <path d="M7.5 16.25h.01" />
      </svg>
      <span class="dc__label">Services</span>
      <p class="dc__desc">
        The backend systems your AI assistant can reach through this platform — dataset lookup,
        metadata, job submission, and more — all exposed as methods it can call directly.
      </p>
      <span class="dc__status" :class="{ 'dc__status--loading': loading }">
        {{ loading ? 'Loading…' : `${summary?.serverCount ?? 0} services reachable` }}
      </span>
      <a href="/catalog/" class="dc__link">Browse the catalog →</a>
    </div>

    <!-- Identities -->
    <div class="dc__card">
      <svg
        class="dc__icon"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        stroke-width="1.5"
        aria-hidden="true"
      >
        <path d="M12 11a3.5 3.5 0 1 0 0-7 3.5 3.5 0 0 0 0 7z" />
        <path d="M4.5 20.5a7.5 7.5 0 0 1 15 0" />
      </svg>
      <span class="dc__label">Identities</span>
      <p class="dc__desc">
        The external accounts — your CERN/ATLAS login, your grid certificate — this platform uses to
        act on your behalf, without ever handing your AI assistant a raw credential.
      </p>
      <span class="dc__status" :class="{ 'dc__status--loading': loading }">
        <template v-if="loading">Loading…</template>
        <template v-else
          >{{ summary?.linkedCount ?? 0 }} linked · grid certificate
          {{ summary?.proxyStatus.cached ? 'active' : 'not linked' }}</template
        >
      </span>
      <a href="/identities/" class="dc__link">Manage identities →</a>
    </div>

    <!-- Tokens -->
    <div class="dc__card">
      <svg
        class="dc__icon"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        stroke-width="1.5"
        aria-hidden="true"
      >
        <path d="M8 15.5m-3.5 0a3.5 3.5 0 1 0 7 0 3.5 3.5 0 1 0-7 0" />
        <path d="M10.8 13 19.5 4.3" />
        <path d="M16.2 7.6l2.2 2.2" />
      </svg>
      <span class="dc__label">Tokens</span>
      <p class="dc__desc">
        A Personal Access Token (PAT) is what lets a client that can't sign in with a browser on its
        own — like Claude Desktop — connect on your behalf.
      </p>
      <span class="dc__status" :class="{ 'dc__status--loading': loading }">
        {{ loading ? 'Loading…' : `${summary?.activeTokenCount ?? 0} active` }}
      </span>
      <a href="/tokens/" class="dc__link">Manage tokens →</a>
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
  gap: 0.5rem;
  padding: 1.25rem;
  border: 1px solid var(--color-af-border);
  border-radius: 4px;
  background: var(--color-af-surface);
}

.dc__icon {
  width: 20px;
  height: 20px;
  color: var(--color-af-teal);
}

.dc__label {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.6875rem;
  font-weight: 600;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  color: var(--color-af-text);
}

.dc__desc {
  margin: 0;
  font-size: 0.8125rem;
  color: var(--color-af-dim);
  line-height: 1.55;
  flex: 1;
}

.dc__status {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.75rem;
  color: var(--color-af-green);
}

.dc__status--loading {
  color: var(--color-af-dim);
}

.dc__link {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.6875rem;
  color: var(--color-af-dim);
  text-decoration: none;
  transition: color 150ms;
}
.dc__card:hover .dc__link,
.dc__link:focus-visible {
  color: var(--color-af-teal);
}

@media (max-width: 900px) {
  .dc {
    grid-template-columns: 1fr;
  }
}
</style>
