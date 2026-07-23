<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import { fetchCatalog, SessionExpiredError } from '../lib/api';
import type { CatalogTool, BackendGroup } from '../lib/api';
import BackendCard from './BackendCard.vue';

const tools = ref<CatalogTool[]>([]);
const loading = ref(true);
const error = ref<string | null>(null);
const sessionExpired = ref(false);
const filter = ref<'all' | 'read' | 'state_change'>('all');
const search = ref('');

onMounted(async () => {
  try {
    const data = await fetchCatalog();
    tools.value = data.tools;
  } catch (err) {
    if (err instanceof SessionExpiredError) {
      sessionExpired.value = true;
    } else {
      error.value =
        err instanceof Error
          ? err.message
          : 'Failed to load catalog. Check that your identities are linked.';
    }
  } finally {
    loading.value = false;
  }
});

function reload() {
  location.reload();
}

// The broker returns a flat tool list; group by backend for the UI.
const backends = computed<BackendGroup[]>(() => {
  const map = new Map<string, BackendGroup>();
  for (const tool of tools.value) {
    let group = map.get(tool.backend);
    if (!group) {
      group = { backend: tool.backend, tools: [], capabilities: [] };
      map.set(tool.backend, group);
    }
    group.tools.push(tool);
    if (!group.capabilities.includes(tool.capability)) {
      group.capabilities.push(tool.capability);
    }
  }
  return [...map.values()].sort((a, b) => a.backend.localeCompare(b.backend));
});

const filteredBackends = computed<BackendGroup[]>(() => {
  let result = backends.value;

  if (filter.value !== 'all') {
    result = result
      .map((b) => ({
        ...b,
        tools: b.tools.filter((t) => t.action_type === filter.value),
      }))
      .filter((b) => b.tools.length > 0);
  }

  if (search.value.trim()) {
    const q = search.value.toLowerCase();
    result = result.filter(
      (b) =>
        b.backend.toLowerCase().includes(q) ||
        b.capabilities.some((c) => c.toLowerCase().includes(q)) ||
        b.tools.some(
          (t) => t.name.toLowerCase().includes(q) || t.description.toLowerCase().includes(q),
        ),
    );
  }

  return result;
});

// Both toolbar counts derive from the filtered set so they stay consistent.
const visibleToolCount = computed(() =>
  filteredBackends.value.reduce((sum, b) => sum + b.tools.length, 0),
);
</script>

<template>
  <div class="cp">
    <!-- Toolbar -->
    <div class="cp__toolbar" role="toolbar" aria-label="Catalog filters">
      <div class="cp__search-wrap">
        <label for="catalog-search" class="sr-only">Search tools and backends</label>
        <input
          id="catalog-search"
          v-model="search"
          type="search"
          class="cp__search"
          placeholder="Search backends, tools, capabilities…"
          aria-label="Search catalog"
        />
      </div>

      <div class="cp__filters" role="group" aria-label="Filter by type">
        <button
          v-for="opt in [
            { value: 'all', label: 'All' },
            { value: 'read', label: 'Read only' },
            { value: 'state_change', label: 'Write ops' },
          ]"
          :key="opt.value"
          class="cp__filter-btn"
          :class="{ 'cp__filter-btn--active': filter === opt.value }"
          :aria-pressed="filter === opt.value"
          @click="filter = opt.value as typeof filter"
        >
          {{ opt.label }}
        </button>
      </div>

      <span v-if="!loading && !error && !sessionExpired" class="cp__count" aria-live="polite">
        {{ filteredBackends.length }} backend{{ filteredBackends.length !== 1 ? 's' : '' }} ·
        {{ visibleToolCount }} tool{{ visibleToolCount !== 1 ? 's' : '' }}
      </span>
    </div>

    <!-- Loading -->
    <div v-if="loading" class="cp__loading" aria-live="polite" aria-label="Loading catalog">
      <span class="cp__spinner" aria-hidden="true"></span>
      <span>Loading catalog…</span>
    </div>

    <!-- Session expired -->
    <div v-else-if="sessionExpired" class="cp__error" role="alert">
      <span class="cp__error-title">Session expired</span>
      <span class="cp__error-body">
        Your session has expired.
        <button type="button" class="cp__reload" @click="reload">Reload</button>
        to re-authenticate.
      </span>
    </div>

    <!-- Error -->
    <div v-else-if="error" class="cp__error" role="alert">
      <span class="cp__error-title">Catalog unavailable</span>
      <span class="cp__error-body">{{ error }}</span>
      <span class="cp__error-hint">
        Make sure your ATLAS IAM and CERN identities are linked on the
        <a href="/identities/" class="cp__error-link">Identities page</a>.
      </span>
    </div>

    <!-- Empty (no backends at all) -->
    <div v-else-if="backends.length === 0" class="cp__empty">
      <p class="cp__empty-title">No backends available</p>
      <p class="cp__empty-body">
        Your account doesn't have any granted capabilities yet. Link your external identities to
        unlock access.
      </p>
      <a href="/identities/" class="cp__empty-cta">Link identities →</a>
    </div>

    <!-- Empty search result -->
    <div v-else-if="filteredBackends.length === 0" class="cp__empty">
      <p class="cp__empty-title">No matches</p>
      <p class="cp__empty-body">
        No backends or tools match "{{ search }}" with the current filter. Try a different search
        term or clear the filter.
      </p>
    </div>

    <!-- Backend list -->
    <div v-else class="cp__list" role="list" aria-label="Available backends">
      <div v-for="backend in filteredBackends" :key="backend.backend" role="listitem">
        <BackendCard :backend="backend" />
      </div>
    </div>
  </div>
</template>

<style scoped>
.cp {
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

/* Toolbar */
.cp__toolbar {
  display: flex;
  align-items: center;
  gap: 1rem;
  flex-wrap: wrap;
}

.cp__search-wrap {
  flex: 1;
  min-width: 12rem;
}

.cp__search {
  width: 100%;
  background: var(--color-af-surface);
  border: 1px solid var(--color-af-muted);
  border-radius: 3px;
  color: var(--color-af-text);
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.8125rem;
  padding: 0.4375rem 0.75rem;
  transition: border-color 150ms;
}
.cp__search::placeholder {
  color: #4b5563;
}
.cp__search:focus {
  outline: none;
  border-color: var(--color-af-teal);
  box-shadow: 0 0 0 2px rgb(from var(--color-af-teal) r g b / 0.1);
}

.cp__filters {
  display: flex;
  gap: 0;
  border: 1px solid var(--color-af-muted);
  border-radius: 3px;
  overflow: hidden;
}

.cp__filter-btn {
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
.cp__filter-btn:last-child {
  border-right: none;
}
.cp__filter-btn:hover {
  color: var(--color-af-text);
  background: rgba(255, 255, 255, 0.04);
}
.cp__filter-btn:focus-visible {
  outline: 2px solid var(--color-af-teal);
  outline-offset: -2px;
}
.cp__filter-btn--active {
  color: var(--color-af-teal);
  background: rgb(from var(--color-af-teal) r g b / 0.08);
}

.cp__count {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.6875rem;
  color: #4b5563;
  white-space: nowrap;
  margin-left: auto;
}

/* List */
.cp__list {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

/* Loading */
.cp__loading {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  padding: 2rem;
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.8125rem;
  color: var(--color-af-dim);
}

.cp__spinner {
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
  .cp__spinner {
    animation: none;
    border-top-color: var(--color-af-dim);
  }
}

/* Error */
.cp__error {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
  padding: 1.25rem;
  border: 1px solid rgb(from var(--color-af-red) r g b / 0.2);
  border-radius: 4px;
  background: rgb(from var(--color-af-red) r g b / 0.05);
}

.cp__error-title {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.8125rem;
  font-weight: 600;
  color: var(--color-af-red);
}

.cp__error-body {
  font-size: 0.875rem;
  color: #9ca3af;
}

.cp__error-hint {
  font-size: 0.8125rem;
  color: var(--color-af-dim);
}

.cp__error-link {
  color: var(--color-af-teal);
  text-decoration: underline;
}

.cp__reload {
  font: inherit;
  color: var(--color-af-teal);
  background: none;
  border: none;
  padding: 0;
  cursor: pointer;
  text-decoration: underline;
}

/* Empty */
.cp__empty {
  padding: 3rem 1.5rem;
  text-align: center;
  border: 1px dashed var(--color-af-border);
  border-radius: 4px;
}

.cp__empty-title {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 1rem;
  font-weight: 600;
  color: #4b5563;
  margin: 0 0 0.5rem;
}

.cp__empty-body {
  font-size: 0.875rem;
  color: var(--color-af-muted);
  margin: 0 0 1.25rem;
  max-width: 32rem;
  margin-inline: auto;
  line-height: 1.6;
}

.cp__empty-cta {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.75rem;
  font-weight: 600;
  color: var(--color-af-teal);
  text-decoration: none;
  letter-spacing: 0.04em;
}
.cp__empty-cta:hover {
  text-decoration: underline;
}

.sr-only {
  position: absolute;
  width: 1px;
  height: 1px;
  padding: 0;
  margin: -1px;
  overflow: hidden;
  clip: rect(0, 0, 0, 0);
  white-space: nowrap;
  border: 0;
}
</style>
