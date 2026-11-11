<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import { fetchCatalog, fetchIdentities } from '../lib/api';
import type { CatalogServer, IdentityProvider } from '../lib/api';
import { resolvePoweredBy } from '../lib/catalog';
import { resolveServiceStatus } from '../lib/serviceStatus';
import { useLoadState } from '../lib/useLoadState';
import ServiceCard from './ServiceCard.vue';
import AsyncState from './ui/AsyncState.vue';
import SegmentedControl from './ui/SegmentedControl.vue';

const servers = ref<CatalogServer[]>([]);
const providers = ref<IdentityProvider[]>([]);
const { loading, error, sessionExpired, accessDenied, run } = useLoadState();
const filter = ref('all');
const search = ref('');

const FILTER_OPTIONS = [
  { value: 'all', label: 'All' },
  { value: 'read', label: 'Read only' },
  { value: 'state_change', label: 'Write ops' },
];

onMounted(() =>
  run(async () => {
    const [catalog, identities] = await Promise.all([fetchCatalog(), fetchIdentities()]);
    servers.value = catalog.servers;
    providers.value = identities.providers;
  }, 'Failed to load catalog. Check that your identities are linked.'),
);

const sortedServers = computed<CatalogServer[]>(() =>
  [...servers.value].sort((a, b) => a.name.localeCompare(b.name)),
);

const filteredServers = computed<CatalogServer[]>(() => {
  let result = sortedServers.value;

  if (filter.value !== 'all') {
    result = result.filter((s) => s.action_type === filter.value);
  }

  if (search.value.trim()) {
    const q = search.value.toLowerCase();
    result = result.filter(
      (s) =>
        s.name.toLowerCase().includes(q) ||
        s.display_name.toLowerCase().includes(q) ||
        s.description.toLowerCase().includes(q) ||
        (s.permission ?? '').toLowerCase().includes(q),
    );
  }

  return result;
});

function poweredByFor(server: CatalogServer) {
  return resolvePoweredBy(server.credential_provider, providers.value);
}

// The fix for each blocked status. Only link_required is fixable by the user.
const FIX_SENTENCE: Record<string, string> = {
  link_required: 'Link an identity to unlock access.',
  permission_required: 'An administrator needs to grant access.',
  unavailable: 'The backend is not responding. Try again later.',
  misconfigured: 'An administrator needs to fix the configuration.',
};

const blockedBanner = computed(() => {
  const blocked = servers.value.filter((s) => s.status !== 'available');
  if (blocked.length === 0) return null;

  const counts = new Map<string, number>();
  for (const s of blocked) counts.set(s.status, (counts.get(s.status) ?? 0) + 1);
  const [topStatus] = [...counts.entries()].sort((a, b) => b[1] - a[1])[0];
  const singleFix = counts.size === 1;
  const cta = resolveServiceStatus(blocked.find((s) => s.status === topStatus)!).cta;

  return {
    title: `${blocked.length} ${blocked.length === 1 ? 'service is' : 'services are'} blocked`,
    body: `${FIX_SENTENCE[topStatus]}${singleFix ? '' : ' Other rows need a different fix.'}`,
    // A button only when one fix covers every blocked service.
    cta: singleFix ? cta : null,
  };
});
</script>

<template>
  <AsyncState
    :loading="loading"
    :error="error"
    error-title="Services unavailable"
    :session-expired="sessionExpired"
    :access-denied="accessDenied"
    :empty="servers.length === 0"
    loading-label="Loading services…"
  >
    <template #error-hint>
      <span class="cp__hint">
        Make sure your ATLAS IAM and CERN identities are linked on the
        <a href="/identities/">Identities page</a>.
      </span>
    </template>

    <template #empty>
      <b>No services available</b>
      <p>
        Your account doesn't have any granted permissions yet. Link your external identities to
        unlock access.
      </p>
      <a href="/identities/" class="af-btn secondary">Link identities</a>
    </template>

    <div class="cp">
      <div v-if="blockedBanner" class="af-banner bad" role="status">
        <span class="af-mark bad" aria-hidden="true"></span>
        <div>
          <b>{{ blockedBanner.title }}</b>
          {{ blockedBanner.body }}
        </div>
        <a v-if="blockedBanner.cta" :href="blockedBanner.cta.href" class="af-btn s">
          {{ blockedBanner.cta.label }}
        </a>
      </div>

      <section class="af-sect" aria-labelledby="cp-heading">
        <h2 id="cp-heading">Your services</h2>

        <div class="cp__toolbar">
          <div class="af-field cp__search">
            <label for="catalog-search">Search services</label>
            <input
              id="catalog-search"
              v-model="search"
              type="search"
              class="af-input"
              placeholder="Name, description or permission"
            />
          </div>

          <SegmentedControl
            v-model="filter"
            :options="FILTER_OPTIONS"
            aria-label="Filter by type"
          />

          <span class="cp__count" aria-live="polite">
            {{ filteredServers.length }} service{{ filteredServers.length !== 1 ? 's' : '' }}
          </span>
        </div>

        <div v-if="filteredServers.length === 0" class="af-empty">
          <b>No matches</b>
          <p>
            No services match "{{ search }}" with the current filter. Try a different search term or
            clear the filter.
          </p>
        </div>

        <ul v-else class="cp__list" aria-label="Available services">
          <li v-for="server in filteredServers" :key="server.name" class="cp__item">
            <ServiceCard :server="server" :powered-by="poweredByFor(server)" />
          </li>
        </ul>
      </section>
    </div>
  </AsyncState>
</template>

<style scoped>
.cp {
  display: flex;
  flex-direction: column;
  gap: var(--space-32);
}

.cp__hint {
  display: block;
}

.cp__toolbar {
  display: flex;
  flex-wrap: wrap;
  align-items: flex-end;
  gap: var(--space-12) var(--space-16);
}

.cp__search {
  flex: 1;
  min-width: 12rem;
  max-width: 360px;
}

.cp__count {
  margin-left: auto;
  color: var(--color-af-text-secondary);
  font-size: var(--text-13);
  white-space: nowrap;
}

/* One bordered list; rows are separated by rules, not boxed individually. */
.cp__list {
  list-style: none;
  margin: 0;
  padding: 0;
  border: 1px solid var(--color-af-border);
  border-radius: var(--radius-10);
}

.cp__item {
  border-bottom: 1px solid var(--color-af-border);
}

.cp__item:last-child {
  border-bottom: 0;
}
</style>
