<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { fetchIdentities, SessionExpiredError } from '../lib/api';
import IdentityLink from './IdentityLink.vue';

interface ProviderRow {
  provider: string;
  display_name: string;
  description: string;
  linked: boolean;
  sub?: string;
}

// The broker only returns display_name/enables for providers still AVAILABLE to
// link; already-linked accounts arrive as {provider, sub}. Fill their labels
// from this client-side map (mirrors the broker's _PROVIDERS metadata).
const PROVIDER_META: Record<string, { display_name: string; enables: string }> = {
  'atlas-iam': {
    display_name: 'ATLAS IAM',
    enables: 'VOMS proxy generation and grid certificate credential brokering',
  },
  cern: {
    display_name: 'CERN SSO',
    enables: 'CERN resource access and CMS/ATLAS experiment datasets',
  },
};

const rows = ref<ProviderRow[]>([]);
const linkedProviders = ref<Set<string>>(new Set());
const loading = ref(true);
const error = ref<string | null>(null);
const sessionExpired = ref(false);

onMounted(async () => {
  try {
    const data = await fetchIdentities();
    const linked: ProviderRow[] = data.linked_accounts.map((a) => ({
      provider: a.provider,
      display_name: PROVIDER_META[a.provider]?.display_name ?? a.provider,
      description: PROVIDER_META[a.provider]?.enables ?? '',
      linked: true,
      sub: a.sub,
    }));
    const available: ProviderRow[] = data.available_providers.map((p) => ({
      provider: p.provider,
      display_name: p.display_name,
      description: p.enables,
      linked: false,
    }));
    rows.value = [...linked, ...available];
    linkedProviders.value = new Set(data.linked_accounts.map((a) => a.provider));
  } catch (err) {
    if (err instanceof SessionExpiredError) {
      sessionExpired.value = true;
    } else {
      error.value = err instanceof Error ? err.message : 'Could not load identity status.';
    }
  } finally {
    loading.value = false;
  }
});

function reload() {
  location.reload();
}

// Show the "missing required identity" warning when a key provider is unlinked.
function missingRequired(provider: string): boolean {
  return !linkedProviders.value.has(provider);
}
</script>

<template>
  <div class="ip">
    <!-- Loading -->
    <div v-if="loading" class="ip__loading" aria-live="polite">
      <span class="ip__spinner" aria-hidden="true"></span>
      Loading identity status…
    </div>

    <!-- Session expired -->
    <div v-else-if="sessionExpired" class="ip__error" role="alert">
      <span class="ip__error-title">Session expired</span>
      <span class="ip__error-body">
        Your session has expired.
        <button type="button" class="ip__reload" @click="reload">Reload</button>
        to re-authenticate.
      </span>
    </div>

    <!-- Error -->
    <div v-else-if="error" class="ip__error" role="alert">
      <span class="ip__error-title">Could not load identities</span>
      <span class="ip__error-body">{{ error }}</span>
    </div>

    <template v-else>
      <!-- Warning: missing required identities -->
      <div
        v-if="missingRequired('cern') || missingRequired('atlas-iam')"
        class="ip__warn"
        role="status"
      >
        <svg width="14" height="14" viewBox="0 0 14 14" fill="none" aria-hidden="true">
          <path
            d="M7 1L13 12H1L7 1Z"
            stroke="var(--color-af-amber)"
            stroke-width="1.25"
            stroke-linejoin="round"
          />
          <path
            d="M7 5.5V8"
            stroke="var(--color-af-amber)"
            stroke-width="1.25"
            stroke-linecap="round"
          />
          <circle cx="7" cy="10" r="0.6" fill="var(--color-af-amber)" />
        </svg>
        <span>
          Link CERN and ATLAS IAM to access the full tool catalog and grid proxy generation.
        </span>
      </div>

      <!-- Identity list -->
      <div v-if="rows.length > 0" class="ip__list">
        <IdentityLink
          v-for="row in rows"
          :key="row.provider"
          :provider="row.provider"
          :linked="row.linked"
          :display_name="row.display_name"
          :description="row.description"
          :sub="row.sub"
        />
      </div>

      <!-- No providers returned at all -->
      <div v-else class="ip__empty">
        <p class="ip__empty-title">No identity providers configured</p>
        <p class="ip__empty-body">
          Contact your facility administrator to enable external identity providers.
        </p>
      </div>

      <!-- What each provider unlocks -->
      <div class="ip__explainer">
        <h2 class="ip__explainer-title">What each identity unlocks</h2>
        <div class="ip__explainer-grid">
          <div v-for="(meta, provider) in PROVIDER_META" :key="provider" class="ip__explainer-row">
            <span class="ip__explainer-provider">{{ provider }}</span>
            <span class="ip__explainer-desc">{{ meta.enables }}</span>
          </div>
        </div>
      </div>
    </template>
  </div>
</template>

<style scoped>
.ip {
  display: flex;
  flex-direction: column;
  gap: 1.5rem;
}

/* Warning */
.ip__warn {
  display: flex;
  align-items: flex-start;
  gap: 0.625rem;
  padding: 0.875rem 1rem;
  border: 1px solid rgb(from var(--color-af-amber) r g b / 0.25);
  border-radius: 4px;
  background: rgb(from var(--color-af-amber) r g b / 0.06);
  font-size: 0.875rem;
  color: #d97706;
  line-height: 1.5;
}

.ip__warn svg {
  flex-shrink: 0;
  margin-top: 0.1875rem;
}

/* List */
.ip__list {
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
}

/* Loading */
.ip__loading {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  padding: 2rem;
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.8125rem;
  color: var(--color-af-dim);
}

.ip__spinner {
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
  .ip__spinner {
    animation: none;
    border-top-color: var(--color-af-dim);
  }
}

/* Error */
.ip__error {
  display: flex;
  flex-direction: column;
  gap: 0.375rem;
  padding: 1rem;
  border: 1px solid rgb(from var(--color-af-red) r g b / 0.2);
  border-radius: 4px;
  background: rgb(from var(--color-af-red) r g b / 0.05);
}
.ip__error-title {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.8125rem;
  font-weight: 600;
  color: var(--color-af-red);
}
.ip__error-body {
  font-size: 0.875rem;
  color: #9ca3af;
}

.ip__reload {
  font: inherit;
  color: var(--color-af-teal);
  background: none;
  border: none;
  padding: 0;
  cursor: pointer;
  text-decoration: underline;
}

/* Empty */
.ip__empty {
  padding: 3rem 1.5rem;
  text-align: center;
  border: 1px dashed var(--color-af-border);
  border-radius: 4px;
}
.ip__empty-title {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 1rem;
  color: #4b5563;
  margin: 0 0 0.5rem;
}
.ip__empty-body {
  font-size: 0.875rem;
  color: var(--color-af-muted);
  margin: 0;
}

/* Explainer */
.ip__explainer {
  padding: 1.25rem;
  border: 1px solid var(--color-af-border);
  border-radius: 4px;
  background: rgb(from var(--color-af-surface) r g b / 0.5);
}

.ip__explainer-title {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.625rem;
  font-weight: 600;
  letter-spacing: 0.1em;
  text-transform: uppercase;
  color: #4b5563;
  margin: 0 0 0.875rem;
}

.ip__explainer-grid {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.ip__explainer-row {
  display: grid;
  grid-template-columns: 8rem 1fr;
  gap: 1rem;
  align-items: baseline;
}

.ip__explainer-provider {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.75rem;
  color: var(--color-af-teal);
}

.ip__explainer-desc {
  font-size: 0.8125rem;
  color: var(--color-af-dim);
}
</style>
