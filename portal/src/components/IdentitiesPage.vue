<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { fetchIdentities } from '../lib/api';
import type { Identity } from '../lib/api';
import IdentityLink from './IdentityLink.vue';

const identities = ref<Identity[]>([]);
const loading = ref(true);
const error = ref<string | null>(null);

// Which capabilities depend on which providers — used for the warning banner
const requiredProviders: Record<string, string> = {
  'atlas-iam': 'AMI, Rucio, ATLAS grid jobs',
  'cern':      'CERN computing resources, CVMFS, grid proxies',
  'gitlab':    'ATLAS GitLab repositories and CI pipelines',
};

onMounted(async () => {
  try {
    const data = await fetchIdentities();
    identities.value = data.identities;
  } catch (err) {
    error.value = err instanceof Error
      ? err.message
      : 'Could not load identity status.';
  } finally {
    loading.value = false;
  }
});

// Unlink handler — update the local state so the UI reflects the change
function handleUnlinked(provider: string) {
  const idx = identities.value.findIndex(i => i.provider === provider);
  if (idx !== -1) {
    identities.value[idx] = { ...identities.value[idx], linked: false, subject: undefined };
  }
}

// Determines whether we should show the "missing required identity" warning
function missingRequired(provider: string): boolean {
  const id = identities.value.find(i => i.provider === provider);
  return id !== undefined && !id.linked;
}
</script>

<template>
  <div class="ip">
    <!-- Loading -->
    <div v-if="loading" class="ip__loading" aria-live="polite">
      <span class="ip__spinner" aria-hidden="true"></span>
      Loading identity status…
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
          <path d="M7 1L13 12H1L7 1Z" stroke="#F59E0B" stroke-width="1.25" stroke-linejoin="round"/>
          <path d="M7 5.5V8" stroke="#F59E0B" stroke-width="1.25" stroke-linecap="round"/>
          <circle cx="7" cy="10" r="0.6" fill="#F59E0B"/>
        </svg>
        <span>
          Link CERN and ATLAS IAM to access the full tool catalog and grid proxy generation.
        </span>
      </div>

      <!-- Identity list -->
      <div v-if="identities.length > 0" class="ip__list">
        <IdentityLink
          v-for="id in identities"
          :key="id.provider"
          :provider="id.provider"
          :linked="id.linked"
          :display_name="id.display_name"
          :description="id.description"
          :capabilities_unlocked="id.capabilities_unlocked"
          :subject="id.subject"
          :linked_at="id.linked_at"
          @unlinked="handleUnlinked"
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
          <div v-for="(description, provider) in requiredProviders" :key="provider" class="ip__explainer-row">
            <span class="ip__explainer-provider">{{ provider }}</span>
            <span class="ip__explainer-desc">{{ description }}</span>
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
  border: 1px solid rgba(245, 158, 11, 0.25);
  border-radius: 4px;
  background: rgba(245, 158, 11, 0.06);
  font-size: 0.875rem;
  color: #D97706;
  line-height: 1.5;
}

.ip__warn svg { flex-shrink: 0; margin-top: 0.1875rem; }

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
  color: #6B7280;
}

.ip__spinner {
  width: 16px;
  height: 16px;
  border: 2px solid #1F2937;
  border-top-color: #00D4C8;
  border-radius: 50%;
  animation: spin 600ms linear infinite;
}
@keyframes spin { to { transform: rotate(360deg); } }
@media (prefers-reduced-motion: reduce) {
  .ip__spinner { animation: none; border-top-color: #6B7280; }
}

/* Error */
.ip__error {
  display: flex;
  flex-direction: column;
  gap: 0.375rem;
  padding: 1rem;
  border: 1px solid rgba(239, 68, 68, 0.2);
  border-radius: 4px;
  background: rgba(239, 68, 68, 0.05);
}
.ip__error-title {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.8125rem;
  font-weight: 600;
  color: #EF4444;
}
.ip__error-body {
  font-size: 0.875rem;
  color: #9CA3AF;
}

/* Empty */
.ip__empty {
  padding: 3rem 1.5rem;
  text-align: center;
  border: 1px dashed #1F2937;
  border-radius: 4px;
}
.ip__empty-title {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 1rem;
  color: #4B5563;
  margin: 0 0 0.5rem;
}
.ip__empty-body { font-size: 0.875rem; color: #374151; margin: 0; }

/* Explainer */
.ip__explainer {
  padding: 1.25rem;
  border: 1px solid #1F2937;
  border-radius: 4px;
  background: rgba(17, 24, 39, 0.5);
}

.ip__explainer-title {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.625rem;
  font-weight: 600;
  letter-spacing: 0.1em;
  text-transform: uppercase;
  color: #4B5563;
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
  color: #00D4C8;
}

.ip__explainer-desc {
  font-size: 0.8125rem;
  color: #6B7280;
}
</style>
