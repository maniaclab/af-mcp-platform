<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { fetchProxyStatus, SessionExpiredError } from '../lib/api';
import type { ProxyStatus } from '../lib/api';
import ProxyStatusWidget from './ProxyStatus.vue';

const status = ref<ProxyStatus | null>(null);
const loading = ref(true);
const error = ref<string | null>(null);
const sessionExpired = ref(false);

onMounted(async () => {
  try {
    status.value = await fetchProxyStatus();
  } catch (err) {
    if (err instanceof SessionExpiredError) {
      sessionExpired.value = true;
    } else {
      error.value = err instanceof Error ? err.message : 'Could not load proxy status.';
    }
  } finally {
    loading.value = false;
  }
});

function handleUnlocked(newStatus: ProxyStatus) {
  status.value = newStatus;
}

function handleRevoked() {
  status.value = { cached: false, voms_attributes: [] };
}

function reload() {
  location.reload();
}
</script>

<template>
  <div class="psp">
    <div v-if="loading" class="psp__loading" aria-live="polite">
      <span class="psp__spinner" aria-hidden="true"></span>
      Checking proxy status…
    </div>

    <div v-else-if="sessionExpired" class="psp__error" role="alert">
      <span class="psp__error-title">Session expired</span>
      <span class="psp__error-body">
        Your session has expired.
        <button type="button" class="psp__reload" @click="reload">Reload</button>
        to re-authenticate.
      </span>
    </div>

    <div v-else-if="error" class="psp__error" role="alert">
      <span class="psp__error-title">Status unavailable</span>
      <span class="psp__error-body">{{ error }}</span>
    </div>

    <ProxyStatusWidget
      v-else-if="status !== null"
      :status="status"
      @unlocked="handleUnlocked"
      @revoked="handleRevoked"
    />
  </div>
</template>

<style scoped>
.psp {
  max-width: 42rem;
}

.psp__loading {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  padding: 2rem 0;
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.8125rem;
  color: var(--color-af-dim);
}

.psp__spinner {
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
  .psp__spinner {
    animation: none;
    border-top-color: var(--color-af-dim);
  }
}

.psp__error {
  display: flex;
  flex-direction: column;
  gap: 0.375rem;
  padding: 1rem;
  border: 1px solid rgb(from var(--color-af-red) r g b / 0.2);
  border-radius: 4px;
  background: rgb(from var(--color-af-red) r g b / 0.05);
}
.psp__error-title {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.8125rem;
  font-weight: 600;
  color: var(--color-af-red);
}
.psp__error-body {
  font-size: 0.875rem;
  color: #9ca3af;
}

.psp__reload {
  font: inherit;
  color: var(--color-af-teal);
  background: none;
  border: none;
  padding: 0;
  cursor: pointer;
  text-decoration: underline;
}
</style>
