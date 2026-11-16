<script setup lang="ts">
/**
 * AdminDriftSection.vue -- the admin page's "Tool mapping drift" panel
 * (issue #330). Emits `count` with the number of drifting services once
 * loaded, for the page's banner.
 */
import { onMounted, ref } from 'vue';
import { fetchToolMappingDrift } from '../lib/api';
import type { LintServiceStatus, ToolMappingDrift } from '../lib/api';
import { useLoadState } from '../lib/useLoadState';
import AsyncState from './ui/AsyncState.vue';
import LintObservations from './ui/LintObservations.vue';
import ToolNameList from './ui/ToolNameList.vue';

const emit = defineEmits<{
  count: [n: number];
}>();

const driftState = useLoadState();

const drifts = ref<ToolMappingDrift[]>([]);
const driftServices = ref<LintServiceStatus[]>([]);
const driftRetention = ref(0);

onMounted(() => {
  void driftState.run(async () => {
    const report = await fetchToolMappingDrift();
    drifts.value = report.drift;
    driftServices.value = report.services;
    driftRetention.value = report.retention_seconds;
    emit('count', report.drift.length);
  }, 'Failed to load tool mapping drift.');
});
</script>

<template>
  <section id="ap-drift" class="af-sect ap__sect" aria-labelledby="ap-drift-title">
    <h2 id="ap-drift-title">Tool mapping drift</h2>
    <p class="af-help">
      Visibility only. <strong>Unmapped</strong> tools are advertised by the backend but have no
      <code>required_permission</code> entry and no <code>__default__</code>, so they are disabled:
      add them to the service's <code>required_permission</code>. <strong>Stale</strong> entries are
      mapped keys the backend no longer advertises (usually a backend rename): rename or remove
      them. <strong>Unroutable</strong> tools are advertised without the service's
      <code>prefix</code> (an <code>apply_namespace: false</code> backend that renamed its tools),
      so no caller sees them: update the service's <code>prefix</code> and
      <code>required_permission</code> keys to the backend's names.
    </p>
    <AsyncState
      inline
      :loading="driftState.loading.value"
      :error="driftState.error.value"
      error-title="Could not load tool mapping drift"
      :session-expired="driftState.sessionExpired.value"
      :access-denied="driftState.accessDenied.value"
      loading-label="Loading tool mapping drift…"
    >
      <LintObservations
        :services="driftServices"
        :retention-seconds="driftRetention"
        :findings="drifts.length"
        all-clear="No tool mapping drift."
        noun="tool mapping drift"
      />
      <div v-if="drifts.length > 0" class="table-container af-box">
        <table class="af-compact table">
          <thead>
            <tr>
              <th scope="col">Service</th>
              <th scope="col" class="af-num">Routable / advertised</th>
              <th scope="col">Unroutable (prefix mismatch)</th>
              <th scope="col">Unmapped (advertised, disabled)</th>
              <th scope="col">Stale (mapped, not advertised)</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="d in drifts" :key="d.service">
              <td>{{ d.service }}</td>
              <td class="af-num">{{ d.routable }} / {{ d.advertised }}</td>
              <td data-af-drift-unroutable>
                <p v-if="d.unroutable.length > 0" class="ap__expected">
                  Expected <code>{{ d.prefix }}_*</code>
                </p>
                <ToolNameList :names="d.unroutable" />
              </td>
              <td data-af-drift-unmapped>
                <ToolNameList :names="d.unmapped" />
              </td>
              <td data-af-drift-stale>
                <ToolNameList :names="d.stale" />
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </AsyncState>
  </section>
</template>

<style scoped>
.ap__sect code {
  font-family: var(--font-mono);
  font-size: var(--text-13);
}

/* The prefix a service's unroutable tools were expected to carry. */
.ap__expected {
  margin: var(--space-8) 0 0;
  color: var(--color-af-text-secondary);
}
</style>
