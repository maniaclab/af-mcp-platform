<script setup lang="ts">
/**
 * AdminMismatchesSection.vue -- the admin page's "Annotation mismatches"
 * panel (issue #238 B.8). Emits `count` with the number of mismatches once
 * loaded, for the page's banner.
 */
import { onMounted, ref } from 'vue';
import { fetchAnnotationMismatches } from '../lib/api';
import type { AnnotationMismatch, LintServiceStatus } from '../lib/api';
import { permissionLabel } from '../lib/permissionLabel';
import { useLoadState } from '../lib/useLoadState';
import AsyncState from './ui/AsyncState.vue';
import LintObservations from './ui/LintObservations.vue';

const emit = defineEmits<{
  count: [n: number];
}>();

const mismatchState = useLoadState();

const mismatches = ref<AnnotationMismatch[]>([]);
const mismatchServices = ref<LintServiceStatus[]>([]);
const mismatchRetention = ref(0);

function resolvedViaLabel(m: AnnotationMismatch): string {
  if (m.resolved_via === 'target_action_types') return 'target_action_types glob override';
  if (m.resolved_via === 'permission') return `permission ${permissionLabel(m.permission)}`;
  return 'default fallback (read)';
}

onMounted(() => {
  void mismatchState.run(async () => {
    const report = await fetchAnnotationMismatches();
    mismatches.value = report.mismatches;
    mismatchServices.value = report.services;
    mismatchRetention.value = report.retention_seconds;
    emit('count', report.mismatches.length);
  }, 'Failed to load annotation mismatches.');
});
</script>

<template>
  <section id="ap-mismatches" class="af-sect ap__sect" aria-labelledby="ap-mismatches-title">
    <h2 id="ap-mismatches-title">Annotation mismatches</h2>
    <p class="af-help">
      Visibility only; enforcement is unchanged. A row means the backend's
      <code>readOnlyHint</code> disagrees with the broker's <code>action_type</code>. To resolve it,
      set a <code>target_action_types</code> glob for the service (keys are service names; globs
      match the prefixed tool name), declare the permission under <code>custom_permissions</code> if
      it is site-defined, or ask the backend to correct its annotation.
    </p>
    <AsyncState
      inline
      :loading="mismatchState.loading.value"
      :error="mismatchState.error.value"
      error-title="Could not load annotation mismatches"
      :session-expired="mismatchState.sessionExpired.value"
      :access-denied="mismatchState.accessDenied.value"
      loading-label="Loading annotation mismatches…"
    >
      <LintObservations
        :services="mismatchServices"
        :retention-seconds="mismatchRetention"
        :findings="mismatches.length"
        all-clear="No mismatches."
        noun="mismatches"
      />
      <div v-if="mismatches.length > 0" class="table-container af-box">
        <table class="af-compact table">
          <thead>
            <tr>
              <th scope="col">Service</th>
              <th scope="col">Tool</th>
              <th scope="col">Backend readOnlyHint</th>
              <th scope="col">Broker action_type</th>
              <th scope="col">Resolved via</th>
              <th scope="col">Permission</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="m in mismatches" :key="`${m.service}.${m.tool}`">
              <td>{{ m.service }}</td>
              <td>
                <code>{{ m.tool }}</code>
              </td>
              <td>readOnlyHint={{ m.declared_read_only_hint }}</td>
              <td>{{ m.resolved_action_type }}</td>
              <td class="af-sub">{{ resolvedViaLabel(m) }}</td>
              <td class="af-sub" :title="m.permission">{{ permissionLabel(m.permission) }}</td>
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
</style>
