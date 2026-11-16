<script setup lang="ts">
/**
 * AdminUsageSection.vue -- the admin page's "Usage across users" panel.
 *
 * A dropdown fed by GET /v1/usage/subjects (only subjects with recorded
 * activity -- never a full Keycloak user directory); selecting one renders
 * that subject's usage via UsagePage.vue's existing rendering (its `subject`
 * prop), rather than duplicating any of that markup here.
 */
import { onMounted, ref } from 'vue';
import { fetchUsageSubjects } from '../lib/api';
import type { UsageSubject } from '../lib/api';
import { useLoadState } from '../lib/useLoadState';
import AsyncState from './ui/AsyncState.vue';
import StatusMark from './ui/StatusMark.vue';
import UsagePage from './UsagePage.vue';

/** unixname is the most recognizable label to an operator; fall back to
 * email, then the bare subject, for a principal the cache couldn't resolve. */
function subjectLabel(s: UsageSubject): string {
  return s.unixname || s.email || s.subject;
}

const usageState = useLoadState();

const subjects = ref<UsageSubject[]>([]);
const selectedSubject = ref<string>('');

onMounted(() => {
  void usageState.run(async () => {
    subjects.value = (await fetchUsageSubjects()).subjects;
  }, 'Failed to load subjects.');
});
</script>

<template>
  <section class="af-sect" aria-labelledby="ap-usage-title">
    <h2 id="ap-usage-title">Usage across users</h2>
    <AsyncState
      inline
      :loading="usageState.loading.value"
      :error="usageState.error.value"
      error-title="Could not load subjects"
      :session-expired="usageState.sessionExpired.value"
      :access-denied="usageState.accessDenied.value"
      loading-label="Loading subjects…"
    >
      <p v-if="subjects.length === 0" class="ap__none">
        <StatusMark tone="off">No subjects with recorded usage yet.</StatusMark>
      </p>
      <template v-else>
        <div class="field af-narrow">
          <label for="ap-usage-subject">Subject</label>
          <select id="ap-usage-subject" v-model="selectedSubject" class="select w-full">
            <option value="" disabled>Select a subject…</option>
            <option v-for="s in subjects" :key="s.subject" :value="s.subject">
              {{ subjectLabel(s) }}
            </option>
          </select>
        </div>

        <!-- Keyed on the selection so switching subjects remounts UsagePage,
               the same way it already reloads when its own window selector
               changes -- no separate refetch wiring needed here. -->
        <UsagePage v-if="selectedSubject" :key="selectedSubject" :subject="selectedSubject" />
      </template>
    </AsyncState>
  </section>
</template>

<style scoped>
.ap__none {
  margin: 0;
  font-size: var(--text-13);
}
</style>
