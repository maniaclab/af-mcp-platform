<script setup lang="ts">
/**
 * LintObservations.vue — what an admin lint table (annotation mismatches,
 * tool mapping drift) has actually observed. The lint runs only when a caller
 * lists a service's tools, so an empty table alone cannot tell "checked and
 * clean" from "never checked": this states which, and lists when each
 * service was last observed.
 */
import { computed } from 'vue';

import type { LintServiceStatus } from '../../lib/api';
import { formatDateTime, formatRelative } from '../../lib/relativeTime';
import StatusMark from './StatusMark.vue';

const props = defineProps<{
  services: LintServiceStatus[];
  /** How long an observation stays on record; the window "not yet observed" speaks about. */
  retentionSeconds: number;
  /** Findings currently shown in the table above this. */
  findings: number;
  /** All-clear text, used only when every service has been observed (e.g. "No mismatches."). */
  allClear: string;
  /** What the all-clear text names, to qualify it when only some services were observed. */
  noun: string;
}>();

function exactTime(epochSeconds: number): string {
  return formatDateTime(new Date(epochSeconds * 1000), { year: true });
}

const unobserved = computed(() => props.services.filter((s) => s.last_observed === null));

/** Start of the window with no observation on record. */
const since = computed(() => exactTime(Date.now() / 1000 - props.retentionSeconds));
</script>

<template>
  <p v-if="findings === 0 && services.length > 0" class="lint__status">
    <StatusMark v-if="unobserved.length === 0" tone="ok">{{ allClear }}</StatusMark>
    <StatusMark v-else-if="unobserved.length === services.length" tone="warn">
      <span data-af-not-observed
        >Not yet observed since {{ since }}. No caller has listed any service's tools in that time,
        so this says nothing about {{ noun }}.</span
      >
    </StatusMark>
    <StatusMark v-else tone="info"
      >No {{ noun }} among the observed services. The others are not yet observed.</StatusMark
    >
  </p>
  <ul v-if="services.length > 0" class="af-sub lint__observed" data-af-observed>
    <li v-for="s in services" :key="s.service">
      <code>{{ s.service }}</code
      >:
      <template v-if="s.last_observed !== null">
        observed
        <span :title="exactTime(s.last_observed)">{{
          formatRelative(s.last_observed * 1000)
        }}</span>
      </template>
      <template v-else>not yet observed since {{ since }}</template>
    </li>
  </ul>
</template>

<style scoped>
.lint__status {
  margin: 0;
  font-size: var(--text-13);
}

.lint__observed {
  margin: var(--space-8) 0 0;
  padding: 0;
  list-style: none;
}

.lint__observed code {
  font-family: var(--font-mono);
  font-size: var(--text-13);
}
</style>
