<script setup lang="ts">
/**
 * PageMessage.vue — the message in a page's banner slot (see PageMessage in
 * lib/serviceStatus.ts). A problem or warning is a solid `.af-banner` and an
 * alert; a hint is an inline information `.af-note` and a polite status.
 */
import type { PageMessage } from '../../lib/serviceStatus';

defineProps<{ message: PageMessage }>();
</script>

<template>
  <div
    class="alert"
    :class="message.kind === 'banner' ? ['af-banner', message.tone] : ['af-note', 'info', 'pm']"
    :role="message.kind === 'banner' ? 'alert' : 'status'"
  >
    <span
      class="af-mark"
      :class="message.kind === 'banner' ? message.tone : 'info'"
      aria-hidden="true"
    ></span>
    <div>
      <b>{{ message.title }}</b
      >{{ message.body }}
    </div>
    <a
      v-if="message.action"
      class="btn"
      data-variant="outline"
      data-size="sm"
      :href="message.action.href"
      >{{ message.action.label }}</a
    >
  </div>
</template>

<style scoped>
/* A hint's title runs into its sentence and the action sits at the end of the
   row; wrapping keeps the button on screen at narrow widths. */
.pm {
  flex-wrap: wrap;
  align-items: center;
}

.pm > div {
  flex: 1 1 180px;
  min-width: 0;
}

.pm b {
  margin-right: var(--space-8);
  font-weight: 600;
}
</style>
