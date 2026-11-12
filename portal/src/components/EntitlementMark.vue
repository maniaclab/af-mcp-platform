<script setup lang="ts">
/**
 * EntitlementMark.vue — one cell of the entitlements matrix and one legend
 * entry. The three states differ by shape (check, pencil, dash) as well as
 * colour. With a `label` the mark is an image with that accessible name;
 * without one it is decoration beside words that already say the same thing.
 */
import { Check, Minus, Pencil } from '@lucide/vue';

defineProps<{
  kind: 'read' | 'write' | 'none';
  label?: string;
}>();
</script>

<template>
  <span
    class="em"
    :class="kind"
    :role="label ? 'img' : undefined"
    :aria-label="label"
    :aria-hidden="label ? undefined : 'true'"
  >
    <Check v-if="kind === 'read'" class="af-icon" :size="16" aria-hidden="true" />
    <Pencil v-else-if="kind === 'write'" class="af-icon" :size="16" aria-hidden="true" />
    <Minus v-else class="af-icon" :size="16" aria-hidden="true" />
  </span>
</template>

<style scoped>
.em {
  display: inline-flex;
  align-items: center;
  justify-content: center;
}

.read {
  color: var(--color-af-ok);
}

.write {
  color: var(--color-af-warn);
}

.none {
  color: var(--color-af-text-secondary);
}
</style>
