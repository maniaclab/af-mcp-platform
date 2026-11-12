<script setup lang="ts">
/**
 * Disclosure.vue — a button that expands and collapses a region
 * (`aria-expanded` / `aria-controls`), with a chevron that turns when open.
 *
 * `v-model:open` for plain use. To fetch on expand, pass `:open` and
 * `@toggle` from useFetchOnExpand instead: the composable then owns the
 * state, and `toggle` fires after the model changes.
 */
import { ChevronRight } from '@lucide/vue';
import { useId } from 'vue';

defineProps<{
  label?: string;
  /** Names the region when the button's own label is not the right name. */
  regionLabel?: string;
}>();

const emit = defineEmits<{ toggle: [open: boolean] }>();
const open = defineModel<boolean>('open', { default: false });

const buttonId = useId();
const regionId = useId();

function toggle(): void {
  open.value = !open.value;
  emit('toggle', open.value);
}
</script>

<template>
  <div class="disclosure">
    <button
      :id="buttonId"
      type="button"
      class="disclosure__toggle"
      :aria-expanded="open"
      :aria-controls="regionId"
      @click="toggle"
    >
      <ChevronRight
        class="af-icon disclosure__chevron"
        :class="{ 'disclosure__chevron--open': open }"
        :size="16"
        aria-hidden="true"
      />
      <slot name="label">{{ label }}</slot>
      <slot name="badge" />
    </button>
    <div
      v-if="open"
      :id="regionId"
      role="region"
      :aria-label="regionLabel"
      :aria-labelledby="regionLabel ? undefined : buttonId"
      class="disclosure__body"
    >
      <slot />
    </div>
  </div>
</template>

<style scoped>
.disclosure__toggle {
  display: inline-flex;
  align-items: center;
  gap: var(--space-8);
  padding: var(--space-4) 0;
  border: 0;
  background: transparent;
  color: var(--color-af-text);
  font: 500 var(--text-13) / 1.4 var(--font-sans);
  cursor: pointer;
}

.disclosure__chevron {
  transition: transform var(--time-base) var(--ease);
}

.disclosure__chevron--open {
  transform: rotate(90deg);
}

.disclosure__body {
  margin-top: var(--space-8);
}

@media (prefers-reduced-motion: reduce) {
  .disclosure__chevron {
    transition: none;
  }
}
</style>
