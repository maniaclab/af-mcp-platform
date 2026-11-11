<script setup lang="ts">
/**
 * InfoTip.vue — an icon-only "more information" button with a hover/focus
 * tooltip. The tooltip text is the button's description; `label` is its name,
 * since an icon alone names nothing.
 */
import { Info } from '@lucide/vue';
import type { TooltipSide } from '../../lib/tooltipPosition';
import PopoverTooltip from '../PopoverTooltip.vue';

withDefaults(
  defineProps<{
    /** Id of the tooltip description the button points at. */
    id: string;
    /** Tooltip text; use the default slot instead for markup. */
    text?: string;
    /** Accessible name of the button. */
    label?: string;
    placement?: TooltipSide;
  }>(),
  { text: '', label: 'More information', placement: 'top' },
);
</script>

<template>
  <PopoverTooltip :tooltip-id="id" :side="placement">
    <button type="button" class="info-tip" :aria-describedby="id" :aria-label="label">
      <Info class="af-icon" :size="16" aria-hidden="true" />
    </button>
    <template #tooltip
      ><slot>{{ text }}</slot></template
    >
  </PopoverTooltip>
</template>

<style scoped>
.info-tip {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: var(--control-s);
  height: var(--control-s);
  padding: 0;
  border: 0;
  border-radius: var(--radius-full);
  background: transparent;
  color: var(--color-af-text-secondary);
  cursor: pointer;
}

.info-tip:hover {
  color: var(--color-af-text);
}
</style>
