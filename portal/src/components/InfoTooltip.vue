<script setup lang="ts">
withDefaults(
  defineProps<{
    tooltipId: string;
    maxWidth?: string;
  }>(),
  { maxWidth: '16rem' },
);
</script>

<template>
  <span class="info-tooltip">
    <slot />
    <span :id="tooltipId" class="info-tooltip__bubble" role="tooltip" :style="{ maxWidth }">
      <slot name="tooltip" />
    </span>
  </span>
</template>

<style scoped>
/* Wrapper + tooltip -- the trigger (default slot) is expected to be a
 * focusable element (button) describedby the tooltip span below, which
 * stays in the DOM at all times (hidden via opacity/visibility, not
 * display: none) so aria-describedby reaches it for assistive tech
 * regardless of hover/focus state. */
.info-tooltip {
  position: relative;
  display: inline-flex;
}

.info-tooltip__bubble {
  position: absolute;
  top: 100%;
  left: 0;
  margin-top: 0.375rem;
  width: max-content;
  padding: 0.5rem 0.625rem;
  background: var(--color-af-void);
  border: 1px solid var(--color-af-muted);
  border-radius: 4px;
  font-family: 'IBM Plex Sans', system-ui, sans-serif;
  font-size: 0.75rem;
  line-height: 1.5;
  color: var(--color-af-text);
  white-space: normal;
  word-break: break-word;
  opacity: 0;
  visibility: hidden;
  transition: opacity 120ms;
  pointer-events: none;
  z-index: 10;
}
.info-tooltip:hover .info-tooltip__bubble,
.info-tooltip:focus-within .info-tooltip__bubble {
  opacity: 1;
  visibility: visible;
}
</style>
