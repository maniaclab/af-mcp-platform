<script setup lang="ts">
import { onBeforeUnmount, onMounted, useTemplateRef } from 'vue';

withDefaults(
  defineProps<{
    tooltipId: string;
    maxWidth?: string;
  }>(),
  { maxWidth: '16rem' },
);

const wrapper = useTemplateRef<HTMLSpanElement>('wrapper');

// The trigger is a real <button> so a keyboard/screen-reader user can reach
// the tooltip via Tab (a hover-only tooltip is invisible to them) -- but
// that means a mouse click also leaves it focused, and CSS :focus-within
// keeps the bubble open until focus moves elsewhere, which reads as a
// "frozen" tooltip to a mouse user who clicked expecting an action. The
// trigger does nothing on click, so blur it immediately after: hover still
// closes the bubble normally once the pointer leaves, and Tab-driven focus
// (no click event) is untouched.
//
// Attached imperatively (not a template @click) because a template click
// binding on this non-interactive wrapper span would be exactly the "static
// element interaction" eslint-plugin-vuejs-accessibility exists to catch --
// correctly so for a real interactive behavior, but this handler adds none:
// the slotted trigger keeps its own semantics, this just releases focus
// after the fact.
function releaseClickFocus(): void {
  if (document.activeElement instanceof HTMLElement && document.activeElement !== document.body) {
    document.activeElement.blur();
  }
}

onMounted(() => wrapper.value?.addEventListener('click', releaseClickFocus));
onBeforeUnmount(() => wrapper.value?.removeEventListener('click', releaseClickFocus));
</script>

<template>
  <span ref="wrapper" class="info-tooltip">
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
