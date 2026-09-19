<script setup lang="ts">
/**
 * PopoverTooltip.vue — a hover/focus tooltip built on the native Popover
 * API, replacing both the retired hand-rolled InfoTooltip.vue AND
 * Basecoat's own `data-tooltip` (tried first -- see git history and
 * DESIGN.md's Tooltips entry). Basecoat's tooltip is a plain
 * `position: absolute` `::before` anchored inside its trigger's own
 * containing block: it does not escape an `overflow: hidden`/`auto`
 * ancestor, and while hidden it still counts toward that ancestor's
 * scrollable overflow -- the exact clipping/scroll-inflation bug
 * TokensPage.vue's and EntitlementsPage.vue's own siting comments describe,
 * unchanged by that swap. A `[popover]` element is promoted to the
 * browser's top layer once shown, genuinely outside any ancestor's
 * containing block or overflow clipping -- this is the one tooltip need
 * Basecoat's shipped component doesn't cover, so building our own here is
 * a deliberate, documented exception to DESIGN.md's Basecoat-class-first
 * rule, not a lapse back into hand-rolling everything.
 *
 * Usage mirrors the retired InfoTooltip.vue: the default slot is the
 * trigger (the caller's own focusable element, describedby `tooltipId`),
 * the #tooltip slot is the tooltip text.
 */
import { onBeforeUnmount, onMounted, useTemplateRef } from 'vue';
import { computeTooltipPosition, type TooltipSide } from '../lib/tooltipPosition';

const props = withDefaults(
  defineProps<{
    /** id of this tooltip's screen-reader description -- callers point their own trigger's aria-describedby at this id, the same contract InfoTooltip.vue used. */
    tooltipId: string;
    side?: TooltipSide;
  }>(),
  { side: 'bottom' },
);

const trigger = useTemplateRef<HTMLSpanElement>('trigger');
const bubble = useTemplateRef<HTMLDivElement>('bubble');

// The Popover API has no declarative hover trigger (`popovertarget` is
// click-only), so this tracks hover and focus independently and shows
// while EITHER is true -- matching InfoTooltip.vue's `:hover,
// :focus-within` OR semantics rather than closing the instant either one
// alone ends.
let hovering = false;
let focused = false;

function position(): void {
  if (!trigger.value || !bubble.value) return;
  const pos = computeTooltipPosition(
    trigger.value.getBoundingClientRect(),
    { width: bubble.value.offsetWidth, height: bubble.value.offsetHeight },
    props.side,
    { width: window.innerWidth, height: window.innerHeight },
  );
  bubble.value.style.top = `${pos.top}px`;
  bubble.value.style.left = `${pos.left}px`;
}

function updateVisibility(): void {
  const el = bubble.value;
  // Feature-detected, not browser-sniffed: older browsers without the
  // Popover API simply never show the bubble -- the sr-only description
  // still reaches assistive tech regardless, so nothing is lost but the
  // hover affordance.
  if (!el || typeof el.showPopover !== 'function') return;
  if (hovering || focused) {
    position();
    el.showPopover();
  } else {
    el.hidePopover();
  }
}

function onMouseEnter(): void {
  hovering = true;
  updateVisibility();
}
function onMouseLeave(): void {
  hovering = false;
  updateVisibility();
}
function onFocusIn(): void {
  focused = true;
  updateVisibility();
}
function onFocusOut(): void {
  focused = false;
  updateVisibility();
}

// A mouse click leaves the trigger focused (`focused` stays true) -- without
// releasing that focus, moving the mouse away afterward would leave the
// bubble open forever (`focused` alone keeps it visible). Same fix
// InfoTooltip.vue applied, same reason: Tab-driven focus never fires a
// click, so keyboard users are untouched.
function releaseClickFocus(): void {
  if (document.activeElement instanceof HTMLElement && document.activeElement !== document.body) {
    document.activeElement.blur();
  }
}

onMounted(() => {
  const el = trigger.value;
  if (!el) return;
  el.addEventListener('mouseenter', onMouseEnter);
  el.addEventListener('mouseleave', onMouseLeave);
  el.addEventListener('focusin', onFocusIn);
  el.addEventListener('focusout', onFocusOut);
  el.addEventListener('click', releaseClickFocus);
});

onBeforeUnmount(() => {
  const el = trigger.value;
  if (!el) return;
  el.removeEventListener('mouseenter', onMouseEnter);
  el.removeEventListener('mouseleave', onMouseLeave);
  el.removeEventListener('focusin', onFocusIn);
  el.removeEventListener('focusout', onFocusOut);
  el.removeEventListener('click', releaseClickFocus);
});
</script>

<template>
  <span ref="trigger" class="popover-tooltip-trigger">
    <slot />
  </span>
  <div
    :id="`${tooltipId}-bubble`"
    ref="bubble"
    class="popover-tooltip-bubble"
    popover="hint"
    aria-hidden="true"
  >
    <slot name="tooltip" />
  </div>
  <!-- Always in the DOM (not display:none, which a closed [popover] is) so
       aria-describedby reaches it for assistive tech regardless of
       hover/focus state -- see the module docstring for why this can't be
       the same element as the popover bubble above, unlike InfoTooltip.vue's
       single always-present span. -->
  <span :id="tooltipId" class="sr-only" role="tooltip"><slot name="tooltip" /></span>
</template>

<style scoped>
.popover-tooltip-trigger {
  display: inline-flex;
}

.popover-tooltip-bubble {
  position: fixed;
  margin: 0;
  width: max-content;
  max-width: 16rem;
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
  pointer-events: none;
}
</style>
