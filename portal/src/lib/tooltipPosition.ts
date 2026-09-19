/**
 * tooltipPosition.ts — the pure placement math for PopoverTooltip.vue.
 *
 * The bubble is `position: fixed` (viewport-relative) rather than anchored
 * via CSS anchor positioning (`anchor-name`/`position-anchor`) -- anchor
 * positioning's cross-browser support isn't yet something to build a core
 * accessibility affordance on, whereas the Popover API itself (which is
 * what actually solves overflow clipping, by promoting the bubble to the
 * top layer) is broadly supported. `position: fixed` + a `getBoundingClientRect()`
 * read at show-time is the well-established fallback-free way to place it.
 */

export interface Rect {
  top: number;
  left: number;
  right: number;
  bottom: number;
  width: number;
  height: number;
}

export interface Size {
  width: number;
  height: number;
}

export type TooltipSide = 'top' | 'bottom';

export interface TooltipPosition {
  top: number;
  left: number;
}

/** Gap between trigger and bubble, matching the retired InfoTooltip.vue's 0.375rem margin (at a 16px root font size). */
const GAP_PX = 6;
/** Minimum distance kept from the viewport edge. */
const VIEWPORT_MARGIN_PX = 8;

/**
 * Places the bubble centered under (or over) the trigger, clamped so it
 * never runs past the viewport's horizontal edges, and flips to the
 * opposite side if there's no room on the requested one -- both distinct
 * from the old InfoTooltip.vue, which never adjusted for viewport bounds at
 * all (see EntitlementsPage.vue/TokensPage.vue's own siting comments for
 * the manual per-row `placement` workarounds that necessitated).
 */
export function computeTooltipPosition(
  trigger: Rect,
  bubble: Size,
  side: TooltipSide,
  viewport: Size,
): TooltipPosition {
  let left = trigger.left + trigger.width / 2 - bubble.width / 2;
  left = Math.max(
    VIEWPORT_MARGIN_PX,
    Math.min(left, viewport.width - bubble.width - VIEWPORT_MARGIN_PX),
  );

  const fitsAbove = trigger.top - bubble.height - GAP_PX >= VIEWPORT_MARGIN_PX;
  const fitsBelow = trigger.bottom + GAP_PX + bubble.height <= viewport.height - VIEWPORT_MARGIN_PX;

  let placeAbove = side === 'top';
  if (side === 'top' && !fitsAbove && fitsBelow) placeAbove = false;
  if (side === 'bottom' && !fitsBelow && fitsAbove) placeAbove = true;

  const top = placeAbove ? trigger.top - bubble.height - GAP_PX : trigger.bottom + GAP_PX;
  return { top, left };
}
