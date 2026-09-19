import { describe, expect, it } from 'vitest';
import { computeTooltipPosition, type Rect } from '../tooltipPosition';

const VIEWPORT = { width: 1024, height: 768 };
const BUBBLE = { width: 160, height: 40 };

function rect(overrides: Partial<Rect>): Rect {
  return { top: 300, left: 300, right: 340, bottom: 320, width: 40, height: 20, ...overrides };
}

describe('computeTooltipPosition', () => {
  it('centers the bubble horizontally under the trigger for side "bottom"', () => {
    const trigger = rect({ left: 480, width: 40 }); // center at 500
    const pos = computeTooltipPosition(trigger, BUBBLE, 'bottom', VIEWPORT);
    expect(pos.left).toBe(500 - BUBBLE.width / 2);
    expect(pos.top).toBe(trigger.bottom + 6);
  });

  it('places the bubble above the trigger for side "top"', () => {
    const trigger = rect({ top: 300, bottom: 320 });
    const pos = computeTooltipPosition(trigger, BUBBLE, 'top', VIEWPORT);
    expect(pos.top).toBe(trigger.top - BUBBLE.height - 6);
  });

  it('clamps the left edge so the bubble never runs past the viewport left', () => {
    const trigger = rect({ left: 2, width: 10 }); // center near x=7, bubble would go negative
    const pos = computeTooltipPosition(trigger, BUBBLE, 'bottom', VIEWPORT);
    expect(pos.left).toBe(8); // VIEWPORT_MARGIN_PX
  });

  it('clamps the right edge so the bubble never runs past the viewport right', () => {
    const trigger = rect({ left: VIEWPORT.width - 10, width: 10 });
    const pos = computeTooltipPosition(trigger, BUBBLE, 'bottom', VIEWPORT);
    expect(pos.left).toBe(VIEWPORT.width - BUBBLE.width - 8);
  });

  it('flips from top to bottom when there is no room above (the EntitlementsPage last-row case)', () => {
    const trigger = rect({ top: 20, bottom: 40 }); // not enough room above for a 40px bubble + gap
    const pos = computeTooltipPosition(trigger, BUBBLE, 'top', VIEWPORT);
    expect(pos.top).toBe(trigger.bottom + 6);
  });

  it("flips from bottom to top when there is no room below (a table's last row)", () => {
    const trigger = rect({ top: VIEWPORT.height - 30, bottom: VIEWPORT.height - 10 });
    const pos = computeTooltipPosition(trigger, BUBBLE, 'bottom', VIEWPORT);
    expect(pos.top).toBe(trigger.top - BUBBLE.height - 6);
  });

  it('does not flip when neither side has room -- picks the requested side rather than guessing', () => {
    const tinyViewport = { width: 1024, height: 50 };
    const trigger = rect({ top: 10, bottom: 30 });
    const pos = computeTooltipPosition(trigger, BUBBLE, 'top', tinyViewport);
    expect(pos.top).toBe(trigger.top - BUBBLE.height - 6);
  });
});
