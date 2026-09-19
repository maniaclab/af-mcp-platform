/**
 * Component tests for PopoverTooltip.vue.
 *
 * jsdom (this suite's DOM environment) doesn't implement the Popover API at
 * all -- `showPopover`/`hidePopover` are undefined on HTMLElement, matching
 * how an older/unsupporting real browser would look to this component's own
 * feature-detection. Stubbing them here exercises the same code path a
 * supporting browser takes, while a separate "no Popover API" test confirms
 * the graceful-degradation path (no crash, sr-only text still present).
 */
import { mount } from '@vue/test-utils';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import PopoverTooltip from '../PopoverTooltip.vue';

function stubPopoverApi() {
  HTMLElement.prototype.showPopover = vi.fn();
  HTMLElement.prototype.hidePopover = vi.fn();
}

function unstubPopoverApi() {
  // @ts-expect-error -- deleting a test-only stub, not a real DOM property
  delete HTMLElement.prototype.showPopover;
  // @ts-expect-error -- same
  delete HTMLElement.prototype.hidePopover;
}

describe('PopoverTooltip', () => {
  afterEach(() => {
    unstubPopoverApi();
  });

  it('renders the trigger slot and the tooltip text in an sr-only description', () => {
    const wrapper = mount(PopoverTooltip, {
      props: { tooltipId: 'tt-1' },
      slots: { default: '<button>read</button>', tooltip: 'Read-only — no side effects.' },
    });

    expect(wrapper.find('button').text()).toBe('read');
    const desc = wrapper.find('#tt-1');
    expect(desc.exists()).toBe(true);
    expect(desc.classes()).toContain('sr-only');
    expect(desc.text()).toBe('Read-only — no side effects.');
    expect(desc.attributes('role')).toBe('tooltip');
  });

  it('the visible bubble is aria-hidden and carries the same text', () => {
    const wrapper = mount(PopoverTooltip, {
      props: { tooltipId: 'tt-2' },
      slots: { default: '<button>read</button>', tooltip: 'Read-only.' },
    });

    const bubble = wrapper.find('#tt-2-bubble');
    expect(bubble.attributes('aria-hidden')).toBe('true');
    expect(bubble.attributes('popover')).toBe('hint');
    expect(bubble.text()).toBe('Read-only.');
  });

  describe('with the Popover API available', () => {
    beforeEach(stubPopoverApi);

    it('shows the bubble on mouseenter and hides it on mouseleave', async () => {
      const wrapper = mount(PopoverTooltip, {
        props: { tooltipId: 'tt-3' },
        slots: { default: '<button>read</button>', tooltip: 'Read-only.' },
      });
      const bubbleEl = wrapper.find('#tt-3-bubble').element as HTMLElement;

      await wrapper.find('.popover-tooltip-trigger').trigger('mouseenter');
      expect(bubbleEl.showPopover).toHaveBeenCalledTimes(1);

      await wrapper.find('.popover-tooltip-trigger').trigger('mouseleave');
      expect(bubbleEl.hidePopover).toHaveBeenCalledTimes(1);
    });

    it('stays open while EITHER hover or focus holds, closing only when both end', async () => {
      const wrapper = mount(PopoverTooltip, {
        props: { tooltipId: 'tt-4' },
        slots: { default: '<button>read</button>', tooltip: 'Read-only.' },
      });
      const trigger = wrapper.find('.popover-tooltip-trigger');
      const bubbleEl = wrapper.find('#tt-4-bubble').element as HTMLElement;

      await trigger.trigger('mouseenter');
      await trigger.trigger('focusin');
      expect(bubbleEl.showPopover).toHaveBeenCalledTimes(2); // once per event, still open

      await trigger.trigger('mouseleave'); // still focused -- must stay open
      expect(bubbleEl.hidePopover).not.toHaveBeenCalled();

      await trigger.trigger('focusout'); // now neither -- must close
      expect(bubbleEl.hidePopover).toHaveBeenCalledTimes(1);
    });

    it('releases focus on click so the tooltip does not stay stuck open once the mouse leaves', async () => {
      // Focus only actually moves document.activeElement for an element
      // attached to the document -- vue-test-utils mounts detached by
      // default.
      const wrapper = mount(PopoverTooltip, {
        props: { tooltipId: 'tt-5' },
        slots: { default: '<button>read</button>', tooltip: 'Read-only.' },
        attachTo: document.body,
      });
      const button = wrapper.find('button').element;
      button.focus();
      expect(document.activeElement).toBe(button);

      await wrapper.find('.popover-tooltip-trigger').trigger('click');

      expect(document.activeElement).not.toBe(button);
      wrapper.unmount();
    });
  });

  describe('without the Popover API (older/unsupporting browser)', () => {
    it('does not throw on hover, and the sr-only description is still present', async () => {
      const wrapper = mount(PopoverTooltip, {
        props: { tooltipId: 'tt-6' },
        slots: { default: '<button>read</button>', tooltip: 'Read-only.' },
      });

      await expect(
        wrapper.find('.popover-tooltip-trigger').trigger('mouseenter'),
      ).resolves.not.toThrow();
      expect(wrapper.find('#tt-6').text()).toBe('Read-only.');
    });
  });
});
