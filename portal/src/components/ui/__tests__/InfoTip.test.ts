/**
 * Component tests for InfoTip.vue. jsdom has no Popover API, which
 * PopoverTooltip feature-detects, so nothing needs stubbing here.
 */
import { mount } from '@vue/test-utils';
import { describe, expect, it } from 'vitest';
import InfoTip from '../InfoTip.vue';

describe('InfoTip', () => {
  it('renders an icon-only button with an accessible name described by the tooltip', () => {
    const w = mount(InfoTip, {
      props: { id: 'tip-1', text: 'Reads only.', label: 'About this service' },
    });
    const btn = w.find('button');
    expect(btn.attributes('type')).toBe('button');
    expect(btn.attributes('aria-label')).toBe('About this service');
    expect(btn.attributes('aria-describedby')).toBe('tip-1');
    expect(btn.text()).toBe('');
    expect(btn.find('svg').attributes('aria-hidden')).toBe('true');
    expect(w.find('#tip-1').text()).toBe('Reads only.');
  });

  it('defaults the accessible name', () => {
    const w = mount(InfoTip, { props: { id: 'tip-2', text: 'x' } });
    expect(w.find('button').attributes('aria-label')).toBe('More information');
  });

  it('renders slot content in place of text', () => {
    const w = mount(InfoTip, { props: { id: 'tip-3' }, slots: { default: '<b>Rich</b> tip' } });
    expect(w.find('#tip-3').text()).toBe('Rich tip');
  });

  it('passes placement through to the tooltip, defaulting to top', () => {
    // PopoverTooltip positions via its `side`; the bubble element is shared
    // either way, so assert on the prop the child received.
    const top = mount(InfoTip, { props: { id: 'a', text: 'x' } });
    expect(top.findComponent({ name: 'PopoverTooltip' }).props('side')).toBe('top');
    const bottom = mount(InfoTip, { props: { id: 'b', text: 'x', placement: 'bottom' } });
    expect(bottom.findComponent({ name: 'PopoverTooltip' }).props('side')).toBe('bottom');
  });
});
