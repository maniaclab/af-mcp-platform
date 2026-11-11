/**
 * Component tests for Disclosure.vue, including its pairing with
 * useFetchOnExpand.
 */
import { flushPromises, mount } from '@vue/test-utils';
import { describe, expect, it, vi } from 'vitest';
import { defineComponent, h } from 'vue';
import { useFetchOnExpand } from '../../../lib/useFetchOnExpand';
import Disclosure from '../Disclosure.vue';

describe('Disclosure', () => {
  it('renders a collapsed toggle button wired to its region', () => {
    const w = mount(Disclosure, { props: { label: 'Methods' } });
    const btn = w.find('button');
    expect(btn.text()).toBe('Methods');
    expect(btn.attributes('type')).toBe('button');
    expect(btn.attributes('aria-expanded')).toBe('false');
    expect(w.find('[role="region"]').exists()).toBe(false);
  });

  it('shows the region, labelled by the button, when open', () => {
    const w = mount(Disclosure, {
      props: { label: 'Methods', open: true },
      slots: { default: '<p class="body">inside</p>' },
    });
    const btn = w.find('button');
    const region = w.find('[role="region"]');
    expect(btn.attributes('aria-expanded')).toBe('true');
    expect(btn.attributes('aria-controls')).toBe(region.attributes('id'));
    expect(region.attributes('aria-labelledby')).toBe(btn.attributes('id'));
    expect(region.find('.body').exists()).toBe(true);
  });

  it('can name the region explicitly', () => {
    const w = mount(Disclosure, {
      props: { label: 'Methods', open: true, regionLabel: 'Methods for rucio' },
    });
    expect(w.find('[role="region"]').attributes('aria-label')).toBe('Methods for rucio');
    expect(w.find('[role="region"]').attributes('aria-labelledby')).toBeUndefined();
  });

  it('toggles uncontrolled and emits update:open and toggle', async () => {
    const w = mount(Disclosure, { props: { label: 'Methods' } });
    await w.find('button').trigger('click');
    expect(w.find('button').attributes('aria-expanded')).toBe('true');
    expect(w.emitted('toggle')).toEqual([[true]]);
    expect(w.emitted('update:open')).toEqual([[true]]);

    await w.find('button').trigger('click');
    expect(w.find('button').attributes('aria-expanded')).toBe('false');
    expect(w.emitted('toggle')?.[1]).toEqual([false]);
  });

  it('has a chevron that is aria-hidden and flagged open for rotation', async () => {
    const w = mount(Disclosure, { props: { label: 'Methods' } });
    const icon = () => w.find('button svg');
    expect(icon().attributes('aria-hidden')).toBe('true');
    expect(icon().classes()).not.toContain('disclosure__chevron--open');
    await w.setProps({ open: true } as never);
    expect(icon().classes()).toContain('disclosure__chevron--open');
  });

  it('renders the label and badge slots', () => {
    const w = mount(Disclosure, {
      slots: { label: 'Grid certificates', badge: '<span class="badge">Mounted</span>' },
    });
    expect(w.find('button').text()).toContain('Grid certificates');
    expect(w.find('button .badge').exists()).toBe(true);
  });

  it('drives useFetchOnExpand without double-toggling', async () => {
    const fetcher = vi.fn().mockResolvedValue('payload');
    const Host = defineComponent({
      setup() {
        const f = useFetchOnExpand<string>(fetcher);
        return () =>
          h(Disclosure, { label: 'Details', open: f.open.value, onToggle: f.toggle }, () =>
            f.loading.value ? 'loading' : (f.data.value ?? ''),
          );
      },
    });
    const w = mount(Host);

    await w.find('button').trigger('click');
    await flushPromises();
    expect(fetcher).toHaveBeenCalledTimes(1);
    expect(w.find('button').attributes('aria-expanded')).toBe('true');
    expect(w.find('[role="region"]').text()).toBe('payload');

    await w.find('button').trigger('click');
    expect(w.find('button').attributes('aria-expanded')).toBe('false');
  });
});
