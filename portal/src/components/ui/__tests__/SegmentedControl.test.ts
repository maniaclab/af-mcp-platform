import { mount } from '@vue/test-utils';
import { describe, expect, it } from 'vitest';
import SegmentedControl from '../SegmentedControl.vue';

const options = [
  { value: '7', label: '7d' },
  { value: '30', label: '30d' },
  { value: '90', label: '90d' },
];

describe('SegmentedControl', () => {
  it('renders a labelled group of buttons with the label as text', () => {
    const w = mount(SegmentedControl, {
      props: { modelValue: '30', options, ariaLabel: 'Trailing window' },
    });
    expect(w.classes()).toContain('af-seg');
    expect(w.attributes('role')).toBe('group');
    expect(w.attributes('aria-label')).toBe('Trailing window');
    expect(w.findAll('button').map((b) => b.text())).toEqual(['7d', '30d', '90d']);
    expect(w.findAll('button').every((b) => b.attributes('type') === 'button')).toBe(true);
  });

  it('marks only the selected option as pressed', () => {
    const w = mount(SegmentedControl, { props: { modelValue: '30', options, ariaLabel: 'w' } });
    expect(w.findAll('button').map((b) => b.attributes('aria-pressed'))).toEqual([
      'false',
      'true',
      'false',
    ]);
  });

  it('emits update:modelValue with the clicked option value', async () => {
    const w = mount(SegmentedControl, { props: { modelValue: '30', options, ariaLabel: 'w' } });
    await w.findAll('button')[2].trigger('click');
    expect(w.emitted('update:modelValue')).toEqual([['90']]);
  });

  it('does not re-emit for the already selected option', async () => {
    const w = mount(SegmentedControl, { props: { modelValue: '30', options, ariaLabel: 'w' } });
    await w.findAll('button')[1].trigger('click');
    expect(w.emitted('update:modelValue')).toBeUndefined();
  });
});
