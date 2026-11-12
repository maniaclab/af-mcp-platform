/**
 * Component tests for ArmedConfirmButton.vue: the two-step inline confirm.
 */
import { mount } from '@vue/test-utils';
import { describe, expect, it } from 'vitest';
import ArmedConfirmButton from '../ArmedConfirmButton.vue';

const props = {
  label: 'Forget this ticket',
  armedLabel: 'Confirm forget',
  busyLabel: 'Forgetting…',
};

describe('ArmedConfirmButton', () => {
  it('starts as a single danger button with the label', () => {
    const w = mount(ArmedConfirmButton, { props });
    const buttons = w.findAll('button');
    expect(buttons).toHaveLength(1);
    expect(buttons[0].text()).toBe('Forget this ticket');
    expect(buttons[0].classes()).toEqual(expect.arrayContaining(['btn', 'af-danger']));
    expect(buttons[0].attributes('data-variant')).toBe('outline');
    expect(buttons[0].attributes('data-size')).toBe('sm');
    expect(buttons[0].attributes('type')).toBe('button');
  });

  it('first click arms: shows the confirm label and a Cancel button, emits nothing', async () => {
    const w = mount(ArmedConfirmButton, { props });
    await w.find('button').trigger('click');
    const buttons = w.findAll('button');
    expect(buttons.map((b) => b.text())).toEqual(['Confirm forget', 'Cancel']);
    expect(buttons[1].classes()).toContain('btn');
    expect(buttons[1].attributes('data-variant')).toBe('ghost');
    expect(buttons[1].attributes('data-size')).toBe('sm');
    expect(w.emitted('confirm')).toBeUndefined();
  });

  it('second click emits confirm', async () => {
    const w = mount(ArmedConfirmButton, { props });
    await w.find('button').trigger('click');
    await w.find('button').trigger('click');
    expect(w.emitted('confirm')).toHaveLength(1);
  });

  it('Cancel disarms without emitting confirm', async () => {
    const w = mount(ArmedConfirmButton, { props });
    await w.find('button').trigger('click');
    await w.findAll('button')[1].trigger('click');
    expect(w.findAll('button')).toHaveLength(1);
    expect(w.find('button').text()).toBe('Forget this ticket');
    expect(w.emitted('confirm')).toBeUndefined();
  });

  it('shows busyLabel, disables the button and hides Cancel while busy', async () => {
    const w = mount(ArmedConfirmButton, { props: { ...props, armed: true, busy: true } });
    expect(w.findAll('button')).toHaveLength(1);
    expect(w.find('button').text()).toBe('Forgetting…');
    expect(w.find('button').attributes('disabled')).toBeDefined();
    expect(w.find('button').attributes('aria-busy')).toBe('true');
  });

  it('supports v-model:armed so a parent can disarm it', async () => {
    const w = mount(ArmedConfirmButton, { props: { ...props, armed: true } });
    expect(w.find('button').text()).toBe('Confirm forget');
    await w.setProps({ armed: false } as never);
    expect(w.find('button').text()).toBe('Forget this ticket');
  });

  it('reports arm and disarm through update:armed', async () => {
    const w = mount(ArmedConfirmButton, { props });
    await w.find('button').trigger('click');
    await w.findAll('button')[1].trigger('click');
    expect(w.emitted('update:armed')).toEqual([[true], [false]]);
  });

  it('applies the per-state class hooks to the matching buttons', async () => {
    const w = mount(ArmedConfirmButton, {
      props: {
        ...props,
        triggerClass: 'kc__btn--forget',
        confirmClass: 'kc__btn--forget-armed',
        cancelClass: 'kc__btn--cancel',
      },
    });
    expect(w.find('button').classes()).toContain('kc__btn--forget');
    await w.find('button').trigger('click');
    expect(w.findAll('button')[0].classes()).toContain('kc__btn--forget-armed');
    expect(w.findAll('button')[1].classes()).toContain('kc__btn--cancel');
  });
});
