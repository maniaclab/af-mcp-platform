import { mount } from '@vue/test-utils';
import { KeyRound } from '@lucide/vue';
import { describe, expect, it } from 'vitest';
import IdentityCardShell from '../IdentityCardShell.vue';

const baseProps = {
  displayName: 'Grid certificate',
  enables: 'HTCondor jobs and grid data access',
  statusTone: 'ok' as const,
  statusLabel: 'Linked',
};

describe('IdentityCardShell', () => {
  it('names the section by its heading and states what the identity enables', () => {
    const w = mount(IdentityCardShell, { props: baseProps });
    const heading = w.find('h3');
    expect(heading.text()).toBe('Grid certificate');
    expect(w.find('section').attributes('aria-labelledby')).toBe(heading.attributes('id'));
    expect(w.text()).toContain('HTCondor jobs and grid data access');
  });

  it('shows the status as a mark plus a word, with the status class forwarded', () => {
    const w = mount(IdentityCardShell, {
      props: { ...baseProps, statusTone: 'warn', statusLabel: 'Access required', statusClass: 'x' },
    });
    const status = w.find('.af-st');
    expect(status.classes()).toContain('x');
    expect(status.find('.af-mark').classes()).toContain('warn');
    expect(status.text()).toBe('Access required');
  });

  it('lists what the credential powers as neutral tags, and omits the row when empty', () => {
    const withPowers = mount(IdentityCardShell, {
      props: { ...baseProps, powers: ['Rucio', 'PanDA'] },
    });
    expect(withPowers.text()).toContain('Powers');
    expect(withPowers.findAll('.af-tag').map((t) => t.text())).toEqual(['Rucio', 'PanDA']);

    const none = mount(IdentityCardShell, { props: { ...baseProps, powers: [] } });
    expect(none.text()).not.toContain('Powers');
    expect(none.find('.af-tag').exists()).toBe(false);
  });

  it('renders an optional icon hidden from assistive tech', () => {
    const w = mount(IdentityCardShell, { props: { ...baseProps, icon: KeyRound } });
    expect(
      w.find('h3').element.parentElement?.querySelector('svg')?.getAttribute('aria-hidden'),
    ).toBe('true');
  });

  it('renders the status-extra, default, actions and form slots', () => {
    const w = mount(IdentityCardShell, {
      props: baseProps,
      slots: {
        'status-extra': '<span id="extra">Keytab linked</span>',
        default: '<p id="body">details</p>',
        actions: '<button id="act">Go</button>',
        form: '<form id="frm"></form>',
      },
    });
    expect(w.find('#extra').exists()).toBe(true);
    expect(w.find('#body').exists()).toBe(true);
    expect(w.find('.ids__actions #act').exists()).toBe(true);
    expect(w.find('.ids__form #frm').exists()).toBe(true);
  });

  it('renders no form region without a form slot, and passes the caller class to the root', () => {
    const w = mount(IdentityCardShell, { props: baseProps, attrs: { class: 'xc' } });
    expect(w.find('.ids__form').exists()).toBe(false);
    expect(w.classes()).toContain('xc');
    expect(w.classes()).toContain('ids');
  });
});
