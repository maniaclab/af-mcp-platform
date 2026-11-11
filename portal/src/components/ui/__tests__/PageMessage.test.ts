/**
 * Component tests for PageMessage.vue: a page's banner-slot message. A problem
 * or warning is a solid banner announced as an alert; a hint is a quiet
 * inline note announced politely.
 */
import { mount } from '@vue/test-utils';
import { describe, expect, it } from 'vitest';
import PageMessage from '../PageMessage.vue';

describe('PageMessage', () => {
  it('renders a problem as a banner and an alert', () => {
    const wrapper = mount(PageMessage, {
      props: {
        message: { kind: 'banner', tone: 'bad', title: 'Broken', body: 'Fix it.', action: null },
      },
    });
    const box = wrapper.get('.alert');
    expect(box.classes()).toEqual(expect.arrayContaining(['af-banner', 'bad']));
    expect(box.attributes('role')).toBe('alert');
    expect(box.text()).toContain('Broken');
    expect(box.text()).toContain('Fix it.');
    expect(wrapper.find('a').exists()).toBe(false);
  });

  it('renders a warning as an alert too', () => {
    const wrapper = mount(PageMessage, {
      props: {
        message: { kind: 'banner', tone: 'warn', title: 'Slow', body: 'Wait.', action: null },
      },
    });
    expect(wrapper.get('.alert').attributes('role')).toBe('alert');
  });

  it('renders a hint as an information note with a polite status role', () => {
    const wrapper = mount(PageMessage, {
      props: {
        message: {
          kind: 'hint',
          title: '2 services are not linked',
          body: 'Link an account on the Identities page to use them.',
          action: { label: 'Link an account', href: '/identities/' },
        },
      },
    });
    const box = wrapper.get('.alert');
    expect(box.classes()).toEqual(expect.arrayContaining(['af-note', 'info']));
    expect(box.classes()).not.toContain('af-banner');
    expect(box.attributes('role')).toBe('status');
    const action = box.get('a.btn');
    expect(action.attributes('href')).toBe('/identities/');
    expect(action.text()).toBe('Link an account');
  });
});
