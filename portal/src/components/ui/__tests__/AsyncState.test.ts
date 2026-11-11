/**
 * Component tests for AsyncState.vue: the loading / session-expired /
 * access-denied / error / empty / content ladder the data pages share.
 */
import { mount } from '@vue/test-utils';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { AccessDeniedError } from '../../../lib/api';
import AsyncState from '../AsyncState.vue';

const base = {
  loading: false,
  error: null,
  errorTitle: 'Services unavailable',
  sessionExpired: false,
  accessDenied: null,
};

function render(props: Record<string, unknown> = {}) {
  return mount(AsyncState, {
    props: { ...base, ...props },
    slots: { default: '<p class="content">the content</p>', empty: '<p class="none">nothing</p>' },
  });
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('AsyncState', () => {
  it('renders the default slot when nothing is wrong', () => {
    const w = render();
    expect(w.find('.content').exists()).toBe(true);
    expect(w.find('[role="alert"]').exists()).toBe(false);
    expect(w.find('.empty').exists()).toBe(false);
  });

  it('shows only the loading row, with the default label, while loading', () => {
    const w = render({ loading: true });
    expect(w.text()).toContain('Loading…');
    expect(w.find('[role="status"]').exists()).toBe(true);
    expect(w.find('.content').exists()).toBe(false);
  });

  it('uses a custom loading label', () => {
    expect(render({ loading: true, loadingLabel: 'Loading usage…' }).text()).toContain(
      'Loading usage…',
    );
  });

  it('shows the session-expired banner with a Reload button that reloads the page', async () => {
    const reload = vi.fn();
    vi.stubGlobal('location', { reload });
    const w = render({ sessionExpired: true });

    const banner = w.find('.af-banner.bad');
    expect(banner.attributes('role')).toBe('alert');
    expect(banner.text()).toContain('Session expired');
    expect(banner.find('.af-mark').attributes('aria-hidden')).toBe('true');
    expect(w.find('.content').exists()).toBe(false);

    const btn = banner.find('button');
    expect(btn.text()).toBe('Reload');
    await btn.trigger('click');
    expect(reload).toHaveBeenCalledTimes(1);
  });

  it('shows access denied as a warning banner carrying the error message', () => {
    const w = render({ accessDenied: new AccessDeniedError('Ask an admin for access.', 'cid') });
    const banner = w.find('.af-banner.warn');
    expect(banner.attributes('role')).toBe('alert');
    expect(banner.text()).toContain('Access not yet granted');
    expect(banner.text()).toContain('Ask an admin for access.');
    expect(banner.find('button').exists()).toBe(false);
  });

  it('shows an error with the given title and message', () => {
    const w = render({ error: 'boom' });
    const banner = w.find('.af-banner.bad');
    expect(banner.attributes('role')).toBe('alert');
    expect(banner.find('b').text()).toBe('Services unavailable');
    expect(banner.text()).toContain('boom');
    expect(banner.find('button').exists()).toBe(false);
  });

  it('shows the empty slot inside .empty only when empty', () => {
    const w = render({ empty: true });
    expect(w.find('.empty .none').exists()).toBe(true);
    expect(w.find('.content').exists()).toBe(false);
  });

  it.each([
    ['loading', { loading: true, sessionExpired: true }, '[role="status"]'],
    ['session expired', { sessionExpired: true, error: 'x' }, '.af-banner.bad button'],
    [
      'access denied',
      { accessDenied: new AccessDeniedError('m', null), error: 'x' },
      '.af-banner.warn',
    ],
  ])('%s takes precedence over lower states', (_name, props, selector) => {
    const w = render({ ...props, empty: true });
    expect(w.find(selector).exists()).toBe(true);
    expect(w.find('.empty').exists()).toBe(false);
    expect(w.find('.content').exists()).toBe(false);
  });

  it('error takes precedence over empty', () => {
    const w = render({ error: 'x', empty: true });
    expect(w.find('.af-banner.bad').exists()).toBe(true);
    expect(w.find('.empty').exists()).toBe(false);
  });

  it('renders the error-hint slot inside the error banner only', () => {
    const slots = {
      default: '<p class="content">c</p>',
      'error-hint': '<span class="hint">h</span>',
    };
    const failed = mount(AsyncState, { props: { ...base, error: 'boom' }, slots });
    expect(failed.find('.af-banner.bad .hint').exists()).toBe(true);
    const fine = mount(AsyncState, { props: base, slots });
    expect(fine.find('.hint').exists()).toBe(false);
  });

  describe('inline', () => {
    it('renders the error as a note, not a banner', () => {
      const w = render({ inline: true, error: 'boom' });
      const note = w.find('.af-note.bad');
      expect(note.attributes('role')).toBe('alert');
      expect(note.find('b').text()).toBe('Services unavailable');
      expect(note.text()).toContain('boom');
      expect(w.find('.af-banner').exists()).toBe(false);
    });

    it('renders session expired as a note with a Reload button', async () => {
      const reload = vi.fn();
      vi.stubGlobal('location', { reload });
      const w = render({ inline: true, sessionExpired: true });
      const note = w.find('.af-note.bad');
      expect(note.attributes('role')).toBe('alert');
      expect(note.text()).toContain('Session expired');
      await note.find('button').trigger('click');
      expect(reload).toHaveBeenCalledTimes(1);
      expect(w.find('.af-banner').exists()).toBe(false);
    });

    it('renders access denied as a warning note carrying the message', () => {
      const w = render({ inline: true, accessDenied: new AccessDeniedError('Ask an admin.', 'c') });
      const note = w.find('.af-note.warn');
      expect(note.attributes('role')).toBe('alert');
      expect(note.text()).toContain('Access not yet granted');
      expect(note.text()).toContain('Ask an admin.');
      expect(w.find('.af-banner').exists()).toBe(false);
    });

    it('still renders the content when nothing is wrong', () => {
      expect(render({ inline: true }).find('.content').exists()).toBe(true);
    });
  });
});
