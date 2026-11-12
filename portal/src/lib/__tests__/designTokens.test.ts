import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { DESIGN_ACCENT_EVENT, readTokenValues, subscribeToTokenChanges } from '../designTokens';
import { THEME_CHANGE_EVENT } from '../theme';

describe('readTokenValues', () => {
  it('returns each token trimmed, as the computed style reports it', () => {
    const style = {
      getPropertyValue: (name: string) =>
        ({ '--space-8': ' 8px ', '--text-14': '0.875rem' })[name] ?? '',
    };
    expect(readTokenValues(['--space-8', '--text-14'], style)).toEqual({
      '--space-8': '8px',
      '--text-14': '0.875rem',
    });
  });

  it('reports a token that is not defined as an empty string, not a stale value', () => {
    const style = { getPropertyValue: () => '' };
    expect(readTokenValues(['--nope'], style)).toEqual({ '--nope': '' });
  });

  it('reads custom properties set on a real element', () => {
    const el = document.createElement('div');
    el.style.setProperty('--color-af-accent', '#800000');
    document.body.appendChild(el);
    const values = readTokenValues(['--color-af-accent'], getComputedStyle(el));
    expect(values['--color-af-accent']).toBe('#800000');
    el.remove();
  });
});

describe('subscribeToTokenChanges', () => {
  let root: HTMLElement;
  beforeEach(() => {
    root = document.createElement('html');
    document.body.appendChild(root);
  });
  afterEach(() => root.remove());

  it.each([[THEME_CHANGE_EVENT], [DESIGN_ACCENT_EVENT]])('calls back on %s', async (name) => {
    const cb = vi.fn();
    const stop = subscribeToTokenChanges(cb, root);
    root.dispatchEvent(new Event(name));
    await Promise.resolve();
    expect(cb).toHaveBeenCalledTimes(1);
    stop();
  });

  it('calls back when a configured accent is written onto the root later', async () => {
    const cb = vi.fn();
    const stop = subscribeToTokenChanges(cb, root);
    root.style.setProperty('--color-af-accent', '#800000');
    await new Promise((r) => setTimeout(r, 0));
    expect(cb).toHaveBeenCalled();
    stop();
  });

  it('coalesces a burst into one call and stops after cleanup', async () => {
    const cb = vi.fn();
    const stop = subscribeToTokenChanges(cb, root);
    root.dispatchEvent(new Event(THEME_CHANGE_EVENT));
    root.dispatchEvent(new Event(THEME_CHANGE_EVENT));
    await new Promise((r) => setTimeout(r, 0));
    expect(cb).toHaveBeenCalledTimes(1);
    stop();
    root.dispatchEvent(new Event(THEME_CHANGE_EVENT));
    await new Promise((r) => setTimeout(r, 0));
    expect(cb).toHaveBeenCalledTimes(1);
  });
});
