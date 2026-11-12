import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { applyAccent, resolveAccent } from '../accent';
import type { BrandingConfig } from '../branding';
import {
  ACCENT_CHOICES,
  LOCAL_ACCENT_PROPERTIES,
  applyLocalAccent,
  watchLocalAccent,
} from '../designAccent';
import { applyResolvedTheme } from '../theme';

const [ACCENT, ON_ACCENT] = LOCAL_ACCENT_PROPERTIES;
const MAROON = '#800000';
const CONFIGURED: BrandingConfig = {
  shortName: '',
  fullName: '',
  facilityName: '',
  accentColor: '#0033a0',
};

let root: HTMLElement;
let scope: HTMLElement;

beforeEach(() => {
  root = document.createElement('html');
  scope = document.createElement('div');
  root.appendChild(scope);
});

afterEach(() => {
  root.remove();
});

describe('applyLocalAccent', () => {
  it('writes the derived accent and on-accent text on the scope only', () => {
    const resolved = applyLocalAccent(scope, MAROON, root);
    expect(resolved).toEqual({ accent: MAROON, onAccent: '#ffffff' });
    expect(scope.style.getPropertyValue(ACCENT)).toBe(MAROON);
    expect(scope.style.getPropertyValue(ON_ACCENT)).toBe('#ffffff');
    expect(root.style.getPropertyValue(ACCENT)).toBe('');
  });

  it('derives the dark-theme accent with the portal derivation', () => {
    applyResolvedTheme(root, 'dark');
    applyLocalAccent(scope, MAROON, root);
    const expected = resolveAccent({ ...CONFIGURED, accentColor: MAROON }, true);
    expect(expected?.accent).not.toBe(MAROON);
    expect(scope.style.getPropertyValue(ACCENT)).toBe(expected?.accent);
    expect(scope.style.getPropertyValue(ON_ACCENT)).toBe(expected?.onAccent);
  });

  it('picks dark on-accent text for a pale accent (yellow)', () => {
    const yellow = ACCENT_CHOICES.find((c) => c.label === 'Yellow');
    expect(applyLocalAccent(scope, yellow!.hex, root)?.onAccent).toBe('#0a0a0a');
  });

  it('overrides a configured accent without touching it', () => {
    applyAccent(CONFIGURED, root);
    applyLocalAccent(scope, MAROON, root);
    expect(scope.style.getPropertyValue(ACCENT)).toBe(MAROON);
    expect(root.style.getPropertyValue(ACCENT)).toBe('#0033a0');
  });

  it('restores the configured accent when the choice is the default (null)', () => {
    applyAccent(CONFIGURED, root);
    applyLocalAccent(scope, MAROON, root);
    expect(applyLocalAccent(scope, null, root)).toBeNull();
    expect(scope.style.getPropertyValue(ACCENT)).toBe('');
    expect(scope.style.getPropertyValue(ON_ACCENT)).toBe('');
    // The configured value on the root is what the scope now inherits.
    expect(root.style.getPropertyValue(ACCENT)).toBe('#0033a0');
  });
});

describe('watchLocalAccent', () => {
  it('re-derives the choice when the theme changes, and stops after cleanup', () => {
    let choice: string | null = MAROON;
    const stop = watchLocalAccent(scope, () => choice, root);
    expect(scope.style.getPropertyValue(ACCENT)).toBe(MAROON);

    applyResolvedTheme(root, 'dark');
    const dark = resolveAccent({ ...CONFIGURED, accentColor: MAROON }, true);
    expect(scope.style.getPropertyValue(ACCENT)).toBe(dark?.accent);

    applyResolvedTheme(root, 'light');
    expect(scope.style.getPropertyValue(ACCENT)).toBe(MAROON);

    stop();
    choice = '#0f7b3f';
    applyResolvedTheme(root, 'dark');
    expect(scope.style.getPropertyValue(ACCENT)).toBe(MAROON);
  });

  it('leaves the scope untouched on a theme change while the default is chosen', () => {
    const stop = watchLocalAccent(scope, () => null, root);
    applyResolvedTheme(root, 'dark');
    expect(scope.style.getPropertyValue(ACCENT)).toBe('');
    stop();
  });
});
