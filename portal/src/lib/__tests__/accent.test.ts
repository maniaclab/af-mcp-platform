import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { applyAccent, resolveAccent, watchAccent } from '../accent';
import type { BrandingConfig } from '../branding';
import { contrastRatio } from '../colorContrast';
import { applyResolvedTheme } from '../theme';

const DARK_BG = '#0f0f10';

function config(overrides: Partial<BrandingConfig>): BrandingConfig {
  return { shortName: '', fullName: '', facilityName: '', ...overrides };
}

let warn: ReturnType<typeof vi.spyOn>;

beforeEach(() => {
  warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
});

afterEach(() => {
  warn.mockRestore();
});

describe('resolveAccent', () => {
  it.each([
    [{}, false],
    [{}, true],
    [{ accentColor: '' }, false],
    [{ accentColorDark: '' }, true],
  ])('returns null when no accent is configured (%j, dark=%s)', (overrides, dark) => {
    expect(resolveAccent(config(overrides), dark)).toBeNull();
    expect(warn).not.toHaveBeenCalled();
  });

  it('uses a dark accentColor as-is in light with a white on-accent', () => {
    expect(resolveAccent(config({ accentColor: '#800000' }), false)).toEqual({
      accent: '#800000',
      onAccent: '#ffffff',
    });
  });

  it('picks a near-black on-accent for a pale accentColor', () => {
    expect(resolveAccent(config({ accentColor: '#ffd200' }), false)).toEqual({
      accent: '#ffd200',
      onAccent: '#0a0a0a',
    });
  });

  it('lightens accentColor in dark until it reaches 3:1 against the dark background', () => {
    const result = resolveAccent(config({ accentColor: '#800000' }), true);
    expect(result).not.toBeNull();
    expect(result!.accent).not.toBe('#800000');
    expect(contrastRatio(result!.accent, DARK_BG)).toBeGreaterThanOrEqual(3);
    const onAccentRatio = contrastRatio(result!.accent, result!.onAccent);
    expect(onAccentRatio).toBeGreaterThanOrEqual(4.5);
  });

  it('leaves an accentColor that already reaches 3:1 untouched in dark', () => {
    expect(resolveAccent(config({ accentColor: '#ffd200' }), true)?.accent).toBe('#ffd200');
  });

  it('uses accentColorDark verbatim in dark', () => {
    expect(
      resolveAccent(config({ accentColor: '#800000', accentColorDark: '#ff8080' }), true),
    ).toEqual({ accent: '#ff8080', onAccent: '#0a0a0a' });
  });

  it('ignores accentColorDark in light', () => {
    expect(
      resolveAccent(config({ accentColor: '#800000', accentColorDark: '#ff8080' }), false)?.accent,
    ).toBe('#800000');
  });

  it('derives the dark accent from nothing when only accentColorDark is set', () => {
    expect(resolveAccent(config({ accentColorDark: '#ff8080' }), false)).toBeNull();
    expect(resolveAccent(config({ accentColorDark: '#ff8080' }), true)?.accent).toBe('#ff8080');
  });

  it.each([
    ['accentColor', 'red'],
    ['accentColor', '#12'],
    ['accentColor', '#zzzzzz'],
    ['accentColor', '800000'],
    ['accentColorDark', 'red'],
    ['accentColorDark', '#12'],
    ['accentColorDark', '#zzzzzz'],
    ['accentColorDark', '800000'],
  ] as const)('ignores an invalid %s (%s) and warns once naming the field', (field, value) => {
    expect(resolveAccent(config({ [field]: value }), true)).toBeNull();
    expect(warn).toHaveBeenCalledTimes(1);
    expect(warn.mock.calls[0][0]).toContain(field);
  });
});

describe('applyAccent', () => {
  it('sets both custom properties inline on the root', () => {
    const root = document.createElement('html');
    applyAccent(config({ accentColor: '#800000' }), root);
    expect(root.style.getPropertyValue('--color-af-accent')).toBe('#800000');
    expect(root.style.getPropertyValue('--color-af-on-accent')).toBe('#ffffff');
  });

  it('reads the dark theme from the root .dark class', () => {
    const root = document.createElement('html');
    root.classList.add('dark');
    applyAccent(config({ accentColor: '#800000', accentColorDark: '#ff8080' }), root);
    expect(root.style.getPropertyValue('--color-af-accent')).toBe('#ff8080');
  });

  it('removes previously set properties when nothing is configured', () => {
    const root = document.createElement('html');
    applyAccent(config({ accentColor: '#800000' }), root);
    applyAccent(config({}), root);
    expect(root.style.getPropertyValue('--color-af-accent')).toBe('');
    expect(root.style.getPropertyValue('--color-af-on-accent')).toBe('');
  });

  it('writes nothing for invalid values and warns once', () => {
    const root = document.createElement('html');
    applyAccent(config({ accentColor: 'red' }), root);
    expect(root.style.getPropertyValue('--color-af-accent')).toBe('');
    expect(root.style.getPropertyValue('--color-af-on-accent')).toBe('');
    expect(warn).toHaveBeenCalledTimes(1);
  });
});

describe('watchAccent', () => {
  it('re-applies when the theme changes', () => {
    const root = document.createElement('html');
    watchAccent(config({ accentColor: '#800000', accentColorDark: '#ff8080' }), root);
    expect(root.style.getPropertyValue('--color-af-accent')).toBe('#800000');

    applyResolvedTheme(root, 'dark');
    expect(root.style.getPropertyValue('--color-af-accent')).toBe('#ff8080');

    applyResolvedTheme(root, 'light');
    expect(root.style.getPropertyValue('--color-af-accent')).toBe('#800000');
  });
});
