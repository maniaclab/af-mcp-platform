import { describe, expect, it, vi } from 'vitest';
import {
  applyResolvedTheme,
  cycleMode,
  getStoredMode,
  initTheme,
  resolveTheme,
  setMode,
  systemPrefersDark,
  THEME_MODES,
  THEME_STORAGE_KEY,
} from '../theme';

describe('resolveTheme', () => {
  it('returns dark for an explicit dark mode regardless of system preference', () => {
    expect(resolveTheme('dark', false)).toBe('dark');
    expect(resolveTheme('dark', true)).toBe('dark');
  });

  it('returns light for an explicit light mode regardless of system preference', () => {
    expect(resolveTheme('light', true)).toBe('light');
    expect(resolveTheme('light', false)).toBe('light');
  });

  it('follows the system preference for auto', () => {
    expect(resolveTheme('auto', true)).toBe('dark');
    expect(resolveTheme('auto', false)).toBe('light');
  });
});

describe('getStoredMode', () => {
  function fakeStorage(value: string | null): Storage {
    return {
      getItem: vi.fn().mockReturnValue(value),
      setItem: vi.fn(),
      removeItem: vi.fn(),
      clear: vi.fn(),
      key: vi.fn(),
      length: 0,
    };
  }

  it('returns auto when nothing is stored', () => {
    expect(getStoredMode(fakeStorage(null))).toBe('auto');
  });

  it('returns the stored value when it is dark or light', () => {
    expect(getStoredMode(fakeStorage('dark'))).toBe('dark');
    expect(getStoredMode(fakeStorage('light'))).toBe('light');
  });

  it('treats a garbage/legacy stored value as auto rather than throwing', () => {
    expect(getStoredMode(fakeStorage('solarized'))).toBe('auto');
  });
});

describe('systemPrefersDark', () => {
  function fakeWindow(matches: boolean): Pick<Window, 'matchMedia'> {
    return {
      matchMedia: vi.fn().mockReturnValue({ matches } as MediaQueryList),
    };
  }

  it('reads (prefers-color-scheme: dark) from matchMedia', () => {
    const win = fakeWindow(true);
    expect(systemPrefersDark(win as Window)).toBe(true);
    expect(win.matchMedia).toHaveBeenCalledWith('(prefers-color-scheme: dark)');
  });

  it('returns false when the system prefers light', () => {
    expect(systemPrefersDark(fakeWindow(false) as Window)).toBe(false);
  });
});

describe('applyResolvedTheme', () => {
  it('adds the dark class and sets color-scheme: dark for a dark resolution', () => {
    const root = document.createElement('html');
    applyResolvedTheme(root, 'dark');
    expect(root.classList.contains('dark')).toBe(true);
    expect(root.style.colorScheme).toBe('dark');
  });

  it('removes the dark class and sets color-scheme: light for a light resolution', () => {
    const root = document.createElement('html');
    root.classList.add('dark');
    applyResolvedTheme(root, 'light');
    expect(root.classList.contains('dark')).toBe(false);
    expect(root.style.colorScheme).toBe('light');
  });
});

describe('setMode', () => {
  function fakeStorage(): Storage {
    const data = new Map<string, string>();
    return {
      getItem: (k: string) => data.get(k) ?? null,
      setItem: (k: string, v: string) => void data.set(k, v),
      removeItem: (k: string) => void data.delete(k),
      clear: () => data.clear(),
      key: () => null,
      length: 0,
    };
  }

  it('persists an explicit dark/light choice under THEME_STORAGE_KEY', () => {
    const storage = fakeStorage();
    const root = document.createElement('html');
    setMode('dark', { storage, root, prefersDark: false });
    expect(storage.getItem(THEME_STORAGE_KEY)).toBe('dark');
    expect(root.classList.contains('dark')).toBe(true);
  });

  it('removing to auto clears the stored key rather than writing "auto"', () => {
    // AUTO must be representable as "no preference recorded" so it stays
    // compatible with Basecoat's own window.basecoat.theme.* fallback path,
    // which only ever checks for a *missing* key, not a literal "auto".
    const storage = fakeStorage();
    storage.setItem(THEME_STORAGE_KEY, 'dark');
    const root = document.createElement('html');
    setMode('auto', { storage, root, prefersDark: true });
    expect(storage.getItem(THEME_STORAGE_KEY)).toBeNull();
    expect(root.classList.contains('dark')).toBe(true); // system prefers dark
  });

  it('applies the resolved theme to root immediately', () => {
    const storage = fakeStorage();
    const root = document.createElement('html');
    setMode('light', { storage, root, prefersDark: true });
    expect(root.classList.contains('dark')).toBe(false);
    expect(root.style.colorScheme).toBe('light');
  });
});

describe('cycleMode', () => {
  it('cycles auto -> dark -> light -> auto', () => {
    expect(cycleMode('auto')).toBe('dark');
    expect(cycleMode('dark')).toBe('light');
    expect(cycleMode('light')).toBe('auto');
  });
});

describe('THEME_MODES', () => {
  it('lists all three modes in display order', () => {
    expect(THEME_MODES).toEqual(['auto', 'dark', 'light']);
  });
});

describe('initTheme', () => {
  // A self-contained fake, not window.localStorage/document.documentElement --
  // real browser storage turned out to be unreliably provided by this
  // suite's jsdom environment depending on the Node runtime (undefined in
  // CI's Node 26 even via window.localStorage, though it worked locally on
  // Node 24), and a fresh element/Map per test needs no beforeEach/afterEach
  // cleanup at all, matching the setMode tests' own fakeStorage() above.
  function fakeStorage(): Storage {
    const data = new Map<string, string>();
    return {
      getItem: (k: string) => data.get(k) ?? null,
      setItem: (k: string, v: string) => void data.set(k, v),
      removeItem: (k: string) => void data.delete(k),
      clear: () => data.clear(),
      key: () => null,
      length: 0,
    };
  }

  it('re-applies the resolved theme when the system preference changes while in auto mode', () => {
    let listener: ((e: Pick<MediaQueryListEvent, 'matches'>) => void) | undefined;
    const mql = {
      matches: false,
      addEventListener: vi.fn((_event: string, cb: typeof listener) => {
        listener = cb;
      }),
      removeEventListener: vi.fn(),
    };
    const win = { matchMedia: vi.fn().mockReturnValue(mql) } as unknown as Window;
    const root = document.createElement('html');

    initTheme({ root, win, storage: fakeStorage() });
    expect(root.classList.contains('dark')).toBe(false);

    listener?.({ matches: true });
    expect(root.classList.contains('dark')).toBe(true);
  });

  it('does not react to system changes once an explicit mode is stored', () => {
    const storage = fakeStorage();
    storage.setItem(THEME_STORAGE_KEY, 'light');
    let listener: ((e: Pick<MediaQueryListEvent, 'matches'>) => void) | undefined;
    const mql = {
      matches: false,
      addEventListener: vi.fn((_event: string, cb: typeof listener) => {
        listener = cb;
      }),
      removeEventListener: vi.fn(),
    };
    const win = { matchMedia: vi.fn().mockReturnValue(mql) } as unknown as Window;
    const root = document.createElement('html');

    initTheme({ root, win, storage });
    listener?.({ matches: true });
    // Explicit "light" wins even though the system now reports dark.
    expect(root.classList.contains('dark')).toBe(false);
  });
});
