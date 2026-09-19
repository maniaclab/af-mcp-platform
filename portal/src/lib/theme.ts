/**
 * theme.ts — the AUTO / DARK / LIGHT theme control's resolution and
 * persistence logic, shared by ThemeToggle.astro's mount script and this
 * module's own tests.
 *
 * The anti-flash-of-wrong-theme bootstrap that runs before first paint
 * (themeInitScript.js) duplicates a small literal subset of this file's
 * logic rather than importing it — see that file's own docstring for why.
 * Any change to resolveTheme()/applyResolvedTheme()'s behavior must be
 * mirrored there by hand.
 *
 * Persistence deliberately uses `localStorage`, not `sessionStorage` (the
 * pattern src/lib/auth.ts uses for tokens, per #42). That decision is about
 * the blast radius of a *credential* leaking across the same-origin surface;
 * a theme preference is not a secret, and sessionStorage would silently
 * lose the choice on every new tab. The storage key, "themeMode", matches
 * Basecoat's own `window.basecoat.theme.*` convention (a stored "dark" or
 * "light" value, or an absent key meaning "follow the system") rather than
 * inventing a parallel one — so a future `window.basecoat.theme.toggle()`
 * call, or any Basecoat-shipped UI, reads and writes the same state this
 * control does.
 */

export const THEME_STORAGE_KEY = 'themeMode';

/** Display order for the AUTO / DARK / LIGHT control. */
export const THEME_MODES = ['auto', 'dark', 'light'] as const;

export type ThemeMode = (typeof THEME_MODES)[number];
export type ResolvedTheme = 'dark' | 'light';

/** Reads the stored mode, defaulting to 'auto' for anything else (missing key, or a stale/garbage value from an older build). */
export function getStoredMode(storage: Pick<Storage, 'getItem'>): ThemeMode {
  const raw = storage.getItem(THEME_STORAGE_KEY);
  return raw === 'dark' || raw === 'light' ? raw : 'auto';
}

export function systemPrefersDark(win: Pick<Window, 'matchMedia'>): boolean {
  return win.matchMedia('(prefers-color-scheme: dark)').matches;
}

/** Turns a mode + the current system preference into the theme that should actually be painted. */
export function resolveTheme(mode: ThemeMode, prefersDark: boolean): ResolvedTheme {
  if (mode === 'auto') return prefersDark ? 'dark' : 'light';
  return mode;
}

/**
 * Applies a resolved theme to the document root: toggles Basecoat's `.dark`
 * class (its `@custom-variant dark (&:is(html.dark *))` requires this
 * specific class on `<html>` for its own `dark:` utilities to fire) and sets
 * `color-scheme` so native form controls/scrollbars follow.
 */
export function applyResolvedTheme(root: HTMLElement, resolved: ResolvedTheme): void {
  root.classList.toggle('dark', resolved === 'dark');
  root.style.colorScheme = resolved;
}

export interface SetModeOptions {
  storage?: Storage;
  root?: HTMLElement;
  win?: Pick<Window, 'matchMedia'>;
  /** Test seam: bypasses `win.matchMedia` when the caller already knows the system preference. */
  prefersDark?: boolean;
}

/**
 * Records `mode` (or clears the stored key for 'auto' — see the module
 * docstring on why AUTO is "absent," not a literal "auto" string) and
 * applies the resulting theme immediately.
 */
export function setMode(mode: ThemeMode, options: SetModeOptions = {}): void {
  const storage = options.storage ?? window.localStorage;
  const root = options.root ?? document.documentElement;
  const win = options.win ?? window;
  const prefersDark = options.prefersDark ?? systemPrefersDark(win);

  if (mode === 'auto') storage.removeItem(THEME_STORAGE_KEY);
  else storage.setItem(THEME_STORAGE_KEY, mode);

  applyResolvedTheme(root, resolveTheme(mode, prefersDark));
}

/** auto -> dark -> light -> auto, for a single-control cycling affordance (unused by the radiogroup, kept for a future compact toggle). */
export function cycleMode(current: ThemeMode): ThemeMode {
  return THEME_MODES[(THEME_MODES.indexOf(current) + 1) % THEME_MODES.length];
}

export interface InitThemeOptions {
  root?: HTMLElement;
  win?: Window;
  storage?: Storage;
}

/**
 * Wires up live system-preference tracking for AUTO mode: while no explicit
 * dark/light choice is stored, a change to the OS-level preference
 * re-applies the theme without a reload. Returns a cleanup function that
 * removes the listener (for symmetry with the rest of the codebase's mount
 * scripts, even though nothing currently tears this down before unload).
 */
export function initTheme(options: InitThemeOptions = {}): () => void {
  const root = options.root ?? document.documentElement;
  const win = options.win ?? window;
  const storage = options.storage ?? window.localStorage;

  const media = win.matchMedia('(prefers-color-scheme: dark)');
  const onChange = (event: Pick<MediaQueryListEvent, 'matches'>) => {
    const mode = getStoredMode(storage);
    if (mode !== 'auto') return; // an explicit choice always wins over a system change
    applyResolvedTheme(root, resolveTheme('auto', event.matches));
  };
  media.addEventListener('change', onChange);
  return () => media.removeEventListener('change', onChange);
}
