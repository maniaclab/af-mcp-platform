/**
 * designAccent.ts — the design reference page's accent switcher.
 *
 * A reader can try a facility colour on /design/ and see every example
 * respond. The choice is page-local: it is written inline on one scope
 * element (never on `<html>`, where accent.ts writes a deployment's
 * configured accent) and is never stored. A scope-level value wins over the
 * inherited configured one on this page, and removing it restores the
 * configured accent (or the ink default) with nothing to re-apply.
 *
 * The derivation is accent.ts's `resolveAccent` (on-accent text by contrast,
 * lightening in dark), not a copy of it.
 */

import { resolveAccent, type ResolvedAccent } from './accent';
import { THEME_CHANGE_EVENT } from './theme';

export interface AccentChoice {
  label: string;
  hex: string;
  /** Why it is offered. */
  note: string;
}

/** Example facility colours; the default (no override) is the deployment's own accent. */
export const ACCENT_CHOICES: AccentChoice[] = [
  { label: 'Maroon', hex: '#800000', note: 'Example facility colour' },
  { label: 'Blue', hex: '#0033a0', note: 'Example facility colour' },
  { label: 'Green', hex: '#0f7b3f', note: 'Example facility colour' },
  { label: 'Yellow', hex: '#ffd200', note: 'Stress case: a pale accent' },
];

/** The custom properties the portal's accent is made of (global.css). */
export const LOCAL_ACCENT_PROPERTIES = ['--color-af-accent', '--color-af-on-accent'] as const;

/**
 * Applies *hex* as the accent of *scope* for the theme *root* currently shows,
 * or, with null, removes the local override so the inherited (configured)
 * accent shows again. Returns what was applied, or null.
 */
export function applyLocalAccent(
  scope: HTMLElement,
  hex: string | null,
  root: HTMLElement = document.documentElement,
): ResolvedAccent | null {
  const resolved = hex
    ? resolveAccent(
        { shortName: '', fullName: '', facilityName: '', accentColor: hex },
        root.classList.contains('dark'),
      )
    : null;
  const [accent, onAccent] = LOCAL_ACCENT_PROPERTIES;
  if (resolved) {
    scope.style.setProperty(accent, resolved.accent);
    scope.style.setProperty(onAccent, resolved.onAccent);
  } else {
    scope.style.removeProperty(accent);
    scope.style.removeProperty(onAccent);
  }
  return resolved;
}

/**
 * applyLocalAccent now with the current choice, and again after every theme
 * change, so the choice is re-derived for the new theme. Returns a cleanup.
 */
export function watchLocalAccent(
  scope: HTMLElement,
  currentChoice: () => string | null,
  root: HTMLElement = document.documentElement,
): () => void {
  const apply = () => applyLocalAccent(scope, currentChoice(), root);
  apply();
  root.addEventListener(THEME_CHANGE_EVENT, apply);
  return () => root.removeEventListener(THEME_CHANGE_EVENT, apply);
}
