/**
 * designTokens.ts — live token values for the design reference page.
 *
 * The page's token tables show the value each custom property has right now,
 * read from the page's computed style, so a table cannot drift from
 * global.css. They are read again whenever something that can change them
 * changes: a theme change (theme.ts), the page-local accent choice, or the
 * deployment's configured accent landing on `<html>` after `/config.json`
 * has loaded.
 */

import { THEME_CHANGE_EVENT } from './theme';

/** Dispatched on the root after the page-local accent choice changes. */
export const DESIGN_ACCENT_EVENT = 'af-design-accent';

/** The element whose computed style the page reads: the accent scope, which sits inside `<html>`. */
export const DESIGN_SCOPE_ID = 'design-scope';

/** A row of a token table: the token, what it is for and, for a type specimen, its sample. */
export interface TokenRow {
  /** Custom property, e.g. `--color-af-bg`. */
  name: string;
  use: string;
  /** Type specimens only: the sample text and its weight. */
  sample?: string;
  weight?: number;
}

/** The part of CSSStyleDeclaration this module needs, so tests need no layout engine. */
export type StyleReader = Pick<CSSStyleDeclaration, 'getPropertyValue'>;

/** Value of each custom property in *names*, trimmed; '' when it is not defined. */
export function readTokenValues(names: string[], style: StyleReader): Record<string, string> {
  return Object.fromEntries(names.map((name) => [name, style.getPropertyValue(name).trim()]));
}

/**
 * Calls *onChange* (at most once per burst, after every other listener of the
 * same event has run) when the theme changes, when the page-local accent
 * changes, or when *root*'s inline style or class changes. Returns a cleanup.
 */
export function subscribeToTokenChanges(
  onChange: () => void,
  root: HTMLElement = document.documentElement,
): () => void {
  let pending = false;
  let stopped = false;
  const schedule = () => {
    if (pending) return;
    pending = true;
    // A microtask runs after all listeners of the event, including accent.ts's,
    // so what is read afterwards is the settled value.
    queueMicrotask(() => {
      pending = false;
      if (!stopped) onChange();
    });
  };
  const events = [THEME_CHANGE_EVENT, DESIGN_ACCENT_EVENT];
  for (const name of events) root.addEventListener(name, schedule);
  const observer = new MutationObserver(schedule);
  observer.observe(root, { attributes: true, attributeFilter: ['style', 'class'] });
  return () => {
    for (const name of events) root.removeEventListener(name, schedule);
    observer.disconnect();
    stopped = true;
  };
}
