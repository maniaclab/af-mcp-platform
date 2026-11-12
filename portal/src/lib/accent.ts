/**
 * accent.ts — optional per-deployment accent colour, resolved at runtime
 * from the same `/config.json` branding block as branding.ts.
 *
 * The default theme is neutral monochrome ink (global.css's
 * `--color-af-accent` / `--color-af-on-accent`); a facility opts in to its
 * own accent by setting `accentColor` (and optionally `accentColorDark`).
 * With nothing configured no inline property is written, so the stylesheet
 * defaults apply. The /design/ page's accent switcher
 * reuses `resolveAccent` (see designAccent.ts).
 */

import type { BrandingConfig } from './branding';
import { contrastRatio, parseHexColor } from './colorContrast';
import { THEME_CHANGE_EVENT } from './theme';

export interface ResolvedAccent {
  accent: string;
  onAccent: string;
}

// Page backgrounds the accent must stand out against (global.css's `--color-af-bg`).
const DARK_BACKGROUND = '#0f0f10';
const MIN_ACCENT_CONTRAST = 3; // WCAG non-text contrast
const MIN_TEXT_CONTRAST = 4.5; // WCAG normal-text contrast, for on-accent text
const MAX_LIGHTEN_STEPS = 20;
const LIGHTEN_STEP = 0.1;
const INK = '#0a0a0a';
const WHITE = '#ffffff';

/** Stricter than parseHexColor, which also accepts #rgb and a missing "#". */
const HEX_PATTERN = /^#[0-9a-fA-F]{6}$/;

function toHex(rgb: number[]): string {
  return '#' + rgb.map((v) => Math.round(v).toString(16).padStart(2, '0')).join('');
}

/** Returns *value* if it is a #rrggbb hex, else warns naming *field* and returns null. Empty/absent is unset, with no warning. */
function validHex(field: string, value: string | undefined): string | null {
  if (!value) return null;
  if (HEX_PATTERN.test(value)) return value;
  console.warn(`branding.${field} "${value}" is not a #rrggbb hex colour; ignoring it`);
  return null;
}

/** Mixes *hex* toward white in 10% steps (at most 20) until it reaches 3:1 against the dark page background. */
function lightenForDark(hex: string): string {
  let rgb: number[] = parseHexColor(hex);
  for (let i = 0; i < MAX_LIGHTEN_STEPS; i++) {
    if (contrastRatio(toHex(rgb), DARK_BACKGROUND) >= MIN_ACCENT_CONTRAST) break;
    rgb = rgb.map((v) => v + (255 - v) * LIGHTEN_STEP);
  }
  return toHex(rgb);
}

/**
 * The accent and on-accent colours to apply for the active theme, or null
 * when no (valid) accent applies. Never throws; invalid values are ignored
 * with a console.warn.
 */
export function resolveAccent(config: BrandingConfig, dark: boolean): ResolvedAccent | null {
  const light = validHex('accentColor', config.accentColor);
  const explicitDark = validHex('accentColorDark', config.accentColorDark);

  let accent: string | null;
  if (dark) accent = explicitDark ?? (light && lightenForDark(light));
  else accent = light;
  if (!accent) return null;

  const onAccent = contrastRatio(accent, WHITE) >= MIN_TEXT_CONTRAST ? WHITE : INK;
  return { accent, onAccent };
}

/**
 * Sets (or, when nothing is configured, removes) the accent custom
 * properties inline on *root*, for the theme its `.dark` class selects.
 */
export function applyAccent(
  config: BrandingConfig,
  root: HTMLElement = document.documentElement,
): void {
  const resolved = resolveAccent(config, root.classList.contains('dark'));
  if (resolved) {
    root.style.setProperty('--color-af-accent', resolved.accent);
    root.style.setProperty('--color-af-on-accent', resolved.onAccent);
  } else {
    root.style.removeProperty('--color-af-accent');
    root.style.removeProperty('--color-af-on-accent');
  }
}

/** applyAccent now, and again whenever theme.ts announces a theme change on *root*. */
export function watchAccent(
  config: BrandingConfig,
  root: HTMLElement = document.documentElement,
): void {
  applyAccent(config, root);
  root.addEventListener(THEME_CHANGE_EVENT, () => applyAccent(config, root));
}
