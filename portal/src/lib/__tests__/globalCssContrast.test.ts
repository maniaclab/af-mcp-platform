/**
 * Parses the real, live token values out of src/styles/global.css (not a
 * copy-pasted snapshot of them) and re-checks WCAG 2.1 AA (4.5:1) for every
 * text-bearing af-* token against both grounds it's actually used on --
 * af-surface (cards/panels) and af-void (the page). This is what keeps
 * global.css's own inline ratio comments, and DESIGN.md's Theming table,
 * honest as the palette evolves: a future edit that regresses a ratio fails
 * here instead of shipping.
 */
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { contrastRatio } from '../colorContrast';

// import.meta.url isn't guaranteed to be a `file:` URL under vitest's module
// runner (the same caveat scripts/sync-csp-hashes.mjs's own tests document),
// so this resolves against process.cwd() instead -- `vitest run`/`npm test`
// always run with cwd at the portal package root.
const GLOBAL_CSS_PATH = resolve(process.cwd(), 'src/styles/global.css');
const source = readFileSync(GLOBAL_CSS_PATH, 'utf8');

function extractBlock(pattern: RegExp): string {
  const match = source.match(pattern);
  if (!match) {
    throw new Error(`globalCssContrast.test.ts: could not find a block matching ${pattern}`);
  }
  return match[1];
}

function extractAfTokens(blockSource: string): Record<string, string> {
  const tokens: Record<string, string> = {};
  for (const m of blockSource.matchAll(/--color-af-([a-z-]+):\s*([^;]+);/g)) {
    tokens[m[1]] = m[2].trim();
  }
  return tokens;
}

// The @theme block holds the LIGHT defaults; .dark overrides the same names
// for dark mode (see global.css's own "Theming" docstring for why).
const lightTokens = extractAfTokens(extractBlock(/@theme\s*{([^}]*)}/s));
const darkTokens = extractAfTokens(extractBlock(/\n\.dark\s*{([^}]*)}/s));

const AA_NORMAL_TEXT = 4.5;

// Only tokens actually used as text color are checked here — af-border,
// af-muted (a non-text, ≥3:1 token per WCAG 1.4.11), af-hover-lift,
// af-scrim, and af-panel-shadow are structural/non-text and intentionally
// excluded.
const TEXT_TOKENS = ['dim', 'label', 'text', 'teal', 'amber', 'red', 'green'];
const GROUNDS = ['surface', 'void'] as const;

describe.each([
  ['light', lightTokens],
  ['dark', darkTokens],
] as const)('global.css %s theme', (themeName, tokens) => {
  it.each(TEXT_TOKENS)('af-%s clears AA (4.5:1) against both af-surface and af-void', (name) => {
    for (const ground of GROUNDS) {
      const ratio = contrastRatio(tokens[name], tokens[ground]);
      expect(
        ratio,
        `af-${name} (${tokens[name]}) vs af-${ground} (${tokens[ground]}) in ${themeName} mode`,
      ).toBeGreaterThanOrEqual(AA_NORMAL_TEXT);
    }
  });

  it('af-on-accent clears AA (4.5:1) against a filled af-teal control', () => {
    const ratio = contrastRatio(tokens['on-accent'], tokens['teal']);
    expect(
      ratio,
      `${themeName}: on-accent (${tokens['on-accent']}) vs teal (${tokens['teal']})`,
    ).toBeGreaterThanOrEqual(AA_NORMAL_TEXT);
  });
});
