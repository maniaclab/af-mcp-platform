/**
 * Parses the real, live token values out of src/styles/global.css (not a
 * copy-pasted snapshot of them) and re-checks WCAG 2.1 contrast for the
 * semantic af-* tokens against the grounds they are used on: text tokens at
 * 4.5:1 (AA), status colours at 3:1 (non-text, WCAG 1.4.11). A future edit
 * that regresses a ratio fails here instead of shipping.
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

// The @theme block holds the LIGHT defaults; .dark overrides only the tokens
// that differ. Tokens identical in both themes (the banner fills) are not
// repeated in .dark, so dark resolves against light for anything it omits.
const lightTokens = extractAfTokens(extractBlock(/@theme\s*{([^}]*)}/s));
const darkTokens = { ...lightTokens, ...extractAfTokens(extractBlock(/\n\.dark\s*{([^}]*)}/s)) };

const AA_NORMAL_TEXT = 4.5;
const NON_TEXT = 3;

const TEXT_TOKENS = ['text', 'text-secondary', 'bad-text'];
const STATUS_TOKENS = ['ok', 'warn', 'bad', 'info'];
const GROUNDS = ['bg', 'bg-subtle'] as const;

describe.each([
  ['light', lightTokens],
  ['dark', darkTokens],
] as const)('global.css %s theme', (themeName, tokens) => {
  it.each(TEXT_TOKENS)('af-%s clears AA (4.5:1) against both af-bg and af-bg-subtle', (name) => {
    for (const ground of GROUNDS) {
      const ratio = contrastRatio(tokens[name], tokens[ground]);
      expect(
        ratio,
        `af-${name} (${tokens[name]}) vs af-${ground} (${tokens[ground]}) in ${themeName} mode`,
      ).toBeGreaterThanOrEqual(AA_NORMAL_TEXT);
    }
  });

  it('af-on-accent clears AA (4.5:1) against a filled af-accent control', () => {
    const ratio = contrastRatio(tokens['on-accent'], tokens['accent']);
    expect(
      ratio,
      `${themeName}: on-accent (${tokens['on-accent']}) vs accent (${tokens['accent']})`,
    ).toBeGreaterThanOrEqual(AA_NORMAL_TEXT);
  });

  it.each(['ok', 'warn', 'bad', 'info'])(
    'af-on-banner-%s clears AA (4.5:1) against its af-banner fill',
    (name) => {
      const ratio = contrastRatio(tokens[`on-banner-${name}`], tokens[`banner-${name}`]);
      expect(
        ratio,
        `${themeName}: on-banner-${name} (${tokens[`on-banner-${name}`]}) vs banner-${name} (${tokens[`banner-${name}`]})`,
      ).toBeGreaterThanOrEqual(AA_NORMAL_TEXT);
    },
  );

  it.each(STATUS_TOKENS)('af-%s clears 3:1 (non-text) against af-bg', (name) => {
    const ratio = contrastRatio(tokens[name], tokens['bg']);
    expect(
      ratio,
      `${themeName}: ${name} (${tokens[name]}) vs bg (${tokens['bg']})`,
    ).toBeGreaterThanOrEqual(NON_TEXT);
  });
});
