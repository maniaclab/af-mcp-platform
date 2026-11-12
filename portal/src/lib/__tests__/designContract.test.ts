/**
 * Enforces the design contract (DESIGN.md; the reference page is /design/) on every
 * .vue, .astro and .css file under src. It reads the sources and fails, naming
 * file and line, on anything that re-introduces a look the contract removed:
 * literal colours, transitional alias tokens, raw type sizes, off-contract
 * fonts, uppercase/letter-spaced labels, glass blur, ad-hoc shadows and radii,
 * and text glyphs used as icons. It also keeps the component vocabulary on
 * Basecoat: the retired hand-rolled `af-*` classes may not be used or defined,
 * and no CSS rule may redefine a Basecoat class (extend it with an `af-` class
 * instead, as in `.btn.af-danger`).
 *
 * Only token primitives may hold literal colours, and those live in
 * src/styles/global.css (the `@theme` and `.dark` blocks), which is exempt
 * from the colour rules. Comments are stripped before matching, so a comment
 * that mentions an old token does not trip a rule.
 */
import { readdirSync, readFileSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

const SRC_DIR = resolve(process.cwd(), 'src');
const GLOBAL_CSS = 'src/styles/global.css';
const COMPONENTS_CSS = 'src/styles/components.css';

interface Rule {
  id: string;
  fix: string;
}

interface Violation {
  file: string;
  line: number;
  rule: Rule;
  text: string;
}

/**
 * Genuine exceptions. A violation is allowed when its file matches, its rule
 * matches and the offending source line contains `contains`. Keep this list
 * small: the fix for a violation is the token or shared class, not an entry.
 */
const ALLOWLIST: { file: string; rule: string; contains: string; reason: string }[] = [
  {
    file: 'src/components/Fonts.astro',
    rule: 'font-family',
    contains: 'IBM Plex',
    reason:
      '@font-face rules declare the family names that --font-sans and --font-mono resolve to.',
  },
  {
    file: 'src/components/ConnectClient.vue',
    rule: 'arrow-glyph',
    contains: 'Settings → Connectors',
    reason: 'A navigation path inside a prose sentence; the arrow is punctuation, not an icon.',
  },
  {
    file: 'src/components/design/DontExamples.astro',
    rule: 'font-size',
    contains: 'wrong:font-size',
    reason:
      'The design reference page\'s "don\'t" examples show a font size below the 12px minimum (a tiny table header) on purpose. Every such line in this one file carries the marker.',
  },
  {
    file: 'src/components/design/DontExamples.astro',
    rule: 'uppercase',
    contains: 'wrong:uppercase',
    reason:
      'The design reference page\'s "don\'t" examples show uppercase labels (a terminal-style table header) on purpose. Every such line in this one file carries the marker.',
  },
  {
    file: 'src/components/design/DontExamples.astro',
    rule: 'letter-spacing',
    contains: 'wrong:letter-spacing',
    reason:
      'The design reference page\'s "don\'t" examples show letter-spaced labels (a terminal-style table header) on purpose. Every such line in this one file carries the marker.',
  },
  {
    file: 'src/components/design/DontExamples.astro',
    rule: 'box-shadow',
    contains: 'wrong:box-shadow',
    reason:
      'The design reference page\'s "don\'t" examples show a shadow on a card that belongs to the page on purpose. Every such line in this one file carries the marker.',
  },
  {
    file: 'src/components/design/DontExamples.astro',
    rule: 'border-radius',
    contains: 'wrong:border-radius',
    reason:
      'The design reference page\'s "don\'t" examples show an off-scale corner radius on a heavy frame on purpose. Every such line in this one file carries the marker.',
  },
  {
    file: 'src/components/design/DontExamples.astro',
    rule: 'icon-glyph',
    contains: 'wrong:icon-glyph',
    reason:
      'The design reference page\'s "don\'t" examples show text glyphs used as icons on purpose. Every such line in this one file carries the marker.',
  },
  {
    file: 'src/components/design/DontExamples.astro',
    rule: 'arrow-glyph',
    contains: 'wrong:arrow-glyph',
    reason:
      'The design reference page\'s "don\'t" examples show an arrow glyph used as an icon on purpose. Every such line in this one file carries the marker.',
  },
];

const RULES = {
  hex: {
    id: 'hex-colour',
    fix: 'Use a colour token: var(--color-af-*). Literal colours may only be defined in src/styles/global.css.',
  },
  colorFn: {
    id: 'colour-function',
    fix: 'Use var(--color-af-*), rgb(from var(--color-af-*) r g b / a) or color-mix(in srgb, var(--color-af-*) N%, var(--color-af-bg)).',
  },
  alias: {
    id: 'alias-token',
    fix: 'The transitional alias tokens are gone. Use the semantic tokens: af-bg, af-bg-subtle, af-border, af-text, af-text-secondary, af-accent, af-ok, af-warn, af-bad, af-bad-text, af-info.',
  },
  fontSize: {
    id: 'font-size',
    fix: 'Use font-size: var(--text-12|13|14|16|20|24|32), or inherit.',
  },
  fontFamily: {
    id: 'font-family',
    fix: 'Use var(--font-sans), var(--font-mono) (literal values only) or inherit.',
  },
  uppercase: {
    id: 'uppercase',
    fix: 'Labels are sentence case; remove text-transform: uppercase / the `uppercase` utility.',
  },
  letterSpacing: {
    id: 'letter-spacing',
    fix: 'Remove letter-spacing / tracking-*. The contract sets none.',
  },
  backdrop: {
    id: 'backdrop-filter',
    fix: 'Remove backdrop-filter / backdrop-blur-*. Surfaces are opaque.',
  },
  boxShadow: {
    id: 'box-shadow',
    fix: 'Use box-shadow: var(--shadow-af-1) (menus, tooltips), var(--shadow-af-2) (dialogs) or none. A ring is `inset 0 0 0 <n>px var(--color-af-*)`.',
  },
  radius: {
    id: 'border-radius',
    fix: 'Use var(--radius-4|8|10|full), 0 or 50%.',
  },
  glyph: {
    id: 'icon-glyph',
    fix: 'Use an icon from @lucide/vue (.vue) or @lucide/astro (.astro), 16px, aria-hidden when decorative.',
  },
  arrow: {
    id: 'arrow-glyph',
    fix: 'Use a lucide icon. An arrow is allowed only inside prose; add it to ALLOWLIST with the reason.',
  },
} satisfies Record<string, Rule>;

/**
 * Hand-rolled classes that Basecoat replaces, with the Basecoat class to use.
 * `af-btn-xl` (the landing page's Sign in) is not retired; the lookahead in
 * RETIRED_RE keeps it out of the `af-btn` match.
 */
const RETIRED_CLASSES: Record<string, string> = {
  'af-btn': '`btn` with data-variant (outline, ghost) and data-size (sm, lg, icon*)',
  'af-input': '`input` (text fields), `native-select` (selects) or `textarea`',
  'af-field': '`field`',
  'af-check': '`field` with `data-orientation="horizontal"` around an `input type="checkbox"`',
  'af-tbl-box': '`table-container` with the `af-box` extension',
  'af-tbl': '`table` (density and numeric cells: `af-compact`, `af-num`, `af-act`, `af-sub`)',
  'af-tag': '`badge` with `data-variant="outline"`',
  'af-dialog': '`dialog` on the native <dialog> (backdrop and shadow: `af-modal`)',
  'af-empty': '`empty`',
  'af-seg': '`button-group` of `btn`s with aria-pressed',
  'af-menu': "Basecoat's `dropdown-menu`",
  'af-tip': 'PopoverTooltip.vue (native Popover API)',
};

const RETIRED_RULES: Record<string, Rule> = Object.fromEntries(
  Object.entries(RETIRED_CLASSES).map(([name, use]) => [
    name,
    { id: `retired-class:${name}`, fix: `\`${name}\` is retired. Use ${use}.` },
  ]),
);

const RETIRED_RE = new RegExp(
  `(?<![\\w-])(${Object.keys(RETIRED_CLASSES).join('|')})(?![\\w-])`,
  'g',
);

/**
 * Classes Basecoat ships. A rule whose selector names one of these without an
 * `af-` class beside it redefines the component instead of extending it.
 */
const BASECOAT_CLASSES = new Set([
  'accordion',
  'alert',
  'alert-dialog',
  'avatar',
  'badge',
  'breadcrumb',
  'btn',
  'button-group',
  'card',
  'checkbox',
  'collapsible',
  'combobox',
  'command',
  'dialog',
  'drawer',
  'dropdown-menu',
  'empty',
  'field',
  'fieldset',
  'input',
  'input-group',
  'item',
  'kbd',
  'label',
  'popover',
  'progress',
  'radio',
  'range',
  'select',
  'sidebar',
  'skeleton',
  'switch',
  'table',
  'table-container',
  'tabs',
  'textarea',
  'toast',
]);

const REDEFINED_RULE: Rule = {
  id: 'basecoat-redefined',
  fix: 'A selector may not redefine a Basecoat class. Extend it with a separate af- class (`.btn.af-danger`, `.alert.af-note.warn`) or re-theme through the token bridge in global.css.',
};

/** Splits a selector list on the commas that are not inside parentheses. */
function splitSelectors(list: string): string[] {
  const out: string[] = [];
  let depth = 0;
  let start = 0;
  for (let i = 0; i < list.length; i++) {
    if (list[i] === '(') depth++;
    else if (list[i] === ')') depth--;
    else if (list[i] === ',' && depth === 0) {
      out.push(list.slice(start, i));
      start = i + 1;
    }
  }
  out.push(list.slice(start));
  return out;
}

/** Replaces every character except newlines with a space, keeping line numbers. */
function blank(text: string): string {
  return text.replace(/[^\n]/g, ' ');
}

interface Regions {
  style: string;
  markup: string;
  script: string;
}

/** Splits a source into same-length views so that offsets and lines still match the file. */
function splitRegions(path: string, source: string): Regions {
  if (path.endsWith('.css')) {
    return { style: source, markup: blank(source), script: blank(source) };
  }
  const style = Array.from(blank(source));
  const script = Array.from(blank(source));
  const markup = Array.from(source);
  const carve = (target: string[], start: number, end: number) => {
    for (let i = start; i < end; i++) {
      target[i] = source[i];
      markup[i] = source[i] === '\n' ? '\n' : ' ';
    }
  };
  for (const m of source.matchAll(/<style\b[^>]*>([\s\S]*?)<\/style>/g)) {
    carve(style, m.index + m[0].indexOf(m[1]), m.index + m[0].indexOf(m[1]) + m[1].length);
  }
  for (const m of source.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/g)) {
    carve(script, m.index + m[0].indexOf(m[1]), m.index + m[0].indexOf(m[1]) + m[1].length);
  }
  const frontmatter = source.match(/^---\n([\s\S]*?)\n---/);
  if (path.endsWith('.astro') && frontmatter) {
    carve(script, 4, 4 + frontmatter[1].length);
  }
  return { style: style.join(''), markup: markup.join(''), script: script.join('') };
}

function stripComments(text: string, kind: 'style' | 'markup' | 'script'): string {
  const keepNewlines = (m: string) => blank(m);
  if (kind === 'style') return text.replace(/\/\*[\s\S]*?\*\//g, keepNewlines);
  if (kind === 'markup') return text.replace(/<!--[\s\S]*?-->/g, keepNewlines);
  return text
    .replace(/\/\*[\s\S]*?\*\//g, keepNewlines)
    .replace(/(^|[\s;,{}()])\/\/[^\n]*/g, (m, lead) => lead + blank(m.slice(lead.length)));
}

function lineOf(text: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index; i++) if (text[i] === '\n') line++;
  return line;
}

const ALIAS_NAMES = 'void|surface|muted|dim|label|teal|amber|red|green|panel-shadow';
const ALIAS_RE = new RegExp(
  `(?:--color-af-|\\b(?:text|bg|border|ring|fill|stroke|from|to|via|divide|outline|shadow|decoration|accent|caret|placeholder)-af-)(?:${ALIAS_NAMES})(?![\\w-])`,
  'g',
);

/** Raw-length tokens left in a value once `var(...)` references are removed. */
function rawTokens(value: string): string[] {
  return value
    .replace(/var\([^)]*\)/g, ' ')
    .split(/[\s/,]+/)
    .filter(Boolean);
}

const BOX_SHADOW_OK =
  /^(none|var\(--shadow-af-[12]\)|inset 0 0 0 [\d.]+px var\(--[\w-]+\)(\s*,\s*inset 0 0 0 [\d.]+px var\(--[\w-]+\))*)$/;

export function scanSource(path: string, source: string): Violation[] {
  const violations: Violation[] = [];
  const regions = splitRegions(path, source);
  const style = stripComments(regions.style, 'style');
  const markup = stripComments(regions.markup, 'markup');
  const script = stripComments(regions.script, 'script');
  const isGlobal = path === GLOBAL_CSS;
  const lines = source.split('\n');

  const report = (rule: Rule, text: string, index: number) => {
    const line = lineOf(source, index);
    if (violations.some((v) => v.line === line && v.rule === rule)) return;
    violations.push({ file: path, line, rule, text: lines[line - 1].trim() || text });
  };
  const find = (
    text: string,
    re: RegExp,
    rule: Rule,
    accept?: (m: RegExpMatchArray) => boolean,
  ) => {
    for (const m of text.matchAll(re)) {
      if (!accept || !accept(m)) report(rule, m[0], m.index);
    }
  };

  // Colours: style blocks and markup (SVG attributes, arbitrary utilities).
  if (!isGlobal) {
    for (const text of [style, markup]) {
      find(
        text,
        /(?<![&\w#])#(?:[0-9a-fA-F]{8}|[0-9a-fA-F]{6}|[0-9a-fA-F]{3,4})(?![\w-])/g,
        RULES.hex,
      );
    }
    find(style, /\b(?:rgba?|hsla?|hwb|lab|lch|oklab|oklch)\(\s*(?!from\s+var\(--)/g, RULES.colorFn);
  }

  // Alias tokens: anywhere in the file, comments excluded.
  for (const text of [style, markup, script]) find(text, ALIAS_RE, RULES.alias);

  // Declarations in style blocks.
  find(style, /(?<![\w-])font-size\s*:\s*([^;}]+)/g, RULES.fontSize, (m) =>
    rawTokens(m[1]).every((t) => t === 'inherit' || t === '0') && !/!important/.test(m[1])
      ? true
      : /^\s*(var\(--text-\d+\)|inherit|0)\s*(!important)?\s*$/.test(m[1]),
  );
  find(style, /(?<![\w-])font-family\s*:\s*([^;}]+)/g, RULES.fontFamily, (m) =>
    /^\s*(var\(--font-(sans|mono)\)|inherit)\s*$/.test(m[1]),
  );
  find(style, /(?<![\w-])text-transform\s*:\s*uppercase/g, RULES.uppercase);
  find(style, /(?<![\w-])letter-spacing\s*:\s*([^;}]+)/g, RULES.letterSpacing, (m) =>
    /^\s*(0|0px|normal|inherit|initial|unset)\s*$/.test(m[1]),
  );
  find(style, /(?<![\w-])backdrop-filter\s*:/g, RULES.backdrop);
  find(style, /(?<![\w-])box-shadow\s*:\s*([^;}]+)/g, RULES.boxShadow, (m) =>
    BOX_SHADOW_OK.test(m[1].trim().replace(/\s+/g, ' ')),
  );
  find(
    style,
    /(?<![\w-])border(?:-(?:top|bottom|start|end)-(?:left|right|start|end))?-?radius\s*:\s*([^;}]+)/g,
    RULES.radius,
    (m) => {
      const tokens = rawTokens(m[1]);
      // components.css draws status-mark shapes with 1px/2px corners.
      const allowed =
        path === COMPONENTS_CSS ? ['0', '50%', '1px', '2px', 'inherit'] : ['0', '50%', 'inherit'];
      return tokens.every((t) => allowed.includes(t));
    },
  );

  // Retired hand-rolled classes: style, markup and script strings alike.
  for (const text of [style, markup, script]) {
    for (const m of text.matchAll(RETIRED_RE)) report(RETIRED_RULES[m[1]], m[0], m.index);
  }

  // Basecoat classes redefined in a style block (a rule head is the text
  // before each `{` that is not an at-rule).
  for (const m of style.matchAll(/(?:^|[{};])\s*([^{};@]+)\{/g)) {
    const head = m[1];
    const at = m.index + m[0].indexOf(head);
    for (const selector of splitSelectors(head)) {
      const classes = [...selector.matchAll(/\.([\w-]+)/g)].map((c) => c[1]);
      if (
        classes.some((c) => BASECOAT_CLASSES.has(c)) &&
        !classes.some((c) => c.startsWith('af-'))
      ) {
        report(REDEFINED_RULE, selector.trim(), at);
      }
    }
  }

  // Tailwind utilities in markup and script strings.
  for (const text of [markup, script]) {
    find(text, /(?<![\w-])uppercase(?![\w-])(?=[^<>]*>|['"`])/g, RULES.uppercase, (m) => {
      // Only a class list (inside quotes) counts, not prose containing the word.
      const before = text.slice(Math.max(0, (m.index ?? 0) - 80), m.index);
      return !/class(?:Name)?\s*=\s*["'][^"']*$|:class\s*=\s*"[^"]*$|\bclass\b[^>]*$/.test(before);
    });
    find(text, /(?<![\w-])tracking-[\w[\]./-]+/g, RULES.letterSpacing);
    find(text, /(?<![\w-])backdrop-[\w[\]./-]+/g, RULES.backdrop);
    find(text, /(?<![\w-])text-\[[\d.]+(?:px|rem|em)\]/g, RULES.fontSize);
  }

  // Glyph icons: user-visible text in markup and script strings.
  for (const text of [markup, script, style]) {
    find(
      text,
      /[✓✗✔✘⚠ⓘ▸▾▴▶▼↗×]|&#(?:9656|9662|10003|10007|9888|9432|8599|215);|&(?:times|check);/g,
      RULES.glyph,
    );
    find(text, /→|&rarr;|&#8594;/g, RULES.arrow);
  }

  return violations;
}

function isAllowed(v: Violation): boolean {
  return ALLOWLIST.some(
    (a) => a.file === v.file && a.rule === v.rule.id && v.text.includes(a.contains),
  );
}

function listFiles(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) return entry.name === '__tests__' ? [] : listFiles(full);
    return /\.(vue|astro|css)$/.test(entry.name) ? [full] : [];
  });
}

function formatViolations(violations: Violation[]): string {
  const byRule = new Map<string, Violation[]>();
  for (const v of violations) byRule.set(v.rule.id, [...(byRule.get(v.rule.id) ?? []), v]);
  return [...byRule.values()]
    .map(
      (group) =>
        `\n[${group[0].rule.id}] ${group[0].rule.fix}\n` +
        group.map((v) => `  ${v.file}:${v.line}  ${v.text}`).join('\n'),
    )
    .join('\n');
}

describe('design contract', () => {
  it('has no off-contract styling or icon glyphs in src', () => {
    const files = listFiles(SRC_DIR);
    expect(files.length).toBeGreaterThan(20);
    const violations = files
      .flatMap((f) => scanSource(relative(process.cwd(), f), readFileSync(f, 'utf8')))
      .filter((v) => !isAllowed(v));
    if (violations.length > 0) {
      throw new Error(
        `${violations.length} design-contract violation(s):\n${formatViolations(violations)}`,
      );
    }
  });

  it('keeps every allowlist entry in use', () => {
    const used = new Set<string>();
    for (const f of listFiles(SRC_DIR)) {
      for (const v of scanSource(relative(process.cwd(), f), readFileSync(f, 'utf8'))) {
        const entry = ALLOWLIST.find(
          (a) => a.file === v.file && a.rule === v.rule.id && v.text.includes(a.contains),
        );
        if (entry) used.add(entry.file + entry.contains);
      }
    }
    expect([...used].sort()).toEqual(ALLOWLIST.map((a) => a.file + a.contains).sort());
  });
});

describe('design contract scanner', () => {
  const css = (body: string) => scanSource('src/x.css', body).map((v) => v.rule.id);

  it.each([
    ['a { color: #fff; }', 'hex-colour'],
    ['a { color: rgba(0 0 0 / 0.5); }', 'colour-function'],
    ['a { color: var(--color-af-teal); }', 'alias-token'],
    ['a { font-size: 11px; }', 'font-size'],
    ['a { font-family: serif; }', 'font-family'],
    ['a { text-transform: uppercase; }', 'uppercase'],
    ['a { letter-spacing: 0.08em; }', 'letter-spacing'],
    ['a { backdrop-filter: blur(4px); }', 'backdrop-filter'],
    ['a { box-shadow: 0 0 8px red; }', 'box-shadow'],
    ['a { border-radius: 6px; }', 'border-radius'],
  ])('flags %s', (body, rule) => {
    expect(css(body)).toContain(rule);
  });

  it.each([
    'a { color: var(--color-af-text); }',
    'a { color: rgb(from var(--color-af-text) r g b / 0.5); }',
    'a { background: color-mix(in srgb, var(--color-af-bad) 8%, var(--color-af-bg)); }',
    'a { font-size: var(--text-14); font-family: var(--font-mono); letter-spacing: 0; }',
    'a { box-shadow: var(--shadow-af-1); border-radius: var(--radius-8) var(--radius-8) 0 0; }',
    'a { box-shadow: inset 0 0 0 1.5px var(--color-af-text-secondary); border-radius: 50%; }',
    '/* the old --color-af-teal and #fff and uppercase glyph × */ a { color: inherit; }',
  ])('accepts %s', (body) => {
    expect(css(body)).toEqual([]);
  });

  it.each([
    ['a { } .af-btn.primary { color: red; }', 'retired-class:af-btn'],
    ['.af-tbl td { color: red; }', 'retired-class:af-tbl'],
    ['.af-tag, .x { color: red; }', 'retired-class:af-tag'],
    ['.btn { height: 1px; }', 'basecoat-redefined'],
    ['.x, .table td:hover { color: red; }', 'basecoat-redefined'],
    ['@layer components { .badge[data-variant="x"] { color: red; } }', 'basecoat-redefined'],
    ['.parent :is(.btn, .y) { color: red; }', 'basecoat-redefined'],
  ])('flags %s', (body, rule) => {
    expect(css(body)).toContain(rule);
  });

  it.each([
    '.btn.af-danger { color: red; }',
    '.alert.af-banner.warn { color: red; }',
    '.af-box .table th { color: red; }',
    '.table.af-compact td { color: red; }',
    '.af-btn-xl { color: red; }',
    '.my-label, .tp__input { color: red; }',
    '/* the retired .af-btn and .btn { } are only named here */ a { color: inherit; }',
  ])('accepts %s', (body) => {
    expect(css(body)).toEqual([]);
  });

  it('flags a retired class in markup and names the line', () => {
    const vue = '<template>\n  <button class="af-btn secondary s">x</button>\n</template>';
    expect(scanSource('src/c.vue', vue).map((v) => [v.rule.id, v.line])).toEqual([
      ['retired-class:af-btn', 2],
    ]);
  });

  it('flags glyph icons and utility aliases in a template and names the line', () => {
    const vue = '<template>\n  <span class="text-af-teal uppercase">✓ ok</span>\n</template>';
    const found = scanSource('src/c.vue', vue);
    expect(found.map((v) => [v.rule.id, v.line])).toEqual(
      expect.arrayContaining([
        ['alias-token', 2],
        ['uppercase', 2],
        ['icon-glyph', 2],
      ]),
    );
  });

  it('ignores literal colours in global.css and 1px radii only in components.css', () => {
    expect(scanSource(GLOBAL_CSS, '@theme { --color-af-bg: #fff; }')).toEqual([]);
    expect(scanSource(COMPONENTS_CSS, 'a { border-radius: 1px; }')).toEqual([]);
    expect(scanSource('src/x.css', 'a { border-radius: 1px; }')).not.toEqual([]);
  });
});
