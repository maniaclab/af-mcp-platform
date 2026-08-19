import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
  extractDeclaredHashes,
  findUnaccountedInline,
  isCspExemptStub,
  patchTemplate,
  renderDirectiveValue,
} from '../sync-csp-hashes.mjs';

function page(cspContent: string, body: string) {
  return `<!doctype html><html><head><meta http-equiv="content-security-policy" content="${cspContent}"></head><body>${body}</body></html>`;
}

describe('extractDeclaredHashes', () => {
  it('parses the script-src and style-src hashes out of the CSP meta tag', () => {
    const html = page(
      "script-src 'self' 'sha256-aaa='; style-src 'self' 'sha256-bbb=' 'sha256-ccc=';",
      '',
    );
    const declared = extractDeclaredHashes(html, 'test.html');
    expect(declared.scriptSrc).toEqual(new Set(['sha256-aaa=']));
    expect(declared.styleSrc).toEqual(new Set(['sha256-bbb=', 'sha256-ccc=']));
  });

  it('throws when the page has no CSP meta tag', () => {
    const html = '<!doctype html><html><head></head><body></body></html>';
    expect(() => extractDeclaredHashes(html, 'test.html')).toThrow(/no Content-Security-Policy/);
  });

  it('throws when the CSP meta tag is missing script-src or style-src', () => {
    const html = page("default-src 'self';", '');
    expect(() => extractDeclaredHashes(html, 'test.html')).toThrow(
      /missing a script-src or style-src/,
    );
  });
});

describe('isCspExemptStub', () => {
  it('exempts an Astro-generated redirect stub (no CSP meta, no inline content)', () => {
    // The literal shape `astro build` emits for a config `redirects` entry.
    const stub =
      '<!doctype html><title>Redirecting to: /identities/</title>' +
      '<meta http-equiv="refresh" content="0;url=/identities/">' +
      '<meta name="robots" content="noindex"><link rel="canonical" href="/identities/">' +
      '<body><a href="/identities/">Redirecting</a></body>';
    expect(isCspExemptStub(stub)).toBe(true);
  });

  it('does not exempt a page that carries a CSP meta tag', () => {
    expect(isCspExemptStub(page("script-src 'self'; style-src 'self';", ''))).toBe(false);
  });

  it('does not exempt a CSP-less page with an inline script', () => {
    const html = '<!doctype html><body><script>alert(1)</scr' + 'ipt></body>';
    expect(isCspExemptStub(html)).toBe(false);
  });

  it('does not exempt a CSP-less page with an inline style', () => {
    const html = '<!doctype html><head><style>body{}</style></head><body></body>';
    expect(isCspExemptStub(html)).toBe(false);
  });
});

describe('findUnaccountedInline', () => {
  it('returns no problems when every inline script and style is hashed', () => {
    // sha256("console.log(1)") base64, computed independently below via the
    // same algorithm the module under test uses.
    const inlineScript = 'console.log(1)';
    const inlineStyle = 'body{color:red}';
    const declared = extractDeclaredHashes(
      page(
        `script-src 'self' '${hashOf(inlineScript)}'; style-src 'self' '${hashOf(inlineStyle)}';`,
        '',
      ),
      'test.html',
    );
    const html = page(
      `script-src 'self' '${hashOf(inlineScript)}'; style-src 'self' '${hashOf(inlineStyle)}';`,
      `<script>${inlineScript}</script><style>${inlineStyle}</style>`,
    );
    expect(findUnaccountedInline(html, declared, 'test.html')).toEqual([]);
  });

  it("ignores external scripts (src attribute) — those are governed by 'self', not a hash", () => {
    const declared = { scriptSrc: new Set<string>(), styleSrc: new Set<string>() };
    const html = page('', '<script src="/app.js"></script>');
    expect(findUnaccountedInline(html, declared, 'test.html')).toEqual([]);
  });

  it('reports an inline script whose hash is not in the declared set', () => {
    const declared = { scriptSrc: new Set<string>(), styleSrc: new Set<string>() };
    const html = page('', '<script>alert(1)</script>');
    const problems = findUnaccountedInline(html, declared, 'test.html');
    expect(problems).toHaveLength(1);
    expect(problems[0]).toMatchObject({ sourceLabel: 'test.html', tag: 'script' });
  });

  it('reports an inline style whose hash is not in the declared set', () => {
    const declared = { scriptSrc: new Set<string>(), styleSrc: new Set<string>() };
    const html = page('', '<style>body{color:blue}</style>');
    const problems = findUnaccountedInline(html, declared, 'test.html');
    expect(problems).toHaveLength(1);
    expect(problems[0]).toMatchObject({ sourceLabel: 'test.html', tag: 'style' });
  });
});

describe('renderDirectiveValue', () => {
  it('quotes each hash and sorts them for a deterministic diff', () => {
    expect(renderDirectiveValue(new Set(['sha256-bbb=', 'sha256-aaa=']))).toBe(
      "'sha256-aaa=' 'sha256-bbb='",
    );
  });

  it('renders an empty string for an empty hash set', () => {
    expect(renderDirectiveValue(new Set())).toBe('');
  });
});

describe('patchTemplate', () => {
  it('substitutes both CSP placeholders', () => {
    const template =
      "script-src 'self' __ASTRO_CSP_SCRIPT_SRC__; style-src 'self' __ASTRO_CSP_STYLE_SRC__;";
    const patched = patchTemplate(template, {
      scriptValue: "'sha256-aaa='",
      styleValue: "'sha256-bbb='",
    });
    expect(patched).toBe("script-src 'self' 'sha256-aaa='; style-src 'self' 'sha256-bbb=';");
  });

  it('throws rather than silently no-op when a placeholder is missing', () => {
    expect(() =>
      patchTemplate("script-src 'self' 'unsafe-inline';", {
        scriptValue: "'sha256-aaa='",
        styleValue: "'sha256-bbb='",
      }),
    ).toThrow(/placeholder __ASTRO_CSP_SCRIPT_SRC__ not found/);
  });
});

describe('nginx.conf.template regression fence', () => {
  // Read relative to cwd (vitest runs with cwd `portal/`, same as `npm test`)
  // rather than via `import.meta.url` — under vitest's module runner that's
  // not reliably a `file:` URL `new URL()` can resolve a relative path
  // against (see the resolvePaths() comment in ../sync-csp-hashes.mjs).
  const template = readFileSync('nginx.conf.template', 'utf8');

  it("never puts 'unsafe-inline' in either add_header Content-Security-Policy line", () => {
    const cspLines = template.match(/^\s*add_header Content-Security-Policy .*$/gm) ?? [];
    expect(cspLines).toHaveLength(2);
    for (const line of cspLines) {
      expect(line).not.toContain('unsafe-inline');
    }
  });

  it('carries both CSP hash placeholders in each add_header Content-Security-Policy line', () => {
    const cspLines = template.match(/^\s*add_header Content-Security-Policy .*$/gm) ?? [];
    expect(cspLines).toHaveLength(2);
    for (const line of cspLines) {
      expect(line).toContain('__ASTRO_CSP_SCRIPT_SRC__');
      expect(line).toContain('__ASTRO_CSP_STYLE_SRC__');
    }
  });
});

// Mirrors sync-csp-hashes.mjs's own sha256Base64 helper (kept local rather
// than exported — it's an implementation detail, not part of the module's
// public surface) so fixtures above can construct a matching declared hash.
function hashOf(text: string): string {
  return `sha256-${createHash('sha256').update(text, 'utf8').digest('base64')}`;
}
