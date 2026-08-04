// Post-build step (chained onto `npm run build` — see package.json) that
// hash-pins nginx.conf.template's CSP header to match the sha256 hashes
// Astro's native `security.csp` (astro.config.mjs) computed for the inline
// scripts/styles it actually shipped in dist/**/*.html.
//
// Astro's own build already injects a <meta http-equiv="content-security-
// policy"> tag per page with the hashes it knows about (its bundled/
// processed scripts and styles, plus the one manual hash astro.config.mjs
// supplies for the is:inline splash CSS Astro's pipeline never sees). This
// script:
//   1. Reads those per-page meta tags and takes the union of their
//      script-src/style-src hashes.
//   2. Independently re-hashes every literal inline <script>/<style> left in
//      dist/**/*.html and checks each one is covered by a hash from step 1 —
//      a hard stop if anything inline shipped without a matching hash,
//      rather than silently falling back to 'unsafe-inline'.
//   3. Substitutes that hash union into nginx.conf.template's
//      __ASTRO_CSP_SCRIPT_SRC__ / __ASTRO_CSP_STYLE_SRC__ placeholders and
//      writes the result to nginx.conf.generated (gitignored — Containerfile.
//      portal copies it from the builder stage instead of the checked-in
//      template, see #33).
//
// Any failure here throws and exits non-zero, failing `npm run build` (and
// therefore `pixi run -e portal build` / CI) loudly rather than shipping a
// CSP that's silently wrong.

import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { glob } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { JSDOM } from 'jsdom';

// Resolved lazily inside main() rather than at module scope: this module is
// imported directly by scripts/__tests__/sync-csp-hashes.test.ts to exercise
// the pure functions below in isolation, and vitest's module runner doesn't
// guarantee import.meta.url is a `file:` URL that `new URL('..', ...)` can
// resolve against.
function resolvePaths() {
  return {
    portalRoot: fileURLToPath(new URL('..', import.meta.url)),
    distDir: new URL('../dist/', import.meta.url),
    templatePath: new URL('../nginx.conf.template', import.meta.url),
    generatedPath: new URL('../nginx.conf.generated', import.meta.url),
  };
}

const CSP_META_SELECTOR = 'meta[http-equiv="content-security-policy" i]';

function sha256Base64(text) {
  return 'sha256-' + createHash('sha256').update(text, 'utf8').digest('base64');
}

/**
 * Parses the script-src/style-src hash tokens (e.g. "sha256-abc...=") out of
 * an Astro-generated CSP meta tag's `content` attribute.
 *
 * Throws if `html` has no CSP meta tag — that means `security.csp` in
 * astro.config.mjs didn't fire for this page, which should be impossible
 * for a successful Astro build, so treat it as a hard build error rather
 * than quietly skipping the page.
 */
export function extractDeclaredHashes(html, sourceLabel) {
  const dom = new JSDOM(html);
  const meta = dom.window.document.querySelector(CSP_META_SELECTOR);
  if (!meta) {
    throw new Error(
      `${sourceLabel}: no Content-Security-Policy <meta> tag found. ` +
        'Is security.csp still enabled in astro.config.mjs?',
    );
  }
  const content = meta.getAttribute('content') ?? '';
  const scriptMatch = content.match(/script-src([^;]*);/);
  const styleMatch = content.match(/style-src([^;]*);/);
  if (!scriptMatch || !styleMatch) {
    throw new Error(
      `${sourceLabel}: CSP <meta> tag is missing a script-src or style-src directive ` +
        `(content="${content}").`,
    );
  }
  const hashesOf = (directiveBody) =>
    new Set([...directiveBody.matchAll(/'(sha256-[^']+)'/g)].map((m) => m[1]));
  return { scriptSrc: hashesOf(scriptMatch[1]), styleSrc: hashesOf(styleMatch[1]) };
}

/**
 * Re-hashes every literal inline <script> (no `src`) and <style> element in
 * `html` and returns the ones whose hash isn't present in `declared`. An
 * empty return value means every inline script/style in the page is
 * accounted for by a CSP hash — a non-empty one means something would be
 * silently blocked (or would have required 'unsafe-inline') in production.
 */
export function findUnaccountedInline(html, declared, sourceLabel) {
  const dom = new JSDOM(html);
  const doc = dom.window.document;
  const problems = [];

  for (const el of doc.querySelectorAll('script:not([src])')) {
    const hash = sha256Base64(el.textContent);
    if (!declared.scriptSrc.has(hash)) {
      problems.push({ sourceLabel, tag: 'script', hash, preview: el.textContent.slice(0, 80) });
    }
  }
  for (const el of doc.querySelectorAll('style')) {
    const hash = sha256Base64(el.textContent);
    if (!declared.styleSrc.has(hash)) {
      problems.push({ sourceLabel, tag: 'style', hash, preview: el.textContent.slice(0, 80) });
    }
  }
  return problems;
}

/**
 * Renders a CSP directive's hash list (sorted for a deterministic diff).
 * nginx.conf.template already supplies 'self' around the
 * __ASTRO_CSP_*_SRC__ placeholder — this renders only the hashes.
 */
export function renderDirectiveValue(hashes) {
  return [...hashes]
    .sort()
    .map((h) => `'${h}'`)
    .join(' ');
}

/**
 * Substitutes __ASTRO_CSP_SCRIPT_SRC__ / __ASTRO_CSP_STYLE_SRC__ in
 * `templateSource` with the given rendered directive values. Throws if a
 * placeholder isn't found — a renamed or removed placeholder must be a
 * build failure, not a silent no-op that ships the literal placeholder text
 * (or worse, leaves 'unsafe-inline' in place) to nginx.
 */
export function patchTemplate(templateSource, { scriptValue, styleValue }) {
  const substitutions = [
    ['__ASTRO_CSP_SCRIPT_SRC__', scriptValue],
    ['__ASTRO_CSP_STYLE_SRC__', styleValue],
  ];
  let patched = templateSource;
  for (const [placeholder, value] of substitutions) {
    if (!patched.includes(placeholder)) {
      throw new Error(
        `nginx.conf.template: placeholder ${placeholder} not found — ` +
          'has the CSP header line been edited without updating this script?',
      );
    }
    patched = patched.replaceAll(placeholder, value);
  }
  return patched;
}

async function main() {
  const { portalRoot, distDir, templatePath, generatedPath } = resolvePaths();

  const htmlFiles = [];
  for await (const entry of glob('**/*.html', { cwd: distDir })) {
    htmlFiles.push(entry);
  }
  if (htmlFiles.length === 0) {
    throw new Error(
      `No .html files found under ${fileURLToPath(distDir)} — did astro build run first?`,
    );
  }

  const scriptHashes = new Set();
  const styleHashes = new Set();
  const unaccounted = [];

  for (const relativePath of htmlFiles) {
    const fileUrl = new URL(relativePath, distDir);
    const html = readFileSync(fileUrl, 'utf8');
    const sourceLabel = `dist/${relativePath}`;

    const declared = extractDeclaredHashes(html, sourceLabel);
    for (const h of declared.scriptSrc) scriptHashes.add(h);
    for (const h of declared.styleSrc) styleHashes.add(h);

    unaccounted.push(...findUnaccountedInline(html, declared, sourceLabel));
  }

  if (unaccounted.length > 0) {
    const details = unaccounted
      .map((p) => `  - ${p.sourceLabel}: inline <${p.tag}> (${p.hash}) "${p.preview}..."`)
      .join('\n');
    throw new Error(
      'sync-csp-hashes: found inline script/style content with no matching CSP hash ' +
        '(Astro-generated or manually supplied in astro.config.mjs):\n' +
        `${details}\n` +
        "Refusing to fall back to 'unsafe-inline' — add a hash for this content " +
        '(security.csp.scriptDirective/styleDirective.hashes in astro.config.mjs) ' +
        'or investigate why Astro did not hash it.',
    );
  }

  const templateSource = readFileSync(templatePath, 'utf8');
  const patched = patchTemplate(templateSource, {
    scriptValue: renderDirectiveValue(scriptHashes),
    styleValue: renderDirectiveValue(styleHashes),
  });
  writeFileSync(generatedPath, patched);

  console.log(
    `sync-csp-hashes: wrote ${fileURLToPath(generatedPath).replace(portalRoot, '')} ` +
      `(${scriptHashes.size} script-src hash(es), ${styleHashes.size} style-src hash(es), ` +
      `verified against ${htmlFiles.length} page(s), no 'unsafe-inline').`,
  );
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main().catch((err) => {
    console.error(err.message);
    process.exitCode = 1;
  });
}
