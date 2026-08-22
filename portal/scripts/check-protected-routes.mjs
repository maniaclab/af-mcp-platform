// Post-build step (chained onto `npm run build` — see package.json) that
// keeps portal/src/pages/*.astro's layout choice (Base.astro = needs a
// session, PublicBase.astro = public) in sync with the oauth2-proxy
// ForwardAuth path list in
// charts/af-mcp-platform/templates/ingress-portal-authenticated.yaml.
//
// That Ingress is the only thing standing between a `Base.astro` page and
// being served through the chart's public `/` catch-all instead — see the
// comment atop ingress-portal.yaml. A page added to portal/src/pages/ that
// imports Base.astro but never gets added to that Ingress's path list would
// silently lose its ForwardAuth gate; a stale entry left behind after a page
// is removed or renamed is dead weight pointing at nothing. Both are cheap
// mistakes to make and easy to miss in review, so this script turns the
// invariant into a build failure instead of a comment someone has to
// remember to honor.
//
// Any failure here throws and exits non-zero, failing `npm run build` (and
// therefore `pixi run -e portal build` / CI) loudly.

import { readFileSync } from 'node:fs';
import { glob } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

function resolvePaths() {
  return {
    pagesDir: new URL('../src/pages/', import.meta.url),
    ingressTemplatePath: new URL(
      '../../charts/af-mcp-platform/templates/ingress-portal-authenticated.yaml',
      import.meta.url,
    ),
  };
}

/**
 * Classifies an .astro page's source by which layout it imports.
 * Returns 'protected' (imports Base.astro — needs the ForwardAuth gate),
 * 'public' (imports PublicBase.astro — deliberately gate-free), or null if
 * it imports neither, which callers should treat as a hard error: every page
 * must make an explicit choice.
 */
export function classifyPageLayout(source) {
  if (/from\s+['"][./]*layouts\/PublicBase\.astro['"]/.test(source)) return 'public';
  if (/from\s+['"][./]*layouts\/Base\.astro['"]/.test(source)) return 'protected';
  return null;
}

/**
 * Maps an .astro page filename to the route Astro serves it at.
 * index.astro is the root route; everything else is /<basename>, matching
 * Astro's static file-based routing for this project's flat pages/ dir (no
 * nested page directories exist here).
 */
export function routeForPageFile(filename) {
  const base = filename.replace(/\.astro$/, '');
  return base === 'index' ? '/' : `/${base}`;
}

/**
 * Extracts the literal path strings out of ingress-portal-authenticated.yaml's
 * `{{- range list "/a" "/b" ... }}` line — the single source of truth for
 * which paths that Ingress protects.
 */
export function extractIngressProtectedPaths(templateSource) {
  const match = templateSource.match(/range list ((?:"[^"]*"\s*)+)}}/);
  if (!match) {
    throw new Error(
      'extractIngressProtectedPaths: no `range list` line found — ' +
        'has ingress-portal-authenticated.yaml been restructured?',
    );
  }
  return [...match[1].matchAll(/"([^"]*)"/g)].map((m) => m[1]);
}

/**
 * Compares the routes Astro marks as protected against the Ingress's path
 * list. `missingFromIngress` is a page that would silently fall through to
 * the public catch-all; `staleInIngress` is a path with no matching
 * protected Astro page left to protect.
 */
export function diffProtectedRoutes(astroProtectedRoutes, ingressPaths) {
  const astroSet = new Set(astroProtectedRoutes);
  const ingressSet = new Set(ingressPaths);
  return {
    missingFromIngress: astroProtectedRoutes.filter((r) => !ingressSet.has(r)),
    staleInIngress: ingressPaths.filter((p) => !astroSet.has(p)),
  };
}

async function main() {
  const { pagesDir, ingressTemplatePath } = resolvePaths();

  const pageFiles = [];
  for await (const entry of glob('*.astro', { cwd: pagesDir })) {
    pageFiles.push(entry);
  }
  if (pageFiles.length === 0) {
    throw new Error(`No .astro files found under ${fileURLToPath(pagesDir)}.`);
  }

  const uncategorized = [];
  const astroProtectedRoutes = [];
  for (const filename of pageFiles) {
    const source = readFileSync(new URL(filename, pagesDir), 'utf8');
    const layout = classifyPageLayout(source);
    if (layout === null) {
      uncategorized.push(filename);
    } else if (layout === 'protected') {
      astroProtectedRoutes.push(routeForPageFile(filename));
    }
  }
  if (uncategorized.length > 0) {
    throw new Error(
      'check-protected-routes: the following pages import neither Base.astro nor ' +
        `PublicBase.astro, so this script can't tell whether they need the ForwardAuth ` +
        `gate: ${uncategorized.join(', ')}`,
    );
  }

  const ingressTemplateSource = readFileSync(ingressTemplatePath, 'utf8');
  const ingressPaths = extractIngressProtectedPaths(ingressTemplateSource);

  const { missingFromIngress, staleInIngress } = diffProtectedRoutes(
    astroProtectedRoutes,
    ingressPaths,
  );
  if (missingFromIngress.length > 0 || staleInIngress.length > 0) {
    const lines = [];
    if (missingFromIngress.length > 0) {
      lines.push(
        `  - Base.astro page(s) missing from ingress-portal-authenticated.yaml's ` +
          `range list, so they'd fall through to the public catch-all: ${missingFromIngress.join(', ')}`,
      );
    }
    if (staleInIngress.length > 0) {
      lines.push(
        `  - path(s) in ingress-portal-authenticated.yaml's range list with no matching ` +
          `Base.astro page: ${staleInIngress.join(', ')}`,
      );
    }
    throw new Error(
      'check-protected-routes: portal pages and the Ingress protected-path list have drifted:\n' +
        lines.join('\n'),
    );
  }

  console.log(
    `check-protected-routes: ${astroProtectedRoutes.length} protected page(s) match ` +
      `ingress-portal-authenticated.yaml's path list.`,
  );
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main().catch((err) => {
    console.error(err.message);
    process.exitCode = 1;
  });
}
