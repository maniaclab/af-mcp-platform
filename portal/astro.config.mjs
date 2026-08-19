import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { defineConfig } from 'astro/config';
import vue from '@astrojs/vue';
import tailwindcss from '@tailwindcss/vite';

// `astro dev` proxies /v1/* to the broker on :8080 so the Vue islands can hit
// the real API in local dev. In production oauth2-proxy fronts both surfaces
// on the same origin; this proxy stands in for that during dev only.
// `astro preview` does not honour vite.server.proxy — use `astro dev` for
// interactive UI work with a running broker.
const BROKER_URL = process.env.PORTAL_DEV_BROKER_URL ?? 'http://localhost:8080';

// Astro's built-in CSP (security.csp below) auto-hashes scripts/styles that
// it processes and bundles — but Base.astro's `<style is:inline>` splash CSS
// deliberately opts OUT of that pipeline (see the comment above that tag) so
// it's present the instant the element is parsed, before Astro's own
// bundled stylesheet link even starts fetching. Because Astro never
// processes that block, it can't hash it, so we hash it ourselves here and
// feed it in as an additional style-src hash. scripts/sync-csp-hashes.mjs
// (run as part of `npm run build`) verifies after every build that this
// stays in sync — it fails loudly if any inline script or style in the
// built output isn't covered by a hash Astro emitted or one supplied here.
const baseAstroSource = readFileSync(
  fileURLToPath(new URL('./src/layouts/Base.astro', import.meta.url)),
  'utf8',
);
const authSplashStyleMatch = baseAstroSource.match(/<style is:inline>([\s\S]*?)<\/style>/);
if (!authSplashStyleMatch) {
  throw new Error(
    'astro.config.mjs: expected a `<style is:inline>` block in src/layouts/Base.astro ' +
      'to hash for the CSP style-src directive, but none was found. If it was removed, ' +
      'drop this hash too; if it moved, update the regex above.',
  );
}
const authSplashStyleHash =
  'sha256-' + createHash('sha256').update(authSplashStyleMatch[1], 'utf8').digest('base64');

export default defineConfig({
  integrations: [vue()],
  vite: {
    plugins: [tailwindcss()],
    server: {
      proxy: {
        '/v1': { target: BROKER_URL, changeOrigin: true },
      },
    },
  },
  output: 'static',
  // The x509 credential status+link UI moved onto the Identities page card
  // (its single home) — keep old /status/ bookmarks working. Static output
  // turns this into a meta-refresh page at /status/index.html.
  redirects: { '/status': '/identities/' },
  server: { port: 4321 },
  security: {
    csp: {
      styleDirective: {
        hashes: [authSplashStyleHash],
      },
    },
  },
});
