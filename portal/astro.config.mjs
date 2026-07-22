import { defineConfig } from 'astro/config';
import vue from '@astrojs/vue';
import tailwindcss from '@tailwindcss/vite';

// `astro dev` proxies /v1/* to the broker on :8080 so the Vue islands can hit
// the real API in local dev. In production oauth2-proxy fronts both surfaces
// on the same origin; this proxy stands in for that during dev only.
// `astro preview` does not honour vite.server.proxy — use `astro dev` for
// interactive UI work with a running broker.
const BROKER_URL = process.env.PORTAL_DEV_BROKER_URL ?? 'http://localhost:8080';

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
  server: { port: 4321 },
});
