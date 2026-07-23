import { defineConfig } from 'vitest/config';

// auth.ts (and Base.astro / callback.astro's inline scripts that call it)
// use browser globals (window.location, window.sessionStorage) — vitest
// defaults to a plain Node environment, which doesn't have those. jsdom
// gives the test suite a real-enough DOM/window without spinning up a
// browser.
export default defineConfig({
  test: {
    environment: 'jsdom',
  },
});
