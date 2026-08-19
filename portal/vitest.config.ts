import vue from '@vitejs/plugin-vue';
import { defineConfig } from 'vitest/config';

// auth.ts (and Base.astro / callback.astro's inline scripts that call it)
// use browser globals (window.location, window.sessionStorage) — vitest
// defaults to a plain Node environment, which doesn't have those. jsdom
// gives the test suite a real-enough DOM/window without spinning up a
// browser.
export default defineConfig({
  // The vue plugin compiles .vue SFCs for component tests (mounted with
  // @vue/test-utils); astro's own vue integration only wires it into the
  // site build, not vitest.
  plugins: [vue()],
  test: {
    environment: 'jsdom',
  },
});
