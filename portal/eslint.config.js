// Flat ESLint config (eslint 9+).
// Keep this minimal — the point is `astro check` catches types; ESLint here
// just enforces baseline Astro/JS lint rules on the portal source.
import eslintPluginAstro from 'eslint-plugin-astro';

export default [
  ...eslintPluginAstro.configs.recommended,
  {
    ignores: ['dist/**', 'node_modules/**', '.astro/**'],
  },
];
