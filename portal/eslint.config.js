// Flat ESLint config (eslint 9+).
// Keep this minimal — the point is `astro check` catches types; ESLint here
// just enforces baseline Astro/JS lint rules on the portal source.
import eslintPluginAstro from 'eslint-plugin-astro';
import eslintPluginVuejsAccessibility from 'eslint-plugin-vuejs-accessibility';
import typescriptEslintParser from '@typescript-eslint/parser';

export default [
  ...eslintPluginAstro.configs.recommended,
  ...eslintPluginVuejsAccessibility.configs['flat/recommended'],
  {
    // .vue SFCs here use `<script setup lang="ts">`; vue-eslint-parser needs
    // to be told to hand script blocks off to the TS parser.
    files: ['**/*.vue'],
    languageOptions: {
      parserOptions: {
        parser: typescriptEslintParser,
      },
    },
    rules: {
      // The plugin's default requires a label to satisfy BOTH nesting and
      // for/id association (`required: { every: [...] }`), which no real
      // markup does — you either nest the control or pair it via for/id, not
      // both. That default flagged every correctly-labelled control in this
      // codebase. Requiring just one of the two (matching jsx-a11y's
      // equivalent rule) still catches genuinely unassociated labels.
      'vuejs-accessibility/label-has-for': ['error', { required: { some: ['nesting', 'id'] } }],
    },
  },
  {
    ignores: ['dist/**', 'node_modules/**', '.astro/**'],
  },
];
