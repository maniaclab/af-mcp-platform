// Prettier config for the Astro/Vue portal.
// Register the Astro parser plugin plus the Tailwind class-sort plugin so
// utility classes stay in a deterministic order across the codebase.
export default {
  semi: true,
  singleQuote: true,
  trailingComma: 'all',
  printWidth: 100,
  plugins: ['prettier-plugin-astro', 'prettier-plugin-tailwindcss'],
  overrides: [
    {
      files: '*.astro',
      options: { parser: 'astro' },
    },
  ],
};
