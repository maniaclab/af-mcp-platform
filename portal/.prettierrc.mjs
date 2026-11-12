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
    {
      // Astro's compiler trims the whitespace at a line break between text and
      // an inline element ("is\n<b>" renders "is<b>"), so these prose-heavy
      // sections are formatted without wrapping: each run of text and inline
      // elements stays on one line and keeps its spaces.
      files: 'src/components/design/sections/*.astro',
      options: { printWidth: 1000 },
    },
  ],
};
