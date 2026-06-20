export default {
  content: ['./src/**/*.{astro,html,js,jsx,md,mdx,svelte,ts,tsx,vue}'],
  theme: {
    extend: {
      colors: {
        // Ground palette — drawn from detector visualization: the void of a
        // collision event display and the Cherenkov radiation track spectrum.
        'af-void':    '#0A0E1A',   // near-black ground
        'af-surface': '#111827',   // elevated surface (cards, panels)
        'af-border':  '#1F2937',   // structural dividers
        'af-muted':   '#374151',   // muted borders and disabled states
        'af-dim':     '#6B7280',   // secondary text, labels
        'af-text':    '#E8ECF0',   // primary text
        'af-teal':    '#00D4C8',   // Cherenkov accent — primary action
        'af-amber':   '#F59E0B',   // calorimeter heat — warnings, state-change
        'af-red':     '#EF4444',   // error, revoke
        'af-green':   '#10B981',   // active/healthy status
      },
      fontFamily: {
        mono:  ['IBM Plex Mono', 'JetBrains Mono', 'Fira Code', 'ui-monospace', 'monospace'],
        sans:  ['IBM Plex Sans', 'Inter', 'system-ui', 'sans-serif'],
      },
      fontSize: {
        'display': ['3.5rem',  { lineHeight: '1.05', letterSpacing: '0.04em', fontWeight: '700' }],
        'h1':      ['2.25rem', { lineHeight: '1.1',  letterSpacing: '0.03em', fontWeight: '700' }],
        'h2':      ['1.5rem',  { lineHeight: '1.2',  letterSpacing: '0.02em', fontWeight: '600' }],
        'h3':      ['1.125rem',{ lineHeight: '1.3',  letterSpacing: '0.02em', fontWeight: '600' }],
        'label':   ['0.6875rem',{ lineHeight: '1',   letterSpacing: '0.1em',  fontWeight: '600' }],
      },
    },
  },
  plugins: [
    require('@tailwindcss/forms'),
    require('@tailwindcss/typography'),
  ],
};
