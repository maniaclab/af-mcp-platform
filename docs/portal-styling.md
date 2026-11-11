# Portal styling: how it is built

This page explains how the portal's styling is wired. What the portal should
look like, and why, is in `DESIGN.md` at the repository root; the worked
reference with rendered examples is
[the design language page](design-language/index.html). Everything here is
about `portal/`.

## Where things live

| File | What it holds |
| --- | --- |
| `portal/src/styles/global.css` | The Tailwind v4 entrypoint and the only place token values are defined: colours, shadows, fonts, type scale and radii in `@theme`; spacing, control heights and motion in `:root`; dark overrides in `.dark`. |
| `portal/src/styles/components.css` | The shared `af-` component classes, in `@layer components`. They use only tokens. |
| `portal/src/components/ui/` | Shared Vue components built on those classes (`StatusMark`, `CopyField`, `ConfirmDialog`, `AsyncState`, ...). |
| `portal/src/components/Fonts.astro` | The `@font-face` rules. |
| `portal/src/lib/theme.ts`, `themeInitScript.js` | Theme resolution, persistence and the pre-paint bootstrap. |
| `portal/src/lib/accent.ts` | The optional facility accent. |

## Tokens

Tailwind 4 is CSS-first; there is no `tailwind.config`. A token declared in the
`@theme` block becomes both a utility class (`--color-af-border` gives
`border-af-border`, `text-af-text`, ...) and a CSS custom property, so scoped
`<style>` blocks in `.vue` and `.astro` files use `var(--color-af-border)`.

Spacing (`--space-*`), control heights (`--control-*`) and motion (`--time-*`,
`--ease`) are plain `:root` custom properties rather than `@theme` entries: they
are consumed through `var()`, not as utilities.

### Adding a token

1. Add the light value to the `@theme` block in `global.css` (or to `:root` for
   a spacing, control or motion token).
2. If it is a colour or shadow that differs in dark, add the dark value to the
   `.dark` block in the same change. A token that is the same in both themes
   (the banner fills) is not repeated there.
3. If it is a text, status or banner colour, add it to the lists in
   `portal/src/lib/__tests__/globalCssContrast.test.ts` so its contrast is
   checked.
4. If the design contract test restricts the property (type sizes and radii
   are matched by name pattern), check that
   `portal/src/lib/__tests__/designContract.test.ts` accepts the new name.
5. Record the token in `DESIGN.md`.

Literal colours are allowed only in `global.css`. Elsewhere use the token,
`rgb(from var(--color-af-*) r g b / a)`, or
`color-mix(in srgb, var(--color-af-*) N%, var(--color-af-bg))`.

## Light and dark themes

The `@theme` block holds the light values as the unconditional default. A
`.dark { ... }` block holds the dark overrides for the same custom properties.
It is **unlayered**: `@theme` compiles into a `@layer`, and an unlayered rule
beats any layered rule regardless of specificity or source order. Because every
`var(--color-af-*)` reference re-resolves against the cascade, adding or
removing `.dark` on `<html>` is the only thing that changes.

`.dark` must be on `<html>` and nowhere else. Basecoat's stylesheet declares
`@custom-variant dark (&:is(html.dark *))`, so the AF tokens and any `dark:`
utility key off the same class in the same place.

Two pieces of code toggle that class:

- `portal/src/lib/theme.ts` owns the logic and is unit-tested. It resolves the
  mode (`auto`, `dark`, `light`) against `prefers-color-scheme`, toggles
  `.dark`, sets `color-scheme` on the root so native controls follow, and
  dispatches an `af-themechange` event on the root. In `auto` it follows a live
  change of the system preference.
- `portal/src/lib/themeInitScript.js` is the bootstrap that prevents a flash of
  the wrong theme. It runs inline in `<head>` before any stylesheet, in both
  `Base.astro` and `PublicBase.astro`. It has to run synchronously, and an ES
  module script is deferred, so it cannot import `theme.ts`; it duplicates the
  small resolve-and-apply slice by hand. Any change to `resolveTheme()` or
  `applyResolvedTheme()` must be mirrored there.

The choice is stored in `localStorage` under `themeMode`. `auto` is stored as
the **absence** of the key, not as a literal value. `localStorage` rather than
the `sessionStorage` used for tokens in `auth.ts`: a theme preference is not a
secret, and `sessionStorage` would lose it in every new tab.

The control is `portal/src/components/ThemeToggle.astro`, a three-option
`role="radiogroup"` (Auto, Dark, Light) with its own script. It is rendered at
the foot of the sidebar in `Base.astro` and in the top bar of
`PublicBase.astro`.

### The particle-track canvas

A canvas cannot resolve CSS custom properties in `fillStyle` or `strokeStyle`.
`portal/src/lib/particleTracks.ts` therefore reads the resolved
`--af-canvas-*` values from `global.css` ("R G B" channel triplets, plus an
alpha floor and span per theme) and composes `rgb(<triplet> / alpha)` strings
at draw time. A `MutationObserver` on the root's `class` attribute re-reads
them when the theme changes. Under `prefers-reduced-motion` it draws one static
frame.

### The gateway diagram

`portal/src/lib/gatewayPulse.ts` drives the landing page diagram with a GSAP
timeline. Box highlights are a CSS class (`is-pulse-active`) with a CSS
transition rather than a JS tween. The loop is skipped under
`prefers-reduced-motion` and plays only while on screen (GSAP ScrollTrigger).

## The facility accent

The default accent is ink, defined in `global.css` as `--color-af-accent` and
`--color-af-on-accent` for each theme. A deployment opts in to its own colour
through the Helm values:

```yaml
portal:
  branding:
    accentColor: "#800000"   # "#rrggbb"; empty keeps the ink default
    accentColorDark: ""      # optional; empty derives it from accentColor
```

The chart writes both into the `branding` block of `/config.json`
(`charts/af-mcp-platform/templates/configmap-portal-config.yaml`). At runtime
`Footer.astro`, which every layout renders, loads that block and calls
`watchAccent()` from `portal/src/lib/accent.ts`, which:

- ignores a value that is not a `#rrggbb` hex, with a `console.warn`;
- in light, uses `accentColor` as given;
- in dark, uses `accentColorDark` if set, otherwise mixes `accentColor` toward
  white in 10% steps (at most 20) until it reaches 3:1 against the dark page
  background (`#0f0f10`);
- picks on-accent text: white if white reaches 4.5:1 against the accent,
  otherwise `#0a0a0a`;
- writes `--color-af-accent` and `--color-af-on-accent` as inline properties on
  `<html>`, and re-applies them on every `af-themechange` event.

With nothing configured no inline property is written and the stylesheet
defaults apply. The light-theme colour is not adjusted: the accent is only ever
a fill or the nav marker, never text, so its contrast against the page is not
load-bearing for reading.

The derivation mirrors `applyAccent` in the design language page, which lets
you try a colour before configuring it.

## Fonts

IBM Plex Sans (400, 500, 600) and IBM Plex Mono (400, 500) are self-hosted as
`woff2` files in `portal/public/fonts/`, declared in `Fonts.astro` with
`font-display: swap`. Self-hosting is required by the Content Security Policy
(`default-src 'self'`), which does not allow a font CDN. `--font-sans` and
`--font-mono` in `global.css` name those families with system fallbacks.

## Icons

Icons are Lucide, imported from `@lucide/vue` in `.vue` files and
`@lucide/astro` in `.astro` files; both are pinned in `portal/package.json`.
To add one:

```vue
<script setup lang="ts">
import { Copy } from '@lucide/vue';
</script>

<template>
  <Copy class="af-icon" :size="16" aria-hidden="true" />
</template>
```

The `af-icon` class fixes the size and stroke and lets the icon inherit the
text colour. Give an icon-only button an accessible name. Do not paste SVG
markup or type a glyph character: the contract test rejects glyphs such as
check marks and arrows.

## Content Security Policy and inline code

The portal ships a strict CSP with hashes rather than `'unsafe-inline'`.

- Astro's built-in CSP (`security.csp` in `portal/astro.config.mjs`) hashes the
  scripts and styles it bundles.
- Two blocks are `is:inline`, which opts them out of Astro's pipeline, so
  `astro.config.mjs` hashes them itself: the auth-splash `<style is:inline>` in
  `Base.astro` (it must be present before the bundled stylesheet loads) and the
  theme bootstrap script (hashed straight from the `THEME_INIT_SCRIPT`
  constant).
- `portal/scripts/sync-csp-hashes.mjs` runs after `astro build`. It re-hashes
  every inline script and style left in `dist/**/*.html`, fails the build if
  one is not covered by a declared hash, and writes the hash union into the
  nginx CSP header (`nginx.conf.generated`).

Consequences for styling: put styles in a component `<style>` block or in the
shared stylesheets, not in a new `is:inline` block, unless you also add its
hash. The runtime accent is applied with `style.setProperty` from script, not
as inline markup.

## Tooltips

`portal/src/components/PopoverTooltip.vue` is built on the native Popover API
(`popover="hint"`, shown and hidden from script). A shown popover is promoted
to the browser's top layer, so it is not clipped by an ancestor with
`overflow: hidden` or `auto` and does not add to that ancestor's scrollable
overflow. `InfoTip.vue` wraps it for the icon-only "more information" button.

- **Positioning.** The bubble is `position: fixed`, placed from
  `getBoundingClientRect()` when shown (`portal/src/lib/tooltipPosition.ts`).
  It clamps to the viewport and flips to the opposite side when the requested
  side has no room. CSS anchor positioning is not used.
- **Accessibility.** A closed popover computes to `display: none`, so
  `aria-describedby` cannot point at it. Each tooltip's text also lives in a
  separate, always-present `sr-only` span with `role="tooltip"`, and the
  trigger points at that.
- **Show and hide.** The Popover API has no declarative hover trigger, so the
  component tracks hover and focus separately and shows while either holds. It
  releases focus on click so a mouse click does not leave the bubble open.

`sr-only` is Tailwind's own utility; the portal does not define its own.

## Dialogs

Dialogs are native `<dialog>` elements opened with `showModal()`, which
supplies the focus trap, the inert page behind and Escape to close.
Tailwind's Preflight resets `margin: 0` on every element, which also removes
the `margin: auto` that centres a modal dialog. `global.css` restores it once
with an unlayered `dialog:modal { margin: auto; }` rule instead of patching
each dialog.

The `af-dialog` class sets `display: flex`, which would override the browser's
`display: none` on a closed dialog, so `components.css` re-hides
`dialog.af-dialog:not([open])`. For the same reason one rule re-applies
`display: none` to every `af-` class that sets `display` when it carries the
`hidden` attribute.

## Basecoat

`global.css` imports `basecoat-css`, and a `:root` block (the "Basecoat
bridge") sets Basecoat's variable set (`--background`, `--foreground`,
`--card`, `--popover`, `--border`, `--input`, `--ring`, `--primary`,
`--primary-foreground`, `--muted-foreground`, `--destructive`, and `--radius`
at `8px`) from the AF tokens. The bridge is one-directional: AF tokens are the
source of truth, and every bridged value is a `var()` reference, so it follows
the theme without being repeated under `.dark`.

As the code stands, no Basecoat component class or `data-` attribute is used
anywhere in `portal/src`. What the import still contributes is Basecoat's base
layer (its universal border and ring reset and its `body` colours, which read
the bridged variables) and the `dark` custom variant described above. The
`themeMode` storage key also matches the convention of Basecoat's own theme
helper. The `af-` prefix on the shared classes exists so they cannot collide
with Basecoat's `.btn`, `.badge` and similar names.

## Contrast checks

`portal/src/lib/__tests__/globalCssContrast.test.ts` parses the `@theme` and
`.dark` blocks straight out of `global.css` (dark falls back to light for any
token it does not override) and asserts, in both themes:

| Pair | Minimum |
| --- | --- |
| `af-text`, `af-text-secondary`, `af-bad-text` on `af-bg` and on `af-bg-subtle` | 4.5:1 |
| `af-on-accent` on `af-accent` | 4.5:1 |
| `af-on-banner-*` on its `af-banner-*` fill | 4.5:1 |
| `af-ok`, `af-warn`, `af-bad`, `af-info` on `af-bg` | 3:1 |

It checks the stylesheet defaults. A facility accent is not covered by it; the
derivation in `accent.ts` (tested in `accent.test.ts`) keeps on-accent text at
4.5:1.

## The design contract test

`portal/src/lib/__tests__/designContract.test.ts` scans every `.vue`, `.astro`
and `.css` file under `portal/src` (comments stripped) and fails with the file,
line and fix for each of these:

| Rule | Rejects |
| --- | --- |
| `hex-colour`, `colour-function` | A literal colour outside `global.css`. |
| `alias-token` | The removed token names (`void`, `surface`, `muted`, `dim`, `label`, `teal`, `amber`, `red`, `green`, `panel-shadow`). |
| `font-size` | Anything other than `var(--text-*)` or `inherit`, including `text-[11px]` utilities. |
| `font-family` | Anything other than `var(--font-sans)`, `var(--font-mono)` or `inherit`. |
| `uppercase`, `letter-spacing` | `text-transform: uppercase`, the `uppercase` utility, `letter-spacing`, `tracking-*`. |
| `backdrop-filter` | Any background blur. |
| `box-shadow` | Anything other than `var(--shadow-af-1)`, `var(--shadow-af-2)`, `none` or an inset ring in a token colour. |
| `border-radius` | Anything other than `var(--radius-*)`, `0` or `50%` (`components.css` may also use `1px` and `2px` for the status-mark shapes). |
| `icon-glyph`, `arrow-glyph` | Text glyphs used as icons. |

A genuine exception goes in the test's `ALLOWLIST` with a reason. A second test
fails if an allowlist entry is no longer needed.

## Running the checks and the preview

```bash
pixi run -e portal test            # vitest, including both tests above
pixi run -e portal check           # format + lint + astro check + tests
pixi run -e portal design-preview  # build, then serve every page with example data
```

`design-preview` takes `--scenario healthy|problems`, `--port N` and
`--accent RRGGBB`; `?theme=light|dark` and `?accent=RRGGBB` work per request.
All of its data is fictional. To capture every page at desktop and phone widths
in both themes:

```bash
cd portal && node scripts/design-screenshots.mjs --out /tmp/design-shots
```

It needs a built portal and a headless Chromium (`--chrome`, `$CHROME_BIN` or
the Playwright cache). See [Local Development](local-development.md) for the
details.
