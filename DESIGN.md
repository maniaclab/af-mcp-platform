---
name: AF MCP Platform Portal
description: Industrial detector-console UI for the credential-brokered MCP gateway
colors:
  af-void: "#0a0e1a"
  af-surface: "#111827"
  af-border: "#1f2937"
  af-muted: "#374151"
  af-dim: "#9ca3af"
  af-label: "#838d99"
  af-text: "#e8ecf0"
  af-teal: "#00d4c8"
  af-amber: "#f59e0b"
  af-red: "#ef4444"
  af-green: "#10b981"
typography:
  display:
    fontFamily: "IBM Plex Mono, JetBrains Mono, Fira Code, ui-monospace, monospace"
    fontSize: "3.5rem"
    fontWeight: 700
    lineHeight: 1.05
    letterSpacing: "0.04em"
  h1:
    fontFamily: "IBM Plex Mono, JetBrains Mono, Fira Code, ui-monospace, monospace"
    fontSize: "2.25rem"
    fontWeight: 700
    lineHeight: 1.1
    letterSpacing: "0.03em"
  h2:
    fontFamily: "IBM Plex Mono, JetBrains Mono, Fira Code, ui-monospace, monospace"
    fontSize: "1.5rem"
    fontWeight: 600
    lineHeight: 1.2
    letterSpacing: "0.02em"
  h3:
    fontFamily: "IBM Plex Mono, JetBrains Mono, Fira Code, ui-monospace, monospace"
    fontSize: "1.125rem"
    fontWeight: 600
    lineHeight: 1.3
    letterSpacing: "0.02em"
  body:
    fontFamily: "IBM Plex Sans, Inter, system-ui, sans-serif"
    fontSize: "0.9375rem"
    fontWeight: 400
    lineHeight: 1.6
  label:
    fontFamily: "IBM Plex Mono, JetBrains Mono, Fira Code, ui-monospace, monospace"
    fontSize: "0.6875rem"
    fontWeight: 600
    lineHeight: 1
    letterSpacing: "0.1em"
rounded:
  sm: "2px"
  md: "3px"
  lg: "4px"
  pill: "999px"
spacing:
  xs: "0.5rem"
  sm: "0.875rem"
  md: "1rem"
  lg: "1.75rem"
  xl: "2.5rem"
components:
  button-primary:
    backgroundColor: "transparent"
    textColor: "{colors.af-teal}"
    rounded: "{rounded.sm}"
    padding: "0.25rem 0.625rem"
  button-primary-hover:
    backgroundColor: "{colors.af-teal}"
  card:
    backgroundColor: "{colors.af-surface}"
    textColor: "{colors.af-text}"
    rounded: "{rounded.lg}"
---

# Design System: AF MCP Platform Portal

## Overview

**Creative North Star: "The Detector Console"**

The portal reads as a real-time instrument panel for a physics detector, not a
generic SaaS dashboard with ATLAS words dropped in. `global.css`'s own
comment states the ground palette is "drawn from detector visualization: the
void of a collision event display and the Cherenkov radiation track
spectrum" — the near-black void, the teal Cherenkov accent, and the amber
calorimeter-heat warning color are the palette's actual justification, not
retrofitted names. IBM Plex Mono carries every heading and label, IBM Plex
Sans carries body copy. Two moments of motion exist in the whole app, both
deliberate and both gated on `prefers-reduced-motion`: the Overview page's
particle-track canvas (golden-angle track spacing, quadratic-Bezier
"magnetic curvature," teal-for-Cherenkov/amber-for-calorimeter color
assignment, called out in its own code comment as "the aesthetic risk"),
and the public landing page's gateway-pulse diagram animation (a light
travels AI Assistant → Gateway → a backend, illustrating the credential-
brokering request flow the diagram already draws statically). Depth comes
from borders and flat surface layering, almost never shadows — this is a
console you read at a glance, not a card catalog you browse.

**Key Characteristics:**
- Near-black void ground, elevated surfaces one step lighter, borders (not shadows) doing the depth work
- IBM Plex Mono for every heading, label, and piece of identifying data (hostnames, tool names, token IDs); IBM Plex Sans for body prose
- Exactly two deliberate motion moments (the Overview hero canvas, the public landing page's gateway-pulse diagram); everything else is still
- Uppercase, letter-spaced mono labels as the "instrument panel" signature (section headings, badges, eyebrows)
- Teal is the only accent used for primary action; amber is reserved for "this changes state, use with care"; red is reserved for destructive/error
- Two themes, one instrument: DARK is the console's native mode, LIGHT is a cool blue-grey "blueprint paper" world sharing the same cold undertone — see **Theming** below

## Theming

**"The void becomes the ink."** DARK is the console's native look, described above. LIGHT is not an inversion of it — it's a cool blue-grey blueprint-paper page (`#e9edf2`) with white cards, where the near-black `af-void` that used to be the dark page's *ground* becomes `af-text`, the light page's *ink*. Same cold undertone in both, so the two themes read as one instrument under two lighting conditions, not two different apps.

Mechanism (see `portal/src/styles/global.css` for the full token tables and every measured contrast ratio): LIGHT is the unconditional default, matching Basecoat's own convention; a `.dark { ... }` block overrides the same custom properties, unlayered, so it wins the cascade regardless of specificity. `.dark` must land on `<html>` specifically — Basecoat's own `dark:` utilities key off `@custom-variant dark (&:is(html.dark *))`, so our AF tokens and Basecoat's dark-mode styling would desync if applied anywhere else. `src/lib/theme.ts` (the resolution/persistence logic, unit-tested) and `src/lib/themeInitScript.js` (the anti-flash-of-wrong-theme bootstrap that runs before any stylesheet, duplicated by necessity — see its own docstring) both toggle this same class.

**The control.** A three-state `AUTO / DARK / LIGHT` `role="radiogroup"` (`ThemeToggle.astro`) — not a single cycling button — in `Base.astro`'s topbar and, for the unauthenticated public pages with no chrome of their own, `Footer.astro` (behind a `showThemeToggle` prop). AUTO follows `prefers-color-scheme` live; DARK/LIGHT are explicit and persist in `localStorage` under the key `themeMode` (a deliberate departure from the sessionStorage-for-tokens rule in `auth.ts` — a theme preference isn't a secret, and sessionStorage would lose the choice on every new tab), with AUTO represented by the key's *absence* rather than a literal `"auto"` value so it stays compatible with Basecoat's own `window.basecoat.theme.*` fallback path.

**The particle-track canvas is not exempt.** It gets a real light rendering — ink tracks on paper, deepened teal/amber plus a slate ink in place of the dark theme's near-white, with a raised alpha floor since the dark-tuned value is invisible on a pale ground (`src/lib/particleTracks.ts`; canvas can't resolve CSS custom properties, so the module reads resolved `--af-canvas-*` channel triplets and re-reads them live via a `MutationObserver` on `<html>`'s class).

**The Basecoat bridge** (`portal/src/styles/global.css`) drives shadcn's variable set (`--background`, `--foreground`, `--border`, `--ring`, `--primary`, `--radius`, …) *from* the AF tokens above, one-directionally — AF stays the source of truth, and the bridge could be deleted without any AF token losing meaning. Only the variables this app currently exercises are bridged (Basecoat's base-layer border/ring reset, `body`'s background/foreground); `--muted`/`--accent`/`--secondary`/`--sidebar-*` are deliberately left at Basecoat's own defaults until a component-migration PR actually needs them against real content.

### Named Rules
**The Two-Themes-One-Cascade Rule.** A new color token is added to the `@theme` block (its LIGHT value) and to `.dark { }` (its DARK value) together, in the same change — never one without the other, and never a raw hex literal at a call site. `src/lib/__tests__/globalCssContrast.test.ts` parses both blocks straight out of `global.css` and re-checks AA for every text-bearing token in both themes.

## Colors

A near-monochrome void-and-surface base with exactly two accent colors, each with one job. Every token below exists in both themes — DARK values are what shipped originally; LIGHT values (added for the AUTO/DARK/LIGHT toggle — see **Theming**) are new. Ratios are WCAG 2.1 sRGB relative-luminance, re-verified by `src/lib/__tests__/globalCssContrast.test.ts` against both `af-surface` and `af-void`.

### Primary
- **Cherenkov Teal** — dark `#00d4c8` (10.32:1 on void), light `#046d66` (6.20:1 on card, 5.28:1 on page): the one primary-action color — copy buttons, links, focus rings, active status. Used sparingly; a screen with teal everywhere has stopped being an accent.

### Secondary
- **Calorimeter Amber** — dark `#f59e0b`, light `#92610a` (5.33:1 on card): reserved for "this is a state-changing / write action, use with care" — never used for anything else (not warnings-in-general, not "important," specifically state-change).

### Neutral
- **Void** — dark `#0a0e1a` (near-black), light `#e9edf2` (cool blue-grey "blueprint paper"): the page background.
- **Surface** — dark `#111827`, light `#ffffff`: one step up from void — cards, panels, table headers.
- **Border** — dark `#1f2937`, light `#cdd5df`: structural dividers between surfaces (non-text, 1.48:1 on card).
- **Muted** — dark `#374151`, light `#7d8a99`: borders and disabled states ONLY. **Never text** — it fails contrast (documented in the token comment itself, and the existing critique flagged four real violations of this rule). The light value clears the ≥3:1 WCAG 1.4.11 bar for a non-text form-control boundary (3.52:1 on card).
- **Dim** — dark `#9ca3af` (6.99:1 on surface, 7.58:1 on void), light `#4b5563` (7.56:1 on card, 6.43:1 on page): secondary text and labels, real AA-passing values in both themes.
- **Label** — dark `#838d99` (5.27:1 on surface), light `#5b6673` (5.84:1 on card, 4.97:1 on page): tertiary/eyebrow/uppercase-label text.
- **Text** — dark `#e8ecf0`, light `#0a0e1a` (19.25:1 on card): primary reading text — the light value is literally the dark theme's void, now the ink (see **Theming**).
- **On-accent** — dark `#0a0e1a`, light `#ffffff`: text/icon color over a filled teal/amber/red/green control.
- **Red** — dark `#ef4444`, light `#b91c1c` (6.47:1 on card): error and revoke actions only.
- **Green** — dark `#10b981`, light `#0a7350` (5.86:1 on card): active/healthy status only.
- **Scrim / panel shadow** — `rgb(0 0 0 / 0.5)` / `rgb(0 0 0 / 0.4)`, fixed in both themes (a backdrop dims what's behind it regardless of the app's own theme — Basecoat's own `.dialog::backdrop` does the same).

### Named Rules
**The Muted-Is-Never-Text Rule.** `af-muted` is a border/disabled-state token. If it's the color of anything a user reads, that's a bug, not a style choice — replace it with `af-dim` or `af-label`.

**The One Accent Rule.** Teal is the only color that means "click this" or "this is active/good." A screen reaching for a second accent color for emphasis should use weight, size, or the mono label treatment instead.

## Typography

**Display/Heading Font:** IBM Plex Mono (fallback: JetBrains Mono, Fira Code, ui-monospace, monospace)
**Body Font:** IBM Plex Sans (fallback: Inter, system-ui, sans-serif)

**Character:** Every heading, label, badge, and piece of identifying data (a hostname, a tool name, a token ID) is set in mono — that's the "instrument readout" signature. Body prose is the only sans-serif text in the app; the pairing reads as "the console labels the instruments, then explains them in plain language underneath."

### Hierarchy
- **Display** (700, 3.5rem, 1.05 line-height, 0.04em tracking, mono): the Overview hero title only.
- **H1** (700, 2.25rem, 1.1, 0.03em, mono): page titles.
- **H2** (600, 1.5rem, 1.2, 0.02em, mono): section headings.
- **H3** (600, 1.125rem, 1.3, 0.02em, mono): card/subsection headings.
- **Body** (400, 0.9375rem, 1.6, sans): prose, descriptions, help text.
- **Label** (600, 0.6875rem, 1, 0.1em tracking, uppercase, mono): eyebrows, badges, table headers, field labels.

### Named Rules
**The Mono-Means-Data Rule.** Mono type marks something the user might copy, match, or verify exactly (a hostname, an ID, a tool name) — or a UI label about that data. It is not a generic "technical feel" costume; body prose explaining what the data means stays in Plex Sans.

## Layout

Content lives in bounded-width columns (the Overview endpoint section caps at `52rem`) inside a persistent app shell (`Base.astro`): a top bar, a left-hand nav with permission badges, and a page-level `<main>`. Cards and panels use generous internal padding (`0.875rem`–`1.75rem`) with tight spacing between related elements and a clear gap before a new section — headings get more space above than below. Responsive behavior collapses at `640px` (mobile): hero height drops, heading sizes step down, `BackendCard.vue` hides secondary description/badge text below that width, and the Tokens table hides its Token ID/Created/Last used columns below that width rather than forcing horizontal scroll (the same pattern, applied last).

## Elevation & Depth

Flat by default. Depth comes from layering (void → surface → border), not shadows — the app has three real `box-shadow` uses in the entire codebase: a soft directional shadow on a slide-in panel, a teal focus-ring glow, and the gateway-pulse diagram's box-highlight glow. Everything else reads as flat surfaces separated by 1px borders (`af-border` for structure, `af-muted` for less emphasis).

### Shadow Vocabulary
- **Focus ring** (`box-shadow: 0 0 0 2px rgb(from var(--color-af-teal) r g b / 0.1–0.15)`): keyboard focus and active-input glow, always teal, always a ring not a blur.
- **Panel shadow** (`box-shadow: 4px 0 24px var(--color-af-panel-shadow)`): the one directional shadow, for a surface that overlays the page (e.g. a slide-out). Fixed black in both themes (see **Colors**).
- **Pulse highlight glow** (`box-shadow: 0 0 16px 2px rgb(from var(--color-af-teal) r g b / 0.3)`): the gateway-pulse animation's box highlight, teal, toggled via a CSS-transitioned class rather than a JS-driven tween.

### Named Rules
**The Borders-Not-Shadows Rule.** Reach for a 1px border (`af-border` or `af-muted`) to separate surfaces before reaching for a shadow. A shadow appears only for the two cases above — focus state, or a surface that's actually floating above the page.

## Shapes

Small, consistent radii — never fully rounded except true pills. Real observed scale: `2px` (badges, small controls — the most common value after the base card radius), `3px` (secondary controls), `4px` (cards, panels, buttons — the base/default radius), `6px` (rare, larger containers), `999px` (pill badges only). Borders are always `1px solid`, never thicker. No skeuomorphic gradients or bevels anywhere.

### Named Rules
**The Sharp-Not-Round Rule.** This is an instrument panel, not a soft consumer app. Default to `4px` for containers and `2px`–`3px` for small controls; reach for `999px` only for an actual pill-shaped status badge, never as a general "friendlier" rounding.

## Components

### Buttons
- **Shape:** `2px`–`4px` radius depending on size, `1px solid` border in the resting state for secondary buttons.
- **Primary:** transparent background, teal text/border at rest; fills teal (with dark text) on hover. Padding roughly `0.25rem 0.625rem` for compact controls, more generous for page-level CTAs.
- **Destructive (revoke/delete):** same shape language, red instead of teal.
- **Hover/Focus:** background fill transition (~150ms) plus the teal focus-ring glow on `:focus-visible`. Never an unstyled default outline.

### Cards / Panels
- **Corner style:** `4px` radius.
- **Background:** `af-surface`, on the `af-void` page background.
- **Border:** `1px solid af-border`.
- **Shadow:** none at rest (see Elevation).
- **Internal padding:** `0.875rem`–`1.75rem` depending on density.

### Badges
- **Style:** small pill or `2px`-radius rectangle, mono uppercase label text, color-coded by meaning (teal = read/active, amber = write/state-change, red = error/revoke, gray = neutral/info).
- **State:** badge meaning should be visible without relying on a hover-only `title` tooltip — this is a known outstanding gap (see the portal's own design critique), not the intended pattern.

### Tooltips
- **Mechanism:** `PopoverTooltip.vue`, built on the native Popover API (`popover="hint"`, `.showPopover()`/`.hidePopover()`) — **not** Basecoat's `data-tooltip`. That was tried first, but Basecoat's `[data-tooltip]::before` is a plain `position: absolute` pseudo-element anchored inside the trigger's own containing block; it doesn't escape an `overflow: hidden`/`auto` ancestor and still counts toward that ancestor's scrollable overflow while hidden — the exact bug it was adopted to fix. A `[popover]` element is promoted to the browser's top layer once shown, genuinely outside any ancestor's clipping — the same mechanism this app already relies on for `<dialog>`. `InfoTooltip.vue` (the original hand-rolled implementation) and, briefly, `data-tooltip` are both retired.
- **This is a deliberate, documented exception to the Basecoat-Class-First Rule below**, not a lapse back into hand-rolling everything — Basecoat doesn't ship a tooltip that covers this need, the same reason several IdentityCard components are already bespoke.
- **Positioning:** `position: fixed`, computed via `getBoundingClientRect()` at show-time (`src/lib/tooltipPosition.ts`), not CSS anchor positioning — anchor positioning's cross-browser support isn't yet something to build a core accessibility affordance on. Clamps to the viewport and flips to the opposite side when the requested one has no room, so a trigger near a table's last row no longer needs a manual per-row side override.
- **Accessibility:** a native `[popover]` computes to `display: none` while closed, so `aria-describedby` can't point at it directly — every trigger's description lives in a separate, always-present `sr-only` span instead. The component tracks hover and focus independently and shows while either holds (there's no declarative hover trigger for the Popover API), matching the old `:hover, :focus-within` OR semantics, and releases focus on click so a mouse click doesn't leave it stuck open.

### Theme toggle
- A three-button `role="radiogroup"` (`ThemeToggle.astro`) reading **AUTO / DARK / LIGHT** in mono uppercase label type — never a single cycling icon button, since AUTO needs to stay a visible, always-reachable state. Active option: teal fill, `af-on-accent` text. See **Theming** for the full mechanism.

### Tables
- **Style:** `af-surface` header row, `af-border` row dividers, mono for identifying columns (IDs, names), sans for descriptive columns.
- **Responsive:** hide secondary columns below `640px` rather than forcing horizontal scroll — the pattern `BackendCard.vue` already uses; the Tokens table is the one place this isn't yet applied.

### Navigation
- Persistent left-hand nav in `Base.astro` with permission-driven badges next to each destination; mono labels, teal for the active item.

### Dialogs
- Native `<dialog>` with `showModal()` for every destructive/high-stakes confirmation (proxy revoke, identity unlink) — real focus trap, ESC-to-close, inert background, focus restored to the trigger on close. `margin: auto` is restored once, unlayered, in `global.css` to counter Tailwind Preflight's reset (issue #152) rather than patched per-dialog.

### Particle-track canvas (signature component)
The Overview page's hero: a sparse radial event display, golden-angle-spaced curved tracks (quadratic Bezier for "magnetic curvature"), teal/amber/white palette matching Cherenkov/EM-calorimeter physics, `prefers-reduced-motion` respected (renders one static frame instead of animating).

### Gateway pulse animation (public landing page)
The public landing page's "how it works" diagram (AI Assistant → Gateway → backend) gets its own motion moment: a small light (GSAP timeline, `gatewayPulse.ts`) travels the diagram's connector lines, briefly highlighting each box (teal border + glow, via a CSS-transitioned `is-pulse-active` class) as it passes, paired with two small aria-hidden callouts ("user: find me a dataset" → "tool call: rucio_list_dataset") anchored beside the AI Assistant node. Skipped entirely under `prefers-reduced-motion` (the diagram is already complete and legible without it), and played only while on screen (GSAP ScrollTrigger play/pause on enter/leave) rather than running continuously off-screen.

## Component Foundation

Basecoat (`basecoat-css`) is the component and theming foundation as of the light-mode work — chosen over Starwind because it ships CSS classes, which work identically inside Astro pages and Vue SFCs (~90% of this UI is Vue), rather than separate `.astro`/`.vue` component implementations to keep in sync. **Basecoat supplies structure; AF tokens keep the identity** — its shadcn variable set is bridged from the AF palette one-directionally (see **Theming**), never the other way around, and `--radius` is pinned to `4px` (the Sharp-Not-Round Rule), not Basecoat's own `0.625rem` default.

This is a foundation, not a finished migration: only the theming layer (the bridge, `body`'s base-layer styling) currently uses Basecoat directly — tooltips turned out to need a bespoke solution instead (see **Tooltips**). The thirteen hand-rolled BEM component systems across the Vue components (`tp__`, `xc__`, `bc__`, …) are unconverted, migrating component-by-component in later work.

### Named Rules
**Basecoat-Class-First Rule.** If Basecoat ships the component (`btn`, `card`, `badge`, `input`, `select`, `table`, `alert`, `dialog`, …), use its class or attribute. Don't hand-roll an equivalent, and don't redefine a Basecoat class to re-theme it — re-theming happens through the token bridge. Tooltips are the one documented exception (see **Tooltips**): verify a Basecoat mechanism actually covers the real need before reaching for it, not just that Basecoat ships something with the same name.

**Spell-Out-The-Component Rule.** A new bespoke class names the component it styles (`.tokens-table__row`), not a cryptic two-letter prefix (`.tp__row`) — the existing prefixes predate this rule and aren't being renamed as a sweep, but don't add a new one.

**No-Reinvented-Utility Rule.** Before adding a scoped CSS rule, check whether Tailwind already ships it as a utility class (`sr-only` is the standing example — it existed as four separate hand-copied definitions across the codebase before being consolidated onto Tailwind's own).

## Do's and Don'ts

### Do:
- **Do** set every heading, label, badge, and piece of identifying data in IBM Plex Mono; keep body prose in IBM Plex Sans.
- **Do** use `af-dim` or `af-label` for secondary/tertiary text — both are real AA-contrast values.
- **Do** use 1px borders and surface-layering for depth; reserve shadows for focus rings and genuinely floating panels.
- **Do** gate destructive actions behind the native `<dialog>` confirm pattern already used for proxy revoke and identity unlink.
- **Do** hide secondary table/card content below 640px rather than forcing horizontal scroll.
- **Do** add a new color token to both the `@theme` block and `.dark { }` together, in the same change (the Two-Themes-One-Cascade Rule).
- **Do** use a Basecoat class or attribute (`btn`, `card`, `dialog`, …) before hand-rolling an equivalent — but verify it actually covers the real need first (see Tooltips: `data-tooltip` looked right and wasn't).

### Don't:
- **Don't** use `af-muted` (`#374151` dark / `#7d8a99` light) as a text color anywhere — it's a border/disabled token and fails contrast.
- **Don't** add a third animated flourish. The particle-track canvas (Overview) and the gateway-pulse diagram (public landing page) are the app's two deliberate, `prefers-reduced-motion`-gated motion moments — a third needs the same bar: physically/functionally motivated, not decoration.
- **Don't** explain a badge's meaning only through a hover `title` attribute — it's invisible on touch and unreliable on screen readers.
- **Don't** reach for a drop shadow as a default card treatment — this system is flat-by-default.
- **Don't** introduce a second display/heading typeface. Mono is the console's whole identity.
- **Don't** add a raw hex color literal at a call site — every color goes through an `af-*` token, checked by `globalCssContrast.test.ts` and the Impeccable detector.
- **Don't** redefine a Basecoat class to re-theme it, or reinvent a utility (like `sr-only`) Tailwind already ships.
