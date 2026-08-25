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

## Colors

A near-monochrome void-and-surface base with exactly two accent colors, each with one job.

### Primary
- **Cherenkov Teal** (`#00d4c8`): the one primary-action color — copy buttons, links, focus rings, active status. Used sparingly; a screen with teal everywhere has stopped being an accent.

### Secondary
- **Calorimeter Amber** (`#f59e0b`): reserved for "this is a state-changing / write action, use with care" — never used for anything else (not warnings-in-general, not "important," specifically state-change).

### Neutral
- **Void** (`#0a0e1a`): the page background, near-black.
- **Surface** (`#111827`): one step up from void — cards, panels, table headers.
- **Border** (`#1f2937`): structural dividers between surfaces.
- **Muted** (`#374151`): borders and disabled states ONLY. **Never text** — it fails contrast (documented in the token comment itself, and the existing critique flagged four real violations of this rule).
- **Dim** (`#9ca3af`): secondary text and labels — 6.99:1 on surface / 7.58:1 on void, real AA-passing values.
- **Label** (`#838d99`): tertiary/eyebrow/uppercase-label text — 5.27:1 on surface / 5.72:1 on void.
- **Text** (`#e8ecf0`): primary reading text.
- **Red** (`#ef4444`): error and revoke actions only.
- **Green** (`#10b981`): active/healthy status only.

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
- **Panel shadow** (`box-shadow: 4px 0 24px rgb(0 0 0 / 0.4)`): the one directional shadow, for a surface that overlays the page (e.g. a slide-out).
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

## Do's and Don'ts

### Do:
- **Do** set every heading, label, badge, and piece of identifying data in IBM Plex Mono; keep body prose in IBM Plex Sans.
- **Do** use `af-dim` or `af-label` for secondary/tertiary text — both are real AA-contrast values.
- **Do** use 1px borders and surface-layering for depth; reserve shadows for focus rings and genuinely floating panels.
- **Do** gate destructive actions behind the native `<dialog>` confirm pattern already used for proxy revoke and identity unlink.
- **Do** hide secondary table/card content below 640px rather than forcing horizontal scroll.

### Don't:
- **Don't** use `af-muted` (`#374151`) as a text color anywhere — it's a border/disabled token and fails contrast.
- **Don't** add a third animated flourish. The particle-track canvas (Overview) and the gateway-pulse diagram (public landing page) are the app's two deliberate, `prefers-reduced-motion`-gated motion moments — a third needs the same bar: physically/functionally motivated, not decoration.
- **Don't** explain a badge's meaning only through a hover `title` attribute — it's invisible on touch and unreliable on screen readers.
- **Don't** reach for a drop shadow as a default card treatment — this system is flat-by-default.
- **Don't** introduce a second display/heading typeface. Mono is the console's whole identity.
