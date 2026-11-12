---
name: AF MCP Platform Portal
description: Infrastructure-console UI for the credential-brokered MCP gateway
colors:
  { af-bg: "#ffffff", af-bg-subtle: "#f6f6f6", af-bg-hover: "#ececec",
    af-border: "#e0e0e0", af-border-strong: "#c6c6c6", af-text: "#0a0a0a",
    af-text-secondary: "#5c5c5c", af-text-disabled: "#8d8d8d", af-accent: "#0a0a0a",
    af-on-accent: "#ffffff", af-ok: "#16a34a", af-warn: "#d97706",
    af-bad: "#dc2626", af-info: "#2563eb", af-bad-text: "#b91c1c",
    af-banner-ok: "#15803d", af-banner-warn: "#fbbf24", af-banner-bad: "#dc2626",
    af-banner-info: "#2563eb", af-on-banner-ok: "#ffffff", af-on-banner-warn: "#0a0a0a",
    af-on-banner-bad: "#ffffff", af-on-banner-info: "#ffffff", af-bg-dark: "#0f0f10",
    af-bg-subtle-dark: "#18181a", af-bg-hover-dark: "#2a2a2d", af-border-dark: "#2a2a2d",
    af-border-strong-dark: "#3d3d42", af-text-dark: "#f5f5f5", af-text-secondary-dark: "#a8a8ad",
    af-text-disabled-dark: "#6f6f75", af-accent-dark: "#f5f5f5", af-on-accent-dark: "#0a0a0a",
    af-ok-dark: "#4ade80", af-warn-dark: "#fbbf24", af-bad-dark: "#f87171",
    af-info-dark: "#60a5fa", af-bad-text-dark: "#f87171" }
typography:
  text-32: { fontFamily: "IBM Plex Sans, system-ui, -apple-system, Segoe UI, sans-serif", fontSize: "2rem", fontWeight: 600, lineHeight: "2.5rem" }
  text-24: { fontFamily: "IBM Plex Sans, system-ui, -apple-system, Segoe UI, sans-serif", fontSize: "1.5rem", fontWeight: 600, lineHeight: "2rem" }
  text-20: { fontFamily: "IBM Plex Sans, system-ui, -apple-system, Segoe UI, sans-serif", fontSize: "1.25rem", fontWeight: 600, lineHeight: "1.75rem" }
  text-16: { fontFamily: "IBM Plex Sans, system-ui, -apple-system, Segoe UI, sans-serif", fontSize: "1rem", fontWeight: 600, lineHeight: "1.5rem" }
  text-14: { fontFamily: "IBM Plex Sans, system-ui, -apple-system, Segoe UI, sans-serif", fontSize: "0.875rem", fontWeight: 400, lineHeight: "1.25rem" }
  text-13: { fontFamily: "IBM Plex Sans, system-ui, -apple-system, Segoe UI, sans-serif", fontSize: "0.8125rem", fontWeight: 400, lineHeight: "1.25rem" }
  text-12: { fontFamily: "IBM Plex Sans, system-ui, -apple-system, Segoe UI, sans-serif", fontSize: "0.75rem", fontWeight: 400, lineHeight: "1rem" }
  mono: { fontFamily: "IBM Plex Mono, ui-monospace, SF Mono, Menlo, monospace", fontWeight: 400 }
rounded: { "4": "4px", "8": "8px", "10": "10px", "full": "999px" }
spacing: { "2": "2px", "4": "4px", "8": "8px", "12": "12px", "16": "16px", "24": "24px", "32": "32px", "48": "48px", "64": "64px" }
components:
  button-primary: { backgroundColor: "{colors.af-accent}", textColor: "{colors.af-on-accent}", typography: "{typography.text-14}", rounded: "{rounded.8}", padding: "0 10px", height: "36px" }
  button-outline: { backgroundColor: "{colors.af-bg}", textColor: "{colors.af-text}", rounded: "{rounded.8}", padding: "0 10px", height: "36px" }
  button-outline-hover: { backgroundColor: "{colors.af-bg-hover}" }
  button-ghost: { backgroundColor: "transparent", textColor: "{colors.af-text}", rounded: "{rounded.8}", padding: "0 10px", height: "36px" }
  button-danger: { backgroundColor: "{colors.af-bg}", textColor: "{colors.af-bad-text}", rounded: "{rounded.8}", padding: "0 10px", height: "36px" }
  button-small: { typography: "{typography.text-14}", padding: "0 10px", height: "32px" }
  button-large: { typography: "{typography.text-14}", padding: "0 10px", height: "40px" }
  button-extra-large: { typography: "{typography.text-16}", padding: "0 32px", height: "52px" }
  input: { backgroundColor: "{colors.af-bg}", textColor: "{colors.af-text}", rounded: "{rounded.8}", padding: "0 10px", height: "36px" }
  banner-warn: { backgroundColor: "{colors.af-banner-warn}", textColor: "{colors.af-on-banner-warn}", rounded: "{rounded.10}", padding: "12px 16px" }
  banner-bad: { backgroundColor: "{colors.af-banner-bad}", textColor: "{colors.af-on-banner-bad}", rounded: "{rounded.10}", padding: "12px 16px" }
  banner-info: { backgroundColor: "{colors.af-banner-info}", textColor: "{colors.af-on-banner-info}", rounded: "{rounded.10}", padding: "12px 16px" }
  banner-ok: { backgroundColor: "{colors.af-banner-ok}", textColor: "{colors.af-on-banner-ok}", rounded: "{rounded.10}", padding: "12px 16px" }
  tag: { backgroundColor: "{colors.af-bg}", textColor: "{colors.af-text}", typography: "{typography.text-12}", rounded: "{rounded.full}", padding: "2px 8px", height: "20px" }
  nav-item-current: { backgroundColor: "{colors.af-bg-subtle}", textColor: "{colors.af-text}", rounded: "{rounded.8}", padding: "0 12px", height: "36px" }
  copy-field: { backgroundColor: "{colors.af-bg-subtle}", textColor: "{colors.af-text}", rounded: "{rounded.8}", padding: "0 4px 0 12px", height: "40px" }
---

# Design System: AF MCP Platform Portal

## Overview

The portal is where a facility's physics users link external accounts, keep a
grid certificate valid, create tokens for MCP clients and check which services
their account can reach. Operators use the same portal, plus an Admin page that
shows platform state across users.

**Reference bar:** GitHub's settings pages, the Tailscale and Cloudflare admin
consoles, Grafana. **Ruled out:** a sci-fi terminal look, a generic
component-library dashboard, a heavy enterprise portal, consumer-SaaS flourishes.

Four rules. Everything below follows from them.

1. **Containers recede, content leads.** Borders are 1px and pale. Fills are
   rare. The data is the darkest thing in a box.
2. **Colour means something or it is absent.** Neutrals are untinted greys. The
   accent marks the main action and the current location. Status colours mark
   status and nothing else.
3. **The accent is never a message.** Banners and notes use the fixed status
   colours, so a facility whose colour is red or yellow cannot make a notice
   look like an error or a warning.
4. **One loud thing per page.** At most one page banner and at most one primary
   button. If nothing is wrong, the page is quiet.

### Basecoat-class-first

The portal is built on [Basecoat](https://basecoatui.com) (`basecoat-css`):
plain CSS classes (`btn`, `badge`, `alert`, `table`, `dialog`, `chart`, ...)
that work the same in `.astro` pages and `.vue` components, with no component
framework to match. **If Basecoat ships a component, use its class and
attributes and re-theme it through the token bridge. Extend it with a separate
`af-` class. Never redefine a Basecoat class.** Basecoat supplies structure and
behaviour; the portal's tokens supply identity. The bridge maps Basecoat's
variables (`--primary`, `--border`, `--ring`, `--chart-1` ...) onto the tokens
below, so a colour is changed once, in `portal/src/styles/global.css`. How it is
wired is in `docs/portal-styling.md`; `designContract.test.ts` fails on a
hand-rolled replacement or a redefined Basecoat class.

Token names in this file are the portal's. The worked reference,
`docs/design-language/index.html`, uses short names in its self-contained demo
CSS (`--bg` is `--color-af-bg`; `--shadow-1` is `--shadow-af-1`) and has a
"Built on Basecoat" section that maps its demo classes to the real ones.

## Colors

Values are in the frontmatter (light is the default, each `-dark` entry is the
same token in the dark theme) and defined once in `portal/src/styles/global.css`.
Three groups with separate jobs.

- **Accent** (`--color-af-accent`, with `--color-af-on-accent` for text on it) is
  ink by default: near-black in light, near-white in dark. A deployment may opt
  in to its own colour (derivation in `docs/portal-styling.md`). It is used only
  as a **fill** (primary button, checked control, skip link) or as the **3px
  marker** on the current sidebar item. Never a text colour, border or banner
  fill.
- **Neutrals** build the page: `af-bg` (page, containers), `af-bg-subtle` (hover
  rows, read-only fields, selected nav item), `af-bg-hover` (hover on buttons),
  `af-border` (container outlines, row rules), `af-border-strong` (anything a
  person can type in or press), `af-text`, `af-text-secondary` (labels, headers,
  help) and `af-text-disabled` (disabled controls only, never readable text).
- **Status** is fixed for every deployment, never the accent:

| Meaning | Mark | Token | Banner fill | Use when |
| --- | --- | --- | --- | --- |
| OK | Circle | `--color-af-ok` | `--color-af-banner-ok` | Working, linked, valid. |
| Warning | Triangle | `--color-af-warn` | `--color-af-banner-warn` | Works for now, or someone must wait or ask. |
| Problem | Square | `--color-af-bad` | `--color-af-banner-bad` | Not working. Also destructive actions. |
| Information | Diamond | `--color-af-info` | `--color-af-banner-info` | A neutral notice or hint. Nothing is wrong. |
| In progress | Half ring | `--color-af-text-secondary` | none | Waiting on the system. |
| Off | Empty ring | `--color-af-text-secondary` | none | Absent by choice. Not an error. |

- **Status is always a shape and a word.** Colour repeats the meaning; it never
  carries it alone. A name is never coloured to show its state.
- Banner fills and their `--color-af-on-banner-*` text are the same in both
  themes. `--color-af-bad-text` is the only status colour used for text. Note
  backgrounds mix a status colour into the page (8 to 10% fill, 45 to 50% border).
- **Chart colours** are the bridged `--chart-1` to `--chart-5`: neutral steps
  (secondary text, text, strong border, disabled text, border), never status.
  A bar is `--chart-1`, its hover is `--chart-2`.

## Typography

**Text and headings:** IBM Plex Sans. **Literal values:** IBM Plex Mono.

| Token | Size / line | Weight | Use |
| --- | --- | --- | --- |
| `--text-32` | 32 / 40px | 600 | Landing page headline only. |
| `--text-24` | 24 / 32px | 600 | Page title, one per page. Stat values. |
| `--text-20` | 20 / 28px | 600 | Landing section headings; empty-state title; dialog title. |
| `--text-16` | 16 / 24px | 600 | Section title, card name. |
| `--text-14` | 14 / 20px | 400, 500 | Default: body, cells, buttons, inputs. |
| `--text-13` | 13 / 20px | 400, 500 | Column headers, help text, notes. |
| `--text-12` | 12 / 16px | 400 | Badges, nav group labels, chart axes. The minimum. |

- Weights are 400 for text, 500 for labels and buttons, 600 for headings.
- Hierarchy comes from size and weight, never a second typeface, capitals or
  letter-spacing. Mono only for values copied or compared character by character
  (tokens, hostnames, tool names, commands, reference ids). Number columns are
  right-aligned with tabular numerals (`af-num`). Help text is capped at 80
  characters per line, empty-state text at 52.

## Layout

Gaps and paddings come from `--space-2/4/8/12/16/24/32/48/64`: 8 icon to label,
12 section title to content, 16 cell padding and inside banners, 24 page header
to content, 32 between sections, 48 and 64 between landing regions.

| Token | Height | Use |
| --- | --- | --- |
| `--control-s` | 32px | Basecoat `data-size="sm"`: row actions, buttons in banners, segmented controls. |
| `--control-m` | 36px | The default button, input and nav item. |
| `--control-l` | 40px | `data-size="lg"`; copy fields. |
| (none) | 52px | `af-btn-xl`: the landing page Sign in. |

Comfortable table rows are 44px (user pages); compact rows are 32px
(Entitlements, Admin). Density is chosen per page: comfortable pages use a 32px
section gap and 14px cells, compact pages 24px and 13px. A compact table may sit
inside a comfortable page for a secondary checklist.

- A 220px sidebar, fixed left and full height, and one content column capped at
  1120px. Content margin is 16px under 600px, 24px from 600px, 32px from 1136px.
- Under 860px the sidebar becomes a drawer opened from a 52px top bar, on a scrim.
- Sections are full width and stacked; a row of equal cards is not a default.
- Wide tables scroll inside their own box, never the page. The landing page has
  no sidebar: the same column, text capped at 720px, regions 64px apart.

## Elevation & Depth

Everything that belongs to the page is flat and separated by a 1px border.
A shadow means the surface is temporarily on top.

| Level | Token | Allowed on |
| --- | --- | --- |
| Flat | none | Tables, sections, rows, banners, notes, sidebar, top bar, popover tooltips. |
| Raised | `--shadow-af-1` | The chart tooltip (through Basecoat's `--shadow-xl`), the open navigation drawer. |
| Overlay | `--shadow-af-2` | Dialogs. |

- No other shadow exists: Basecoat's `--shadow-xs` and `--shadow-sm` are none and
  its backdrop blur is 0. In dark both shadows carry a 1px light outline.

## Shapes

| Token | Value | Use |
| --- | --- | --- |
| `--radius-4` | 4px | Popover tooltips, chart indicators. |
| `--radius-8` | 8px | Buttons, inputs, nav items, copy fields (Basecoat's `rounded-md`). |
| `--radius-10` | 10px | Containers: table boxes, row lists, banners, notes, fields, empty states. |
| `--radius-full` | 999px | Badges (tags) and round icon buttons. Not status pills. |

- Basecoat derives its radii from `--radius`, set to 10px: controls 8px, alerts
  and empty states 10px. Its dialog panel is `rounded-xl`, 14px.
- Borders are 1px: `--color-af-border` outlines containers and rules rows,
  `--color-af-border-strong` outlines controls. Table headers are unfilled.
  No coloured stripe down one side of a container.
- The empty state (Basecoat's `empty`) is the only dashed border, and its
  content is centred, as Basecoat lays it out.
- Focus: Basecoat's controls draw a border and 3px halo from `--ring`; the
  portal's own links, nav items and summaries draw a 2px outline in the text
  colour, offset 2px. No element shows both.

## Motion

`--time-fast` 100ms (hover colour), `--time-base` 200ms (disclosure chevron,
drawer, chart bars), `--time-slow` 300ms (the sign-in spinner), `--ease`
`cubic-bezier(0.2, 0, 0, 1)` for every transition.

- Only hover colour, a turning chevron, the sliding drawer, a small spinner and a
  chart's first draw move. Page content does not animate on load. Reduced motion
  stops every transition and spinner and draws charts without animation.
- Two animations are kept on purpose: the **particle-track canvas** (beside the
  Overview header and in the landing hero; one still frame under reduced motion)
  and the **gateway diagram** on the landing page (runs only on screen, never
  under reduced motion).

## Icons

Lucide, from `@lucide/vue` and `@lucide/astro`; markup is never pasted. 16px
beside text, 20px in a large button, `currentColor`, `aria-hidden` when
decorative. An icon repeats a label; an icon-only button has an accessible name.
Text glyphs are never icons (an arrow is allowed only inside a sentence). Status
uses the status mark.

## Writing

| Rule | Write | Not |
| --- | --- | --- |
| Name the thing and the fix | Your grid proxy has expired. Renew it to keep grid services working. | Access denied (403). |
| Buttons are verb + object | Link certificate | Continue |
| Relative time, exact on hover | Expires in 3 days | 2026-11-13T09:14:00Z |
| Say what is lost | Revoke token. Clients using it stop working immediately. | Are you sure? |
| Empty states say what goes here | No tokens yet. Create one for clients that can't sign in with a browser. | Nothing to show. |
| Product words | Grid certificate | x509 VOMS proxy credential provider |

Sentence case everywhere; no filler ("Token created", not "successfully created!"). Internal terms appear only on the Admin page.

## Components

### Basecoat components in use

| Basecoat class | As used here | Notes |
| --- | --- | --- |
| `btn` | No variant: the primary action. `data-variant="outline"`: ordinary action. `data-variant="ghost"`: low emphasis (Cancel, row links). `data-size="sm"` 32px in tables and banners; default 36px; `data-size="lg"` 40px; `data-size="icon"` 36px square. | One primary per page. Danger is `btn af-danger` with `data-variant="outline"`. |
| `badge` | `data-variant="outline"`: a neutral pill label for a category (permission, credential type, read or write). | 20px, 12px text. Never status. |
| `alert` | The box for banners and notes, with `af-banner` or `af-note`. | See Banner, note and hint. |
| `table-container` + `table` | With `af-box` (frame); `af-compact`, `af-num`, `af-act`, `af-sub` on top. | Three or more items with the same fields. |
| `field`, `input`, `native-select`, `textarea`, `label`, checkbox | A label above the control, hint or error below. `field` with `data-orientation="horizontal"` for a checkbox. `af-narrow` caps a field at 360px (a readable width in a page section). | A placeholder never stands in for a label. |
| `button-group` | With `af-toggle`: a single-choice switch (`SegmentedControl`). The selected button is ink, not the accent. | A range or filter, not page navigation. |
| `dialog` | Native `<dialog>` with `af-modal` (scrim, overlay shadow). `ConfirmDialog` wraps it; focus starts on Cancel. | Decisions that cannot be undone, or a short form. |
| `empty` | Centred title, sentence and optional action. | A list with nothing in it. |
| `chart` | Through `BarChart.vue` (Chart.js underneath, loaded only where a chart mounts): neutral `--chart-N` bars, grid in `--border`, 12px secondary axis labels in the page font, no gradient or shadow, Basecoat's tooltip markup. | The canvas is `role="img"` with a summary label and every value is repeated in a visually hidden table. |

### Portal extensions on Basecoat

| Class | Why it exists |
| --- | --- |
| `af-danger` | Basecoat's destructive variant is a tinted fill; the contract wants a red outline and label, never a fill, so it cannot be mistaken for a red facility accent. |
| `af-banner` / `af-note` (`ok`, `warn`, `bad`, `info`) on `alert` | Basecoat's `alert` has no status treatments and expects an svg; these add the solid banner fills and tinted notes and lay a mark, text and action in one wrapping row. `af-banner slim` is the one-line shell bar. |
| `af-box`, `af-compact`, `af-num`, `af-act`, `af-sub` | The table frame, 32px density, right-aligned numbers, the action cell and secondary cells. |
| `af-toggle` | Fills the selected `button-group` button with ink rather than the accent. |
| `af-modal` | The scrim and overlay shadow on `dialog`. |
| `af-btn-xl` | The one 52px call to action on the landing page. |

### Bespoke pieces

Basecoat has no equivalent, so these are `af-` classes or Vue components.

| Class or component | What it is for | Not when |
| --- | --- | --- |
| `af-st` + `af-mark` (`StatusMark`) | A status word with its shape. Tones `ok`, `warn`, `bad`, `info`, `busy`, `off`. | Labelling a category; the mark without a word. |
| `PageMessage` | A page's banner slot: a problem or warning as `af-banner`, a hint as `af-note info`. | More than one per page. |
| `AsyncState` | The loading, session-expired, access-denied, error and empty ladder for fetched data. | Hand-written loading or error markup. |
| `af-kv` | A two-column list of label and value for one record. | Comparing several records. |
| `af-stats` + `af-stat` | A label, a 24px value and an optional 12px line. | A number needing a row of context. |
| `af-copy` (`CopyField`) | A read-only mono value with a Copy button ("Copied" for two seconds). | Values nobody copies. |
| `Disclosure`, `ArmedConfirmButton` | An expanding region; a two-step inline confirm. | Hiding the page's main content; anything needing an explanation of what is lost. |
| `InfoTip` / `PopoverTooltip` | A tooltip on the native Popover API. A documented exception: Basecoat's `data-tooltip` is clipped by scrolling ancestors. | Anything needed to finish the task; it is not reachable on touch. |
| `af-nav`, `af-nav-group`, `af-nav-label` | The sidebar. A documented exception: the shell sidebar (fixed, grouped, count badges, drawer under 860px) is built in `Base.astro`, because Basecoat's sidebar targets an app-shell layout the portal does not use. | In-page tabs. |
| `af-page`, `af-page-head`, `af-sect`, `af-help`, `af-wrap`, `af-topbar`, `af-brand`, `skip-link`, `af-icon`, `EntitlementMark` | Page structure, shell, icon sizing; the entitlements matrix cell. | |

### Banner, note and hint

- A **banner** (`alert af-banner` + `warn`, `bad`) is the page's one loud
  message: mark, bold title, one sentence, at most one button naming the fix.
  It is announced as `role="alert"`. Problem beats warning.
- A **hint** (`alert af-note info`, `role="status"`) is quiet information that
  never alarms: an account left unlinked is the user's choice. It sits in the
  banner slot only when no banner does. Information that is not a hint (an
  account just linked, maintenance) uses `af-banner ok` or `af-banner info`
  with `role="status"`.
- A **note** (`af-note`) is inline beside the thing it explains.
  `af-banner info slim` is the maintenance bar, on every page including the landing page.

## Page pattern

Every signed-in page has the same parts in the same order.

1. **Maintenance bar**, only while maintenance is on.
2. **Page header**: a 24px title, one line on what the page is for, at most one
   primary button on the right.
3. **Banner slot**: empty when nothing is wrong, otherwise the single most
   urgent message. Problem beats warning beats hint.
4. **Sections**: full width, stacked, a 16px title and one main component each.

## Pages

| Page | Job | Primary action | Banner slot | Main components |
| --- | --- | --- | --- | --- |
| Landing `/` | Say what the platform is; sign in. | Sign in (`af-btn-xl`) | Maintenance bar only | Headline, particle canvas, gateway diagram, benefits |
| Overview | Is my access working? How do I connect a client? | None | Grid proxy expired (problem); a service misconfigured (problem) or unavailable (warning); a service rejected a linked credential (warning); proxy expiring (warning); a token expiring within 7 days (warning). Hints: no account linked; N services not linked | Status rows, stats, copy field |
| Services | Which backends and methods can I reach? | None | Misconfigured (problem), unavailable (warning), a credential rejected (warning, with a re-link action when they share one identity). Hint: N services not linked, with an action when they share one account | Search, filter, service rows (not a table) |
| Identities | Link accounts and keep the grid certificate valid. | Per card | Proxy expired (problem); a credential rejected (warning); proxy expiring (warning); a link failed (problem); a link succeeded (ok, clears after 5 seconds) | One card per credential, key-value lists |
| Tokens | Create and revoke tokens for clients without a browser. | New token | A token expires within 7 days (warning); a revoke failed (problem) | Table, dialog with copy field |
| Usage | What have my clients been doing? | None; range control | None | Stats, bar chart, table per service |
| Entitlements | Which group grants which permission? | None | None | Compact matrix table |
| Admin | Platform state across users. | None | Tool configuration issues (warning) | Compact tables, status marks |

A data page also shows a problem banner when its own data fails to load.

State rules that hold on every page:

- **Not linked is off, not wrong.** The off mark, the words "Not linked", a quiet
  row. It never raises a warning or problem banner; at most a hint. A service
  that needs no credential (the gateway's own) is never counted as unlinked.
  The Identities page needs no hint: its rows show the state and the action.
- **Credential rejected is a warning, not "Not linked".** The user did link, and
  the backend refuses what they set up (the broker's `link_state: "rejected"`).
  Warning mark, the words "Credential rejected", a row at full ink (never the
  quiet treatment), one sentence ("Your linked <identity> was rejected. Re-link
  it to use this service.") and a re-link action that names the identity and
  goes to its card. It raises a warning banner, ranked below misconfigured and
  unavailable and above a not-linked hint. It sorts with the things that need
  attention (after misconfigured and unavailable, before available) and is
  never counted as not linked. Its "Powered by" line shows no link state.
- **A grid proxy warns only when it cannot renew itself and has under 1 hour
  left.** An auto-renewing proxy never shows as expiring.
- **Misconfigured and Unavailable differ.** Misconfigured needs an operator:
  problem mark and a reference id. Unavailable is temporary: warning mark.
- **Access required** needs an administrator: warning mark, inline detail, no banner.
  A row shows its identity's link state only where that is the actionable fact.

## Do's and Don'ts

### Do:

- **Do** use a Basecoat class where one exists, and a token for every colour,
  type size, radius, shadow and duration.
- **Do** pair every status colour with its shape and a word, keep messages in
  status colours and actions in the accent, and leave a quiet page quiet.
- **Do** announce problems and warnings as `role="alert"`, hints as `role="status"`.

### Don't:

- **Don't** redefine a Basecoat class, or hand-roll one it ships.
- **Don't** fill a banner or note with the accent, use it as text, or show more
  than one banner or one primary button.
- **Don't** use capitals, letter-spacing, a second typeface or text below 12px
  for hierarchy; don't add a shadow to anything that belongs to the page.
- **Don't** use a tag, pill or coloured name for status, a text glyph as an icon,
  or a third animation.

Enforcement (`designContract.test.ts`, `globalCssContrast.test.ts`), the preview
tooling and how the styling is built are in `docs/portal-styling.md`. The worked
reference with rendered examples is `docs/design-language/index.html`.
