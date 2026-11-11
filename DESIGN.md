---
name: AF MCP Platform Portal
description: Infrastructure-console UI for the credential-brokered MCP gateway
colors:
  af-bg: "#ffffff"
  af-bg-subtle: "#f6f6f6"
  af-bg-hover: "#ececec"
  af-border: "#e0e0e0"
  af-border-strong: "#c6c6c6"
  af-text: "#0a0a0a"
  af-text-secondary: "#5c5c5c"
  af-text-disabled: "#8d8d8d"
  af-accent: "#0a0a0a"
  af-on-accent: "#ffffff"
  af-ok: "#16a34a"
  af-warn: "#d97706"
  af-bad: "#dc2626"
  af-info: "#2563eb"
  af-bad-text: "#b91c1c"
  af-banner-ok: "#15803d"
  af-banner-warn: "#fbbf24"
  af-banner-bad: "#dc2626"
  af-banner-info: "#2563eb"
  af-on-banner-ok: "#ffffff"
  af-on-banner-warn: "#0a0a0a"
  af-on-banner-bad: "#ffffff"
  af-on-banner-info: "#ffffff"
  af-bg-dark: "#0f0f10"
  af-bg-subtle-dark: "#18181a"
  af-bg-hover-dark: "#2a2a2d"
  af-border-dark: "#2a2a2d"
  af-border-strong-dark: "#3d3d42"
  af-text-dark: "#f5f5f5"
  af-text-secondary-dark: "#a8a8ad"
  af-text-disabled-dark: "#6f6f75"
  af-accent-dark: "#f5f5f5"
  af-on-accent-dark: "#0a0a0a"
  af-ok-dark: "#4ade80"
  af-warn-dark: "#fbbf24"
  af-bad-dark: "#f87171"
  af-info-dark: "#60a5fa"
  af-bad-text-dark: "#f87171"
typography:
  text-32:
    fontFamily: "IBM Plex Sans, system-ui, -apple-system, Segoe UI, sans-serif"
    fontSize: "2rem"
    fontWeight: 600
    lineHeight: "2.5rem"
  text-24:
    fontFamily: "IBM Plex Sans, system-ui, -apple-system, Segoe UI, sans-serif"
    fontSize: "1.5rem"
    fontWeight: 600
    lineHeight: "2rem"
  text-20:
    fontFamily: "IBM Plex Sans, system-ui, -apple-system, Segoe UI, sans-serif"
    fontSize: "1.25rem"
    fontWeight: 600
    lineHeight: "1.75rem"
  text-16:
    fontFamily: "IBM Plex Sans, system-ui, -apple-system, Segoe UI, sans-serif"
    fontSize: "1rem"
    fontWeight: 600
    lineHeight: "1.5rem"
  text-14:
    fontFamily: "IBM Plex Sans, system-ui, -apple-system, Segoe UI, sans-serif"
    fontSize: "0.875rem"
    fontWeight: 400
    lineHeight: "1.25rem"
  text-13:
    fontFamily: "IBM Plex Sans, system-ui, -apple-system, Segoe UI, sans-serif"
    fontSize: "0.8125rem"
    fontWeight: 400
    lineHeight: "1.25rem"
  text-12:
    fontFamily: "IBM Plex Sans, system-ui, -apple-system, Segoe UI, sans-serif"
    fontSize: "0.75rem"
    fontWeight: 400
    lineHeight: "1rem"
  mono:
    fontFamily: "IBM Plex Mono, ui-monospace, SF Mono, Menlo, monospace"
    fontWeight: 400
rounded:
  "4": "4px"
  "8": "8px"
  "10": "10px"
  full: "999px"
spacing:
  "2": "2px"
  "4": "4px"
  "8": "8px"
  "12": "12px"
  "16": "16px"
  "24": "24px"
  "32": "32px"
  "48": "48px"
  "64": "64px"
components:
  button-primary:
    backgroundColor: "{colors.af-accent}"
    textColor: "{colors.af-on-accent}"
    typography: "{typography.text-14}"
    rounded: "{rounded.8}"
    padding: "0 16px"
    height: "36px"
  button-secondary:
    backgroundColor: "{colors.af-bg}"
    textColor: "{colors.af-text}"
    rounded: "{rounded.8}"
    padding: "0 16px"
    height: "36px"
  button-secondary-hover:
    backgroundColor: "{colors.af-bg-hover}"
  button-quiet:
    backgroundColor: "transparent"
    textColor: "{colors.af-text}"
    rounded: "{rounded.8}"
    padding: "0 8px"
    height: "36px"
  button-danger:
    backgroundColor: "{colors.af-bg}"
    textColor: "{colors.af-bad-text}"
    rounded: "{rounded.8}"
    padding: "0 16px"
    height: "36px"
  button-small:
    typography: "{typography.text-13}"
    padding: "0 12px"
    height: "28px"
  button-large:
    typography: "{typography.text-16}"
    padding: "0 24px"
    height: "44px"
  input:
    backgroundColor: "{colors.af-bg}"
    textColor: "{colors.af-text}"
    rounded: "{rounded.8}"
    padding: "0 12px"
    height: "36px"
  banner-warn:
    backgroundColor: "{colors.af-banner-warn}"
    textColor: "{colors.af-on-banner-warn}"
    rounded: "{rounded.10}"
    padding: "12px 16px"
  banner-bad:
    backgroundColor: "{colors.af-banner-bad}"
    textColor: "{colors.af-on-banner-bad}"
    rounded: "{rounded.10}"
    padding: "12px 16px"
  banner-info:
    backgroundColor: "{colors.af-banner-info}"
    textColor: "{colors.af-on-banner-info}"
    rounded: "{rounded.10}"
    padding: "12px 16px"
  banner-ok:
    backgroundColor: "{colors.af-banner-ok}"
    textColor: "{colors.af-on-banner-ok}"
    rounded: "{rounded.10}"
    padding: "12px 16px"
  tag:
    backgroundColor: "{colors.af-bg-subtle}"
    textColor: "{colors.af-text}"
    typography: "{typography.text-12}"
    rounded: "{rounded.4}"
    padding: "0 8px"
    height: "22px"
  nav-item-current:
    backgroundColor: "{colors.af-bg-subtle}"
    textColor: "{colors.af-text}"
    rounded: "{rounded.8}"
    padding: "0 12px"
    height: "36px"
  copy-field:
    backgroundColor: "{colors.af-bg-subtle}"
    textColor: "{colors.af-text}"
    rounded: "{rounded.8}"
    padding: "0 4px 0 12px"
    height: "44px"
---

# Design System: AF MCP Platform Portal

## Overview

The portal is where a facility's physics users link external accounts, keep a
grid certificate valid, create tokens for MCP clients and check which services
their account can reach. Facility operators use the same portal, plus an Admin
page that shows platform state across users.

**Reference bar:** GitHub's settings pages, the Tailscale and Cloudflare admin
consoles, and Grafana. A user should recognise every control without learning
anything.

**Ruled out:** a sci-fi terminal look (dark, mono everywhere, glowing accents),
a generic component-library dashboard, a heavy enterprise portal, and
consumer-SaaS marketing flourishes inside the app.

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

Token names in this file are the portal's (`portal/src/styles/global.css`). The
worked reference, `docs/design-language/index.html`, uses short names in its
demo CSS: drop the `color-af-` prefix (`--bg` is `--color-af-bg`, `--border` is
`--color-af-border`, `--text` is `--color-af-text`) and `--shadow-1` /
`--shadow-2` are `--shadow-af-1` / `--shadow-af-2`. Type, space, radius, control
and time tokens have the same names in both.

## Colors

Three groups with separate jobs. Values are in the frontmatter; light is the
default and each `-dark` entry is the same token under the dark theme.

### Primary

- **Accent** (`--color-af-accent`, with `--color-af-on-accent` for text on it).
  Ink by default: near-black in light, near-white in dark. A deployment may opt
  in to its own colour; none is assigned to it.
- The accent is used only as a **fill** (primary button, checked checkbox, the
  skip link) or as the **3px marker** on the current sidebar item. It is never a
  text colour, a border colour or a banner fill.
- Derivation when a facility sets a colour:
    - Light theme: the configured colour as given.
    - Dark theme: the configured dark colour if one is set. Otherwise the light
      colour is mixed toward white in 10% steps (at most 20) until it reaches
      3:1 against the dark page background.
    - On-accent: white if white reaches 4.5:1 on the accent, otherwise
      near-black.
    - A value that is not a `#rrggbb` hex is ignored and the ink default stays.

### Neutral

| Token | Use |
| --- | --- |
| `--color-af-bg` | Page and container background. |
| `--color-af-bg-subtle` | Hover rows, read-only fields, the selected nav item. |
| `--color-af-bg-hover` | Hover on buttons and menu items. |
| `--color-af-border` | Container outlines and row rules. |
| `--color-af-border-strong` | Outline of anything a person can type in or press. |
| `--color-af-text` | Primary text, including links. |
| `--color-af-text-secondary` | Labels, column headers, help text. |
| `--color-af-text-disabled` | Disabled controls only. Never readable text. |

### Status

Fixed for every deployment. Never the accent.

| Meaning | Mark shape | Token | Banner fill | Use when |
| --- | --- | --- | --- | --- |
| OK | Circle | `--color-af-ok` | `--color-af-banner-ok` | Working, linked, valid. |
| Warning | Triangle | `--color-af-warn` | `--color-af-banner-warn` | Works for the moment, or needs someone to wait or ask. |
| Problem | Square | `--color-af-bad` | `--color-af-banner-bad` | Not working. Also destructive actions. |
| Information | Diamond | `--color-af-info` | `--color-af-banner-info` | A neutral notice. Nothing is wrong. |
| In progress | Half-filled ring | `--color-af-text-secondary` | none | Waiting on the system. |
| Off | Empty ring | `--color-af-text-secondary` | none | Absent by choice. Not an error. |

- **Status is always a shape and a word.** Colour repeats the meaning; it never
  carries it alone. A name is never coloured to show its state.
- Banner fills and their text colours (`--color-af-on-banner-*`) are the same in
  both themes.
- `--color-af-bad-text` is the only status colour used for text: error messages
  and the danger button label.
- Tinted note backgrounds are mixed from a status colour and the page
  background (8 to 10% fill, 45 to 50% border). No other tints exist.

## Typography

**Text and headings:** IBM Plex Sans. **Literal values:** IBM Plex Mono.

| Token | Size / line | Weight | Use |
| --- | --- | --- | --- |
| `--text-32` | 32 / 40px | 600 | Landing page headline only. |
| `--text-24` | 24 / 32px | 600 | Page title, one per page. Stat values. |
| `--text-20` | 20 / 28px | 600 | Landing page section headings only. |
| `--text-16` | 16 / 24px | 600 | Section title, dialog title, card name. |
| `--text-14` | 14 / 20px | 400, 500 | Default: body, table cells, buttons, inputs. |
| `--text-13` | 13 / 20px | 400, 500 | Column headers, field labels, help text, notes, compact tables. |
| `--text-12` | 12 / 16px | 400 | Tags, nav group labels, text under a stat. The minimum size. |

- Weights are 400 for text, 500 for labels and buttons, 600 for headings. No
  others.
- Hierarchy comes from size and weight. Never from a second typeface, capitals
  or letter-spacing. Labels are sentence case.
- Mono is only for values a person copies or compares character by character:
  tokens, hostnames, service prefixes, tool names, commands, reference ids. It
  inherits the surrounding size. A whole table or heading is never mono.
- Number columns are right-aligned with tabular numerals (`.num`).
- Help text is capped at 80 characters per line, empty-state text at 52.

## Layout

### Spacing and control heights

Every gap, padding and height comes from a 4px-based scale.

| Token | Use |
| --- | --- |
| `--space-2` (2px) | Hairline offsets; gaps inside a segmented control. |
| `--space-4` (4px) | Title to its description; menu padding. |
| `--space-8` (8px) | Icon to label; between related controls. |
| `--space-12` (12px) | Input padding; section title to its content. |
| `--space-16` (16px) | Cell padding; inside banners and notes. |
| `--space-24` (24px) | Container padding; page header to content. |
| `--space-32` (32px) | Between sections; page margin on wide screens. |
| `--space-48` (48px), `--space-64` (64px) | Between landing page regions. |

| Token | Height | Use |
| --- | --- | --- |
| `--control-s` | 28px | Row actions in tables, buttons inside banners. |
| `--control-m` | 36px | Default for buttons, inputs and nav items. |
| `--control-l` | 44px | Copy fields, comfortable table rows. |

### Density

Density is chosen per page, not per component.

| Mode | Table row | Cell text | Header text | Section gap | Pages |
| --- | --- | --- | --- | --- | --- |
| Comfortable | 44px | 14px | 13px | 32px | Overview, Services, Identities, Tokens, Usage |
| Compact | 32px | 13px | 12px | 24px | Entitlements, Admin |

Operators scan many rows, so their pages are compact. Physics users check a
handful of items, so theirs are comfortable. A compact table may appear inside
a comfortable page for a secondary checklist (the grid certificate preflight).

### Grid

- A 220px sidebar, fixed to the left and full height, and one content column.
- Content is capped at 1120px and centred in the space beside the sidebar.
- Content margin is 16px under 600px, 24px from 600px and 32px from 1136px.
- Under 860px the sidebar becomes a drawer opened from a top bar with a menu
  button. The drawer sits on a scrim.
- Sections are full width and stacked. A row of equal cards is not a default
  layout.
- Wide tables scroll sideways inside their own box. The page does not.
- The landing page has no sidebar. It uses the same 1120px column with text
  blocks capped at 720px, and regions separated by a 1px rule and 64px.

## Elevation & Depth

Everything that belongs to the page is flat and separated by a 1px border. A
shadow means the surface is temporarily on top.

| Level | Token | Allowed on |
| --- | --- | --- |
| Flat | none | Tables, sections, cards, banners, sidebar, top bar, tooltips. |
| Raised | `--shadow-af-1` | The open navigation drawer; menus. |
| Overlay | `--shadow-af-2` | Dialogs. |

- No other shadow exists. A ring is drawn as an inset 1.5px line in a token
  colour (the "in progress" and "off" marks).
- In dark both shadows also carry a 1px light outline, because a shadow alone
  is hard to see on a dark page.
- No background blur. Surfaces are opaque.
- Tooltips are flat: page background, 1px strong border, 4px radius.

## Shapes

| Token | Value | Use |
| --- | --- | --- |
| `--radius-4` | 4px | Tags, segments, menu items, tooltips. |
| `--radius-8` | 8px | Buttons, inputs, nav items, notes, copy fields. |
| `--radius-10` | 10px | Containers: table boxes, cards, banners, dialogs, empty states. |
| `--radius-full` | 999px | Round icon-only buttons. Not status pills. |

- Borders are 1px. `--color-af-border` outlines containers and rules rows;
  `--color-af-border-strong` outlines controls.
- Table headers are unfilled. No heavy outlines, no coloured stripe down one
  side of a container.
- An empty state is the only dashed border.
- Focus is one ring everywhere: a 2px outline in the text colour, offset 2px.

## Motion

| Token | Value | Use |
| --- | --- | --- |
| `--time-fast` | 100ms | Hover colour change on buttons and the theme control. |
| `--time-base` | 200ms | Disclosure chevron; drawer slide; diagram highlight. |
| `--time-slow` | 300ms | Reserved for a large surface entering. The sign-in splash spinner is timed from it. |
| `--ease` | `cubic-bezier(0.2, 0, 0, 1)` | Every transition. |

- What may move: a control's background and border colour on hover; a
  disclosure chevron turning; the navigation drawer sliding in; a small spinner
  while the system is working.
- Tables, rows, sections and page content do not animate on load.
- With reduced motion requested, every transition and spinner stops.
- Two animations are kept on purpose:
    - **Particle-track canvas.** A small boxed canvas beside the Overview page
      header and in the landing page hero. Ink-grey tracks, never behind text.
      It draws one still frame under reduced motion.
    - **Gateway diagram.** On the landing page, a light travels from the AI
      assistant through the gateway to a backend, highlighting each box as it
      passes. It runs only while on screen and not at all under reduced motion;
      the diagram is complete without it.

## Icons

- One set: Lucide, from the `@lucide/vue` and `@lucide/astro` packages. Markup
  is not pasted by hand.
- 16px beside text; 20px inside a large button. Default stroke, `currentColor`.
- An icon repeats a label; it does not replace one. An icon-only button has an
  accessible name and a tooltip.
- Decorative icons are `aria-hidden`.
- Text glyphs are never icons (no check marks, warning signs, triangles or
  arrows typed as characters). An arrow is allowed only as punctuation inside a
  sentence.
- Status uses the status mark, not an icon.

## Writing

| Rule | Write | Not |
| --- | --- | --- |
| Name the thing and the fix | Your grid proxy has expired. Renew it to keep grid services working. | Access denied (403). |
| Buttons are verb + object | Link certificate | Continue |
| Sentence case everywhere | New token | NEW TOKEN, New Token |
| Relative time, exact time on hover | Expires in 3 days | 2026-11-13T09:14:00Z |
| No filler | Token created | Your token was successfully created! |
| Destructive actions say what is lost | Revoke token. Clients using it stop working immediately. | Are you sure? |
| Empty states say what goes here | No tokens yet. Create one for clients that can't sign in with a browser. | Nothing to show. |
| Product words, not internals | Grid certificate | x509 VOMS proxy credential provider |

Internal terms (config keys, tool-mapping names) appear only on the Admin page,
where the reader is an operator.

## Components

Shared classes live in `portal/src/styles/components.css` and carry an `af-`
prefix. Shared Vue components live in `portal/src/components/ui/`.

| Class or component | What it is for | Use when | Not when |
| --- | --- | --- | --- |
| `af-st` + `af-mark` (`StatusMark`) | A status word with its shape. Tones: `ok`, `warn`, `bad`, `info`, `busy`, `off`. | Showing the state of a service, account, token or job. | Labelling a category (use a tag). Never the mark without a word. |
| `af-btn primary` | The page's main action, filled with the accent. | Once per page at most. | A second action on the same page; inside a banner. |
| `af-btn secondary` | An ordinary action, outlined. | Row and card actions, dialog confirm of a safe action. | |
| `af-btn quiet` | A low-emphasis action with no outline. | Cancel, "view" links at the end of a row. | The only action in a section. |
| `af-btn danger` | A destructive action, red label on the page background. | Revoke, unlink. Always confirmed. | Anything reversible. |
| `af-btn` sizes `s`, `l`, `xl` | 28px, 44px and 52px heights; default is 36px. | `s` in table rows and banners; `xl` only for sign-in on the landing page. | Mixing sizes in one row of actions. |
| `ArmedConfirmButton` | A two-step inline confirm: first click arms, second confirms. | A destructive action too small for a dialog. | Anything that needs an explanation of what is lost. |
| `af-banner` (`warn`, `bad`, `info`, `ok`) | The page-level message: mark, bold title, one sentence, optionally one small button. | The single most urgent thing on the page. | More than one per page; decoration; an accent fill. |
| `af-banner info slim` | A one-line bar in the signed-in shell. | Maintenance mode, on every signed-in page. | Anything specific to one page. |
| `af-note` (`warn`, `bad`, `info`, `ok`) | A tinted inline message at 13px, next to the thing it is about. | Explaining one card, field or section. | Page-level problems (use the banner). |
| `AsyncState` | The loading, session-expired, access-denied, error and empty ladder for a data page. | Around any content fetched from the broker. | Hand-written loading or error markup. |
| `af-tbl-box` + `af-tbl` | A bordered box holding a table with an unfilled header and pale row rules. Add `compact` for compact density; `.num` for numbers, `.sub` for secondary cells, `.act` for the action cell. | Three or more items with the same fields. | Laying out a form or a single record. |
| `af-kv` | A two-column list of label and value. | One record's details. | Comparing several records (use a table). |
| `af-stats` + `af-stat` | A label, a 24px value and an optional 12px line. | Two to four headline numbers. | A number that needs a row of context. |
| `af-field`, `af-input`, `af-check` | Label above the control, hint or error below. Max 360px wide. | Every form control. | A placeholder standing in for a label. |
| `af-copy` (`CopyField`) | A read-only mono value with a Copy button. The button reads "Copied" for two seconds. | A URL, token or command the user pastes elsewhere. | Values nobody copies. |
| `af-tag` | A neutral 22px label for a category. | Permission names, credential types, read or write. | Status. A tag is never coloured. |
| `af-seg` (`SegmentedControl`) | A single-choice switch that applies at once. The selected segment is ink, not the accent. | Switching a range or a filter. | Navigation between pages; more than about four options. |
| `Disclosure` | A button with a chevron that expands a region. | Detail most users do not need (methods of a service, command snippets). | Hiding the page's main content. |
| `InfoTip` | A round icon-only button with a tooltip. | An exact value or a short definition. | Anything needed to complete the task; it is not reachable on touch. |
| `af-dialog` (`ConfirmDialog`) | A modal up to 440px wide. Buttons bottom right, confirming action last, focus starts on Cancel. | A decision that cannot be undone, or a short form. | Anything that fits inline. Never a dialog from a dialog. |
| `af-nav`, `af-nav-group`, `af-nav-label` | The sidebar: grouped links with an icon, an optional count, and the current page marked by weight, a subtle fill and the accent marker. | The signed-in shell only. | In-page tabs. |
| `af-empty` | A dashed box that says what belongs here and offers the action that fills it. | A list with nothing in it. It may carry the page's primary button; the header then does not repeat it. | Errors. |
| `af-help` | Secondary 13px text under a section title. | One or two sentences of explanation. | Warnings. |
| `af-page`, `af-page-head`, `af-sect` | The page root, the header and a titled section. Add `compact` to `af-page` for compact density. | Every signed-in page. | |
| `af-wrap`, `af-topbar`, `af-brand`, `skip-link` | The shell: content column, top bar, facility name, skip link. | Layouts only. | |
| `af-icon` | Sizes and strokes a Lucide icon. | Every icon. | |
| `EntitlementMark` | A matrix cell: check for read, pencil for write, dash for none. | The entitlements matrix and its legend. | Status. |

Cards with a 1px border and 10px radius hold one credential each on Identities,
and one bordered list holds the service rows on Services. Each row or card
leads with a name and a status mark; actions sit on the right.

## Page pattern

Every signed-in page has the same parts in the same order.

1. **Maintenance bar.** Only while maintenance is on. Slim, information colour.
2. **Page header.** A 24px title, one line saying what the page is for, and at
   most one primary button on the right.
3. **Banner slot.** Empty when nothing is wrong. Otherwise the single most
   urgent message for this page. Problem beats warning beats information.
4. **Sections.** Full width, stacked, 32px apart (24px when compact). Each has
   a 16px title and one main component.

The sidebar is the same on every page. Admin appears in it only for operators.

## Pages

| Page | Job | Primary action | Page banner appears when | Main components | Density |
| --- | --- | --- | --- | --- | --- |
| Landing `/` | Say what the platform is; get a facility user signed in. | Sign in (`xl`) | Never | Headline, one paragraph, particle canvas, gateway diagram, three benefits | Spacious |
| Overview | Is my access working? How do I connect a client? | None; Copy on the endpoint | The most urgent of: grid proxy expired (problem); a service misconfigured (problem) or unavailable (warning); grid proxy expiring (warning); a token expiring within 7 days (warning); no account linked at all (information) | Status rows linking to each page, stats, copy field, particle canvas beside the header | Comfortable |
| Services | Which backends and methods can I reach, and why not the others? | None | A service is misconfigured (problem) or unavailable (warning) | Search field, segmented filter, service rows with status, tags and a disclosure of methods | Comfortable |
| Identities | Link external accounts and keep the grid certificate valid. | None in the header; each card has its own link button | Grid proxy expired (problem) or expiring (warning); a link attempt failed (problem); an account was just linked (OK, clears after 5 seconds) | One card per account or credential, notes, key-value lists, confirm dialog | Comfortable |
| Tokens | Create and revoke tokens for clients without browser sign-in. | New token | A token expires within 7 days (warning); a revoke failed (problem) | Table, dialog with copy field, note, disclosure | Comfortable |
| Usage | What have my clients been doing? | None; range control | Never | Segmented control, stats, table per service | Comfortable |
| Entitlements | Which group grants which permission? | None | Never | Matrix table | Compact |
| Admin | Platform state across users; operators only. | None; maintenance toggle in its section | Tool configuration issues are found (warning) | Field, key-value lists, compact tables, status marks | Compact |

Any data page also shows a problem banner when its own data fails to load.

State rules that hold on every page:

- **Not linked is off, not wrong.** An unlinked account shows the off mark, the
  words "Not linked" and a quiet row. It never raises a warning or problem
  banner.
- **A grid proxy warns only when it cannot renew itself and has under 1 hour
  left.** An auto-renewing proxy never shows as expiring.
- **Misconfigured and Unavailable are different.** Misconfigured needs an
  operator: problem mark, plus a reference id to quote. Unavailable is
  temporary: warning mark, nothing to do but wait.
- **Access required** needs an administrator: warning mark and an inline note.
  It never raises a banner.
- **Maintenance** is the slim information bar in the shell, not the page
  banner.

## Do's and Don'ts

### Do:

- **Do** use a token for every colour, type size, radius, shadow and duration.
- **Do** pair every status colour with its shape and a word.
- **Do** keep messages in status colours and actions in the accent.
- **Do** stack full-width sections and let tables use the width.
- **Do** leave the page quiet when nothing is wrong.
- **Do** set literal values in mono and everything else in the text face.

### Don't:

- **Don't** fill a banner or a note with the accent, or use the accent as text.
- **Don't** show more than one page banner or more than one primary button.
- **Don't** use capitals, letter-spacing or a second typeface for hierarchy.
- **Don't** set text below 12px.
- **Don't** add a shadow to anything that belongs to the page, or blur a
  background.
- **Don't** use a tag, a pill or a coloured name to show status.
- **Don't** use text glyphs as icons.
- **Don't** add a third animation.

## How this is enforced

- `portal/src/lib/__tests__/designContract.test.ts` reads every `.vue`,
  `.astro` and `.css` file under `portal/src` and fails, naming file and line,
  on: literal colours outside `global.css`; type sizes and font families that
  are not tokens; uppercase or letter-spaced text; background blur; any shadow
  other than the two tokens or an inset ring; radii that are not tokens; and
  text glyphs used as icons.
- `portal/src/lib/__tests__/globalCssContrast.test.ts` reads the colour tokens
  from `global.css` and checks, in both themes: text colours at 4.5:1 on both
  backgrounds; on-accent at 4.5:1 on the accent; each banner's text at 4.5:1 on
  its fill; each status colour at 3:1 on the page.
- `pixi run -e portal design-preview` serves every page with example data in a
  healthy or a problems scenario. `portal/scripts/design-screenshots.mjs`
  captures each page at desktop and phone widths in both themes for review.
- How the styling is built: `docs/portal-styling.md`.

## Reference

`docs/design-language/index.html` is the worked reference: every definition
above with rendered examples, do and don't pairs, and controls to try a
facility accent in both themes.
