/**
 * Scrollbars follow the theme in every browser. Browsers draw a native
 * scrollbar from `color-scheme`, and Firefox's result for a dark theme reads as
 * a light track, so Basecoat's `scrollbar` component sets `scrollbar-color`
 * explicitly from the portal tokens. `scrollbar-color` is inherited, so one
 * class on `<html>` covers the page, dialogs and every scrolling table box.
 */
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

const read = (path: string) => readFileSync(resolve(process.cwd(), path), 'utf8');

describe('scrollbars', () => {
  const css = read('src/styles/global.css');

  it("imports Basecoat's scrollbar component", () => {
    expect(css).toContain("@import 'basecoat-css/components/scrollbar';");
  });

  it("draws the thumb from a portal token, not Basecoat's near-invisible border colour", () => {
    expect(css).toMatch(/--scrollbar-thumb:\s*var\(--color-af-border-strong\)/);
  });

  it.each(['src/layouts/Base.astro', 'src/layouts/PublicBase.astro'])(
    'puts the scrollbar class on <html> in %s',
    (layout) => {
      const html = read(layout).match(/<html[^>]*>/)?.[0] ?? '';
      expect(html).toMatch(/class="[^"]*\bscrollbar\b/);
    },
  );
});
