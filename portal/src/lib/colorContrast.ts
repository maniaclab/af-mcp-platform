/**
 * colorContrast.ts — WCAG 2.1 sRGB relative-luminance contrast ratio, used
 * by src/lib/__tests__/globalCssContrast.test.ts to keep global.css's
 * documented ratios (in its token comments and in DESIGN.md's Theming
 * section) honest as the palette evolves, instead of trusting a
 * point-in-time calculation that can silently drift out of sync with the
 * actual values.
 */

/** #rgb or #rrggbb -> [r, g, b] in [0, 255]. Throws on anything else — this module only needs to parse the plain hex literals global.css's color tokens use. */
export function parseHexColor(hex: string): [number, number, number] {
  const normalized = hex.trim().replace(/^#/, '');
  const full =
    normalized.length === 3
      ? normalized
          .split('')
          .map((c) => c + c)
          .join('')
      : normalized;
  if (!/^[0-9a-fA-F]{6}$/.test(full)) {
    throw new Error(`parseHexColor: "${hex}" is not a #rgb or #rrggbb color`);
  }
  return [
    parseInt(full.slice(0, 2), 16),
    parseInt(full.slice(2, 4), 16),
    parseInt(full.slice(4, 6), 16),
  ];
}

function linearize(channel255: number): number {
  const c = channel255 / 255;
  return c <= 0.04045 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4);
}

/** WCAG relative luminance (0..1) of a hex color. */
export function relativeLuminance(hex: string): number {
  const [r, g, b] = parseHexColor(hex);
  return 0.2126 * linearize(r) + 0.7152 * linearize(g) + 0.0722 * linearize(b);
}

/** WCAG contrast ratio (1..21) between two hex colors, order-independent. */
export function contrastRatio(hexA: string, hexB: string): number {
  const lA = relativeLuminance(hexA);
  const lB = relativeLuminance(hexB);
  const [lighter, darker] = lA > lB ? [lA, lB] : [lB, lA];
  return (lighter + 0.05) / (darker + 0.05);
}
