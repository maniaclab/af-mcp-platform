/**
 * Every page links the platform icon, and the icon goes through Vite's asset
 * pipeline: nginx caches *.svg as immutable for a year, so an icon served
 * from public/ under a fixed name would never refresh after a change.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

const read = (path: string) => readFileSync(join(process.cwd(), path), 'utf8');
const LAYOUTS = ['src/layouts/Base.astro', 'src/layouts/PublicBase.astro'];

describe('favicon', () => {
  it.each(LAYOUTS)('%s links the SVG icon imported from src/assets', (layout) => {
    const source = read(layout);
    expect(source).toMatch(/import faviconUrl from '\.\.\/assets\/favicon\.svg\?url';/);
    expect(source).toMatch(/<link rel="icon" type="image\/svg\+xml" href=\{faviconUrl\} \/>/);
  });

  it('is a square SVG with no script or external reference', () => {
    const svg = read('src/assets/favicon.svg');
    expect(svg).toMatch(/^<svg xmlns="http:\/\/www\.w3\.org\/2000\/svg" viewBox="0 0 64 64">/);
    expect(svg).not.toMatch(/<script|href=|url\(/i);
  });
});
