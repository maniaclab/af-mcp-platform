/**
 * The footer is the one place a facility name is rendered outside the
 * branding configuration: it must take the name from DEFAULT_BRANDING (which
 * applyBranding then overrides from /config.json) and carry no facility link
 * of its own.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

const FOOTER = readFileSync(join(process.cwd(), 'src/components/Footer.astro'), 'utf8');

describe('Footer.astro', () => {
  it('does not hardcode a facility name or link', () => {
    expect(FOOTER).not.toMatch(/ATLAS|atlas\.cern/i);
  });

  it('renders the default facility name from DEFAULT_BRANDING', () => {
    expect(FOOTER).toContain('DEFAULT_BRANDING.facilityName');
  });
});
