import { describe, expect, it } from 'vitest';

import { applyBranding, DEFAULT_BRANDING, safeHttpUrl } from '../branding';
import type { BrandingConfig } from '../branding';

function domWithBrandTags(): Document {
  document.body.innerHTML = `
    <a data-af-brand="shortName">placeholder</a>
    <a data-af-brand="fullName" data-af-brand-target="aria-label" aria-label="placeholder">logo text</a>
    <a data-af-brand-link="facilityUrl"><span data-af-brand="facilityName">placeholder</span></a>
    <span data-af-no-brand>untouched</span>
  `;
  return document;
}

describe('DEFAULT_BRANDING', () => {
  it('names no facility, so a deployment that sets nothing shows a neutral identity', () => {
    for (const value of Object.values(DEFAULT_BRANDING)) {
      expect(value).not.toMatch(/ATLAS|CERN/i);
    }
    expect(DEFAULT_BRANDING.facilityName).toBe('Analysis Facility');
  });
});

describe('applyBranding', () => {
  it('patches textContent for a plain [data-af-brand] element', () => {
    const doc = domWithBrandTags();
    applyBranding({ shortName: 'Example AF Ops', fullName: '', facilityName: '' }, doc);
    expect(doc.querySelector('[data-af-brand="shortName"]')?.textContent).toBe('Example AF Ops');
  });

  it('patches aria-label instead of textContent when data-af-brand-target="aria-label"', () => {
    const doc = domWithBrandTags();
    applyBranding({ shortName: '', fullName: 'Example AF Ops Platform', facilityName: '' }, doc);
    const el = doc.querySelector('[data-af-brand="fullName"]');
    expect(el?.getAttribute('aria-label')).toBe('Example AF Ops Platform');
    // textContent is untouched -- this element is targeted by aria-label only.
    expect(el?.textContent).toBe('logo text');
  });

  it('falls back to DEFAULT_BRANDING for any empty field', () => {
    const doc = domWithBrandTags();
    const emptyConfig: BrandingConfig = { shortName: '', fullName: '', facilityName: '' };
    applyBranding(emptyConfig, doc);
    expect(doc.querySelector('[data-af-brand="shortName"]')?.textContent).toBe(
      DEFAULT_BRANDING.shortName,
    );
    expect(doc.querySelector('[data-af-brand="facilityName"]')?.textContent).toBe(
      DEFAULT_BRANDING.facilityName,
    );
  });

  it('leaves elements without [data-af-brand] untouched', () => {
    const doc = domWithBrandTags();
    applyBranding({ shortName: 'X', fullName: 'Y', facilityName: 'Z' }, doc);
    expect(doc.querySelector('[data-af-no-brand]')?.textContent).toBe('untouched');
  });
});

describe('safeHttpUrl', () => {
  it.each(['https://af.example.org/', 'http://af.example.org/path?q=1'])('accepts %s', (url) => {
    expect(safeHttpUrl(url)).toBe(url);
  });

  it.each([
    '',
    undefined,
    'javascript:alert(1)',
    'data:text/html,x',
    'ftp://af.example.org',
    'af.example.org',
    'not a url',
  ])('rejects %s', (url) => {
    expect(safeHttpUrl(url)).toBeUndefined();
  });
});

describe('applyBranding facilityUrl', () => {
  const config: BrandingConfig = { shortName: '', fullName: '', facilityName: 'Example AF' };

  it('links the facility name to an http(s) facilityUrl, opening safely in a new tab', () => {
    const doc = domWithBrandTags();
    applyBranding({ ...config, facilityUrl: 'https://af.example.org/' }, doc);
    const link = doc.querySelector('[data-af-brand-link="facilityUrl"]');
    expect(link?.getAttribute('href')).toBe('https://af.example.org/');
    expect(link?.getAttribute('target')).toBe('_blank');
    expect(link?.getAttribute('rel')).toBe('noopener noreferrer');
    expect(link?.textContent).toBe('Example AF');
  });

  it.each([undefined, '', 'javascript:alert(1)'])(
    'leaves the name unlinked for %s',
    (facilityUrl) => {
      const doc = domWithBrandTags();
      applyBranding({ ...config, facilityUrl }, doc);
      const link = doc.querySelector('[data-af-brand-link="facilityUrl"]');
      expect(link?.hasAttribute('href')).toBe(false);
      expect(link?.hasAttribute('target')).toBe(false);
      expect(link?.textContent).toBe('Example AF');
    },
  );
});
