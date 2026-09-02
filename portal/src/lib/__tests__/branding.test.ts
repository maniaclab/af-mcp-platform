import { describe, expect, it } from 'vitest';

import { applyBranding, DEFAULT_BRANDING } from '../branding';
import type { BrandingConfig } from '../branding';

function domWithBrandTags(): Document {
  document.body.innerHTML = `
    <a data-af-brand="shortName">placeholder</a>
    <a data-af-brand="fullName" data-af-brand-target="aria-label" aria-label="placeholder">logo text</a>
    <span data-af-brand="facilityName">placeholder</span>
    <span data-af-no-brand>untouched</span>
  `;
  return document;
}

describe('applyBranding', () => {
  it('patches textContent for a plain [data-af-brand] element', () => {
    const doc = domWithBrandTags();
    applyBranding({ shortName: 'UChicago AF Ops', fullName: '', facilityName: '' }, doc);
    expect(doc.querySelector('[data-af-brand="shortName"]')?.textContent).toBe('UChicago AF Ops');
  });

  it('patches aria-label instead of textContent when data-af-brand-target="aria-label"', () => {
    const doc = domWithBrandTags();
    applyBranding({ shortName: '', fullName: 'UChicago AF Ops Platform', facilityName: '' }, doc);
    const el = doc.querySelector('[data-af-brand="fullName"]');
    expect(el?.getAttribute('aria-label')).toBe('UChicago AF Ops Platform');
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
