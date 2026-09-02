/**
 * branding.ts — per-deployment site identity, resolved at runtime.
 *
 * This is a static build (astro.config.mjs `output: 'static'`), so any
 * per-deployment text has to come from `/config.json` (see auth.ts's
 * `getBranding()`, which loads it) and get patched into the DOM after
 * mount — the same runtime-config pattern OIDC settings and brokerOrigin
 * already use. DEFAULT_BRANDING is what every page shows before that
 * patch runs (and what a deployment with no `portal.branding.*` values set
 * keeps showing, unchanged from before this existed).
 */

export interface BrandingConfig {
  /** Short mark in the sidebar/topbar logo, e.g. "AF / MCP". */
  shortName: string;
  /** Full platform name, e.g. in the sidebar logo's aria-label. */
  fullName: string;
  /** Facility/institution name shown in the overview hero and footer. */
  facilityName: string;
}

export const DEFAULT_BRANDING: BrandingConfig = {
  shortName: 'AF / MCP',
  fullName: 'AF MCP Platform',
  facilityName: 'ATLAS Analysis Facility',
};

/**
 * Patches every `[data-af-brand]` element in *doc* from *config* — falls
 * back to DEFAULT_BRANDING's value for any field a deployment leaves
 * unset (an empty string in config.json, same convention as
 * `getBrokerOrigin`'s brokerOrigin fallback). Elements carrying
 * `data-af-brand-target="aria-label"` get their `aria-label` attribute
 * set instead of textContent, for the two logo links which use the name
 * as their accessible label, not their visible text.
 */
export function applyBranding(config: BrandingConfig, doc: Document = document): void {
  const merged: BrandingConfig = {
    shortName: config.shortName || DEFAULT_BRANDING.shortName,
    fullName: config.fullName || DEFAULT_BRANDING.fullName,
    facilityName: config.facilityName || DEFAULT_BRANDING.facilityName,
  };

  doc.querySelectorAll<HTMLElement>('[data-af-brand]').forEach((el) => {
    const field = el.dataset.afBrand as keyof BrandingConfig | undefined;
    if (!field || !(field in merged)) return;
    const value = merged[field];
    if (el.dataset.afBrandTarget === 'aria-label') {
      el.setAttribute('aria-label', value);
    } else {
      el.textContent = value;
    }
  });
}
