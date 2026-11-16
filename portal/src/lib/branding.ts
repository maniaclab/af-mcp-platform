/**
 * branding.ts — per-deployment site identity, resolved at runtime.
 *
 * This is a static build (astro.config.mjs `output: 'static'`), so any
 * per-deployment text has to come from `/config.json` (see auth.ts's
 * `getBranding()`, which loads it) and get patched into the DOM after
 * mount — the same runtime-config pattern OIDC settings and brokerOrigin
 * already use. DEFAULT_BRANDING is what every page shows before that
 * patch runs (and what a deployment with no `portal.branding.*` values set
 * keeps showing). The defaults name no facility.
 */

export interface BrandingConfig {
  /** Short mark in the sidebar/topbar logo, e.g. "AF / MCP". */
  shortName: string;
  /** Full platform name, e.g. in the sidebar logo's aria-label. */
  fullName: string;
  /** Facility/institution name shown in the overview hero and footer. */
  facilityName: string;
  /** Optional http(s) URL of the facility's website; when valid, the footer links the facility name to it. Empty/absent leaves the name unlinked. */
  facilityUrl?: string;
  /** Optional `#rrggbb` accent for the light theme. Empty/absent keeps the neutral ink default (see accent.ts). */
  accentColor?: string;
  /** Optional `#rrggbb` accent for the dark theme. Empty/absent derives it from accentColor (see accent.ts). */
  accentColorDark?: string;
}

export const DEFAULT_BRANDING: BrandingConfig = {
  shortName: 'AF / MCP',
  fullName: 'AF MCP Platform',
  facilityName: 'Analysis Facility',
};

/**
 * Returns *value* when it parses as an http(s) URL, else undefined, so a
 * misconfigured `javascript:` or `data:` URL is never rendered as a link.
 */
export function safeHttpUrl(value: string | undefined): string | undefined {
  if (!value) return undefined;
  try {
    const { protocol } = new URL(value);
    return protocol === 'http:' || protocol === 'https:' ? value : undefined;
  } catch {
    return undefined;
  }
}

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
  const merged: Pick<BrandingConfig, 'shortName' | 'fullName' | 'facilityName'> = {
    shortName: config.shortName || DEFAULT_BRANDING.shortName,
    fullName: config.fullName || DEFAULT_BRANDING.fullName,
    facilityName: config.facilityName || DEFAULT_BRANDING.facilityName,
  };

  doc.querySelectorAll<HTMLElement>('[data-af-brand]').forEach((el) => {
    const field = el.dataset.afBrand as keyof typeof merged | undefined;
    if (!field || !(field in merged)) return;
    const value = merged[field];
    if (el.dataset.afBrandTarget === 'aria-label') {
      el.setAttribute('aria-label', value);
    } else {
      el.textContent = value;
    }
  });

  // The `<a>` carries no href in the static markup, so it is plain text until
  // a valid facilityUrl arrives. External, so it opens in a new tab like the
  // portal's other external links.
  const facilityUrl = safeHttpUrl(config.facilityUrl);
  doc.querySelectorAll<HTMLAnchorElement>('[data-af-brand-link="facilityUrl"]').forEach((a) => {
    if (facilityUrl) {
      a.setAttribute('href', facilityUrl);
      a.setAttribute('target', '_blank');
      a.setAttribute('rel', 'noopener noreferrer');
    } else {
      a.removeAttribute('href');
      a.removeAttribute('target');
      a.removeAttribute('rel');
    }
  });
}
