/**
 * catalog.ts — pure client-side joins between /v1/catalog's
 * `credential_provider` field and /v1/identities' provider list (issue #90).
 * There is no broker endpoint for this join -- it is built here from data
 * both the Services and Identities pages already fetch.
 *
 * Kept as plain data-in/data-out functions (no DOM/fetch access) so they're
 * trivially unit-testable, same pattern as lib/linkedBanner.ts.
 */
import type { CatalogServer, IdentityProvider } from './api';

/** What a server card's "Powered by" affordance should show. */
export interface PoweredBy {
  /** "identity" -- an identity_providers entry (x509 included: since #182
   *  it is an ordinary entry whose alias appears in the providers list);
   *  "none" -- auth_type "none", no user credential required at all. */
  kind: 'identity' | 'none';
  label: string;
  /** null when there is no linked/unlinked concept ("none"). */
  linked: boolean | null;
  /** Where the card's affordance should link to, or null when there's
   *  nothing to link to ("none"). */
  linkHref: string | null;
}

export function resolvePoweredBy(
  credentialProvider: string | null,
  providers: IdentityProvider[],
): PoweredBy {
  if (credentialProvider === null) {
    return { kind: 'none', label: 'No credential required', linked: null, linkHref: null };
  }
  const provider = providers.find((p) => p.id === credentialProvider);
  return {
    kind: 'identity',
    label: provider?.display_name ?? credentialProvider,
    linked: provider?.linked ?? false,
    linkHref: '/identities/',
  };
}

/**
 * Groups catalog servers by the identity alias that services them, for the
 * Identities page's "What each identity unlocks" grid. Credential-less
 * ("none") servers are omitted -- there is no identity_providers row to
 * attach them to. x509-serviced servers group like any other: since #182
 * their alias is a real identity_providers entry rendered on that page.
 */
export function groupServersByAlias(servers: CatalogServer[]): Map<string, CatalogServer[]> {
  const grouped = new Map<string, CatalogServer[]>();
  for (const server of servers) {
    const alias = server.credential_provider;
    if (alias === null) continue;
    const existing = grouped.get(alias);
    if (existing) {
      existing.push(server);
    } else {
      grouped.set(alias, [server]);
    }
  }
  return grouped;
}
