/**
 * identityTarget.ts — which Identities page row a URL hash points at. Services
 * and Overview link to `/identities/#identity-card-<id>`; the page marks that
 * row so the user can see which identity the link is about.
 */

const ANCHOR_PREFIX = 'identity-card-';

/** The id in a `#identity-card-<id>` hash, or null if the hash names no id in *ids*. */
export function identityTargetFromHash(hash: string, ids: readonly string[]): string | null {
  const anchor = hash.replace(/^#/, '');
  if (!anchor.startsWith(ANCHOR_PREFIX)) return null;
  const id = anchor.slice(ANCHOR_PREFIX.length);
  return ids.includes(id) ? id : null;
}
