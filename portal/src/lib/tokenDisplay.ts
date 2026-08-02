/**
 * tokenDisplay.ts — pure display-derivation helpers for TokensPage.vue's
 * token list (issue #115): deriving an active/revoked/expired status and a
 * compact "token id" from a full jti. Kept dependency-free (no DOM, no
 * implicit Date.now() reads inside tokenStatus) so they're trivially
 * unit-testable -- the caller supplies `now` explicitly rather than this
 * module reading the clock itself.
 */

export type TokenStatus = 'active' | 'revoked' | 'expired';

export interface TokenStatusInput {
  revoked_at: string | null;
  expires_at: string;
}

/**
 * Derives a token's display status. Revoked always wins over expired (a
 * token can be both, e.g. revoked shortly before its natural expiry) since
 * "revoked" is the more informative reason a caller stopped trusting it.
 */
export function tokenStatus(row: TokenStatusInput, now: number = Date.now()): TokenStatus {
  if (row.revoked_at) return 'revoked';
  if (Date.parse(row.expires_at) <= now) return 'expired';
  return 'active';
}

/**
 * First 8 characters of a jti plus an ellipsis, for a compact but still
 * recognizable "token id" column. The full jti is always available via a
 * `title` attribute on the caller's side -- this never silently drops
 * information the user can't get back to.
 */
export function shortJti(jti: string): string {
  return jti.length <= 8 ? jti : `${jti.slice(0, 8)}…`;
}
