/**
 * tokenDisplay.ts — pure display-derivation helpers for TokensPage.vue's
 * token list: deriving an active/revoked/expired status and a compact
 * "token id" from a full lookup_id (issue #144 step 2a renamed the
 * identifier from `jti` -- a broker-issued PAT has no JWT, so no jti).
 * Kept dependency-free (no DOM, no implicit Date.now() reads inside
 * tokenStatus) so they're trivially unit-testable -- the caller supplies
 * `now` explicitly rather than this module reading the clock itself.
 */

export type TokenStatus = 'active' | 'revoked' | 'expired';

export interface TokenStatusInput {
  revoked_at: string | null;
  // null means the PAT never expires (an explicit opt-in at mint time --
  // see api/tokens.py's MintTokenRequest.never_expires) -- never treated as
  // expired.
  expires_at: string | null;
}

/**
 * Derives a token's display status. Revoked always wins over expired (a
 * token can be both, e.g. revoked shortly before its natural expiry) since
 * "revoked" is the more informative reason a caller stopped trusting it.
 */
export function tokenStatus(row: TokenStatusInput, now: number = Date.now()): TokenStatus {
  if (row.revoked_at) return 'revoked';
  if (row.expires_at !== null && Date.parse(row.expires_at) <= now) return 'expired';
  return 'active';
}

/**
 * First 8 characters of a lookup_id plus an ellipsis, for a compact but
 * still recognizable "token id" column. The full lookup_id is always
 * available via a `title` attribute on the caller's side -- this never
 * silently drops information the user can't get back to.
 */
export function shortLookupId(lookupId: string): string {
  return lookupId.length <= 8 ? lookupId : `${lookupId.slice(0, 8)}…`;
}

// The broker still allows notes up to 256 chars server-side (api/tokens.py's
// _MAX_NOTE_LENGTH) -- unchanged; shrinking that limit would be an API
// contract change breaking any existing caller (docs/connecting-a-client.md's
// curl/Python snippets, CI scripts) with no correctness benefit, now that the
// note is never squeezed into a fixed-width table cell (issue #152). This
// constant is a UI-only cap: it's both the mint form's textarea `maxlength`
// (TokensPage.vue) for newly-minted notes, and truncateNote's default below,
// which keeps the (i) icon's hover/focus tooltip a modest size even for a
// note minted before this cap existed (up to the old 256-char ceiling).
export const NOTE_MAX_LENGTH = 100;

/**
 * Truncates a token's free-text note (issue #116) for display in the (i)
 * info icon's hover/focus tooltip (issue #152 -- previously rendered inline
 * under the token name, which stretched the name column while still
 * truncating the note). `null` (no note supplied) passes through unchanged.
 */
export function truncateNote(
  note: string | null,
  maxLength: number = NOTE_MAX_LENGTH,
): string | null {
  if (note === null) return null;
  return note.length <= maxLength ? note : `${note.slice(0, maxLength)}…`;
}

/**
 * Display label for a token row's `permission_grant` (issue #144 step 4).
 *
 * `null` means an ordinary identity PAT -- its authority is always the
 * caller's CURRENT permissions, re-derived fresh on every request, so
 * "full account access" is the accurate description rather than "no
 * permissions": there is no restriction narrowing it below that. A
 * non-null (possibly empty) array means a permission PAT scoped to at
 * most those permission names -- sorted for a stable, comparison-friendly
 * display regardless of what order the broker happened to return them in.
 */
export function permissionGrantLabel(permissionGrant: string[] | null): string {
  if (permissionGrant === null) return 'Full account access';
  if (permissionGrant.length === 0) return 'No permissions';
  return [...permissionGrant].sort().join(', ');
}
