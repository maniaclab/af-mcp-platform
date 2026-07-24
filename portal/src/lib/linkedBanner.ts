/**
 * linkedBanner.ts — parses the `?linked=<id>` query param an OAuth 2.1
 * linking callback (see broker/src/af_mcp_broker/api/oauth21.py's
 * `callback` route) attaches to its redirect back to the Identities page,
 * so IdentitiesPage.vue can show a "Linked successfully" confirmation.
 *
 * Kept as plain string-in/object-out functions (no DOM access) so they're
 * trivially unit-testable — the caller is responsible for reading
 * `window.location.search` and calling `history.replaceState()`.
 */

export interface LinkedParam {
  /** The `id` from `?linked=<id>`, or null if the param wasn't present. */
  linkedId: string | null;
  /** *search*'s query string with `linked` removed — "" or "?key=value". */
  remainingSearch: string;
}

export function extractLinkedParam(search: string): LinkedParam {
  const params = new URLSearchParams(search);
  const linkedId = params.get('linked');
  params.delete('linked');
  const remaining = params.toString();
  return { linkedId, remainingSearch: remaining ? `?${remaining}` : '' };
}
