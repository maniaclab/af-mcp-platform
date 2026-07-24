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

export interface LinkedErrorParams {
  /** The `id` from `?linked_error_alias=<id>` -- which provider failed to link. */
  alias: string;
  /** The OAuth 2.1 `error` code from `?linked_error=<code>` (e.g. "server_error"). */
  code: string;
  /** The `linked_error_description`, or null if the AS didn't send one. */
  description: string | null;
  /** *search*'s query string with all `linked_error*` params removed. */
  remainingSearch: string;
}

/**
 * Parses the `?linked_error_alias=<id>&linked_error=<code>&linked_error_description=<desc>`
 * params an OAuth 2.1 linking callback attaches to its redirect back to the
 * Identities page when the backend authorization server itself failed (see
 * broker/src/af_mcp_broker/api/oauth21.py's `callback` route and
 * oauth_state.py's `append_linked_error_params`), so IdentitiesPage.vue can
 * show an error banner instead of the raw 422 the broker used to return.
 *
 * `linked_error_uri` is intentionally not parsed here -- it's an OAuth 2.1
 * informational field the broker passes through for server-side log
 * correlation only, not something the portal renders.
 *
 * Returns null when `linked_error` isn't present at all (the common case).
 */
export function extractLinkedErrorParams(search: string): LinkedErrorParams | null {
  const params = new URLSearchParams(search);
  const code = params.get('linked_error');
  if (!code) return null;
  const alias = params.get('linked_error_alias') ?? code;
  const description = params.get('linked_error_description');
  params.delete('linked_error_alias');
  params.delete('linked_error');
  params.delete('linked_error_description');
  params.delete('linked_error_uri');
  const remaining = params.toString();
  return { alias, code, description, remainingSearch: remaining ? `?${remaining}` : '' };
}
