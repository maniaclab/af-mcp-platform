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

/** The minimal provider shape resolveLinkedBanner/resolveLinkedErrorBanner need
 * to look up a display_name — deliberately narrower than api.ts's
 * IdentityProvider so this module stays a self-contained leaf. */
export interface BannerProvider {
  id: string;
  display_name: string;
}

/**
 * Resolves the "Linked successfully" banner text for a parsed `linked` id,
 * given the current provider list. Returns null when there's nothing to
 * show: no `linked` param, or an id that doesn't match a real provider — the
 * OAuth callback would only ever set a real id, so an unrecognized one is
 * either a stale bookmark or someone poking at the URL, not a genuine
 * success (see issue #81).
 */
export function resolveLinkedBanner(
  providers: BannerProvider[],
  linkedId: string | null,
): string | null {
  if (!linkedId) return null;
  const linked = providers.find((p) => p.id === linkedId);
  return linked ? linked.display_name : null;
}

/**
 * Resolves the linking-failure banner text for parsed `linked_error*` params,
 * given the current provider list. Same "only show for a known provider"
 * guard as resolveLinkedBanner, and the same reasoning (see issue #81).
 */
export function resolveLinkedErrorBanner(
  providers: BannerProvider[],
  linkedError: LinkedErrorParams | null,
): string | null {
  if (!linkedError) return null;
  const failed = providers.find((p) => p.id === linkedError.alias);
  if (!failed) return null;
  const reason = linkedError.description ?? linkedError.code;
  return `Linking ${failed.display_name} failed: ${reason}`;
}
