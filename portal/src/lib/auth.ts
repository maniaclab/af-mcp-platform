/**
 * auth.ts — reads identity injected by oauth2-proxy ForwardAuth middleware.
 *
 * oauth2-proxy injects headers on every authenticated request:
 *   X-Auth-Request-User     → username (e.g. "kratsg")
 *   X-Auth-Request-Email    → email (e.g. "kratsg@uchicago.edu")
 *   X-Auth-Request-Groups   → comma-separated group memberships
 *   Authorization           → "Bearer <AF Keycloak access token>"
 *
 * In Astro SSG the page is pre-rendered; at runtime (client-side) we read
 * the values that Base.astro injected into <meta> tags from the server
 * request headers.  This avoids sending the token over a client-side fetch
 * just to learn who the user is.
 */

export interface AFUser {
  username: string;
  email: string;
  groups: string[];
}

/** Returns the authenticated user from the meta tags injected by Base.astro. */
export function getUser(): AFUser | null {
  if (typeof document === 'undefined') return null;

  const email    = document.querySelector<HTMLMetaElement>('meta[name="af-user-email"]')?.content ?? '';
  const username = document.querySelector<HTMLMetaElement>('meta[name="af-user-username"]')?.content ?? '';
  const groupsRaw= document.querySelector<HTMLMetaElement>('meta[name="af-user-groups"]')?.content ?? '';

  if (!email && !username) return null;

  return {
    email,
    username,
    groups: groupsRaw ? groupsRaw.split(',').map(g => g.trim()).filter(Boolean) : [],
  };
}
