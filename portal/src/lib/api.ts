/**
 * api.ts — typed broker API client.
 *
 * Auth model: the portal is its own OAuth public client (see ../lib/auth) and
 * sends its own `aud=mcp-gateway` Bearer on every request — the broker
 * validates it directly, the same way it validates any other caller's token.
 * There's no cookie in this path any more: oauth2-proxy now only gates the
 * portal's HTML/static assets, not `/v1` or `/mcp` (see #42).
 *
 * On a 401, we attempt one silent renew (refresh_token grant) and retry the
 * request once before giving up. If that still 401s, or there was no session
 * to renew in the first place, callers get a SessionExpiredError and should
 * surface a "reload to re-authenticate" prompt rather than treating it as a
 * hard error — reloading re-runs Base.astro's OIDC check.
 *
 * Local dev exception: when OIDC isn't configured at all (see ../lib/auth),
 * requests go out with no Authorization header rather than failing fast —
 * that's the `pixi run -e portal dev` + `pixi run -e bypass broker` combo,
 * where BROKER_DEV_INSECURE_PRINCIPAL supplies the principal server-side and
 * the broker doesn't check for a Bearer at all.
 */
import { getAccessToken, isOidcConfigured, renewAccessToken } from './auth';

// PUBLIC_BROKER_URL MUST include the `/v1` suffix when overridden
// (e.g. https://mcp.af.uchicago.edu/v1). It replaces the base wholesale, so a
// value without `/v1` would silently drop the API prefix. Default is the
// same-origin `/v1` path served behind oauth2-proxy.
const API_BASE = (import.meta.env.PUBLIC_BROKER_URL ?? '/v1') as string;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

export class APIError extends Error {
  constructor(
    public readonly status: number,
    public readonly statusText: string,
    public readonly body: string,
  ) {
    super(`${status} ${statusText}: ${body}`);
    this.name = 'APIError';
  }
}

/** Thrown when there's no valid (or renewable) OIDC session to authenticate a request with. */
export class SessionExpiredError extends Error {
  constructor() {
    super('Session expired');
    this.name = 'SessionExpiredError';
  }
}

/**
 * Every SessionExpiredError, from whichever call site below, invalidates the
 * identities cache — a session expiring means the next fetchIdentities()
 * must go back to the broker rather than serve stale cached data through a
 * dead session.
 */
function throwSessionExpired(): never {
  clearIdentitiesCache();
  throw new SessionExpiredError();
}

async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const token = await getAccessToken();
  if (!token && (await isOidcConfigured())) {
    // OIDC is configured but there's no session (or renewal already failed
    // inside getAccessToken) — skip the round trip, it would just 401.
    throwSessionExpired();
  }

  const doFetch = (bearer: string | null) =>
    fetch(`${API_BASE}${path}`, {
      ...init,
      headers: {
        'Content-Type': 'application/json',
        ...(init?.headers ?? {}),
        ...(bearer ? { Authorization: `Bearer ${bearer}` } : {}),
      },
    });

  let res = await doFetch(token);
  if (res.status === 401 && (await isOidcConfigured())) {
    // The broker rejected a token that looked unexpired locally (clock skew,
    // server-side revocation) — try one silent renew before giving up.
    const renewed = await renewAccessToken();
    if (renewed) {
      res = await doFetch(renewed);
    }
    if (res.status === 401) {
      throwSessionExpired();
    }
  }
  if (!res.ok) {
    const body = await res.text().catch(() => '');
    throw new APIError(res.status, res.statusText, body);
  }
  // 204 No Content — return undefined cast to T
  if (res.status === 204) return undefined as unknown as T;
  return res.json() as Promise<T>;
}

// ---------------------------------------------------------------------------
// Identities — GET /v1/identities
// ---------------------------------------------------------------------------

/** "keycloak-brokered" — Keycloak's stored-broker-token pattern; "oauth21-direct"
 * — the broker acting as a direct OAuth 2.1 client. The portal never needs
 * to branch display logic on this — it's carried through mainly so
 * IdentityLink.vue knows which linking mechanism `link_url` belongs to. */
export type ProviderType = 'keycloak-brokered' | 'oauth21-direct';

export interface IdentityProvider {
  /** Portal-facing stable identifier (e.g. "atlas-iam", or an OAuth 2.1 provider's alias). */
  id: string;
  type: ProviderType;
  display_name: string;
  /** Human-readable description of what linking this provider enables. */
  enables: string;
  linked: boolean;
  /** URL to navigate the browser to in order to link this provider, or null if linking isn't possible right now. */
  link_url: string | null;
}

export interface IdentitiesResponse {
  subject: string;
  email: string;
  unixname: string;
  uid: number;
  gid: number;
  groups: string[];
  providers: IdentityProvider[];
}

// Identity data (providers[].linked) changes only when the user completes a
// linking flow, so every portal page load hitting the broker for it is
// wasted work — Base.astro's inline script calls fetchIdentities() on every
// page to populate the nav's username display. sessionStorage-cache it with
// a short TTL: long enough to cover a typical rapid-nav session, short
// enough not to go stale if something changes the identity out from under a
// lingering tab. Explicit invalidation (see clearIdentitiesCache()) handles
// the cases that actually change this data: a session expiring, a
// keycloak-brokered LINK_IDP callback completing (callback.astro), and an
// oauth21-direct linking flow's callback landing back on the Identities page
// with a `?linked=<id>` query param (see IdentitiesPage.vue).
const IDENTITIES_CACHE_KEY = 'af-portal.identities';
const IDENTITIES_CACHE_TTL_MS = 5 * 60 * 1000;

interface CachedIdentities {
  data: IdentitiesResponse;
  expiresAt: number;
}

function readIdentitiesCache(): IdentitiesResponse | null {
  const raw = window.sessionStorage.getItem(IDENTITIES_CACHE_KEY);
  if (!raw) return null;
  let cached: CachedIdentities;
  try {
    cached = JSON.parse(raw) as CachedIdentities;
  } catch {
    // Corrupt entry (shouldn't happen since we're the only writer) — treat
    // as a miss rather than throwing.
    return null;
  }
  if (cached.expiresAt <= Date.now()) return null;
  return cached.data;
}

function writeIdentitiesCache(data: IdentitiesResponse): void {
  const cached: CachedIdentities = { data, expiresAt: Date.now() + IDENTITIES_CACHE_TTL_MS };
  window.sessionStorage.setItem(IDENTITIES_CACHE_KEY, JSON.stringify(cached));
}

/**
 * Invalidates the identities cache. Called on SessionExpiredError (see
 * throwSessionExpired()) and by callback.astro once a LINK_IDP callback
 * completes, so the next fetchIdentities() reflects the newly-linked
 * provider instead of serving the pre-link snapshot for up to the full TTL.
 */
export function clearIdentitiesCache(): void {
  window.sessionStorage.removeItem(IDENTITIES_CACHE_KEY);
}

export async function fetchIdentities(): Promise<IdentitiesResponse> {
  const cached = readIdentitiesCache();
  if (cached) return Promise.resolve(cached);

  const data = await apiFetch<IdentitiesResponse>('/identities');
  writeIdentitiesCache(data);
  return data;
}

// NOTE on linking mechanisms: every provider row carries its
// own `link_url` and the click handler is a plain `window.location.href`
// navigation (see IdentityLink.vue) — the portal itself does not build these
// URLs. For a "keycloak-brokered" provider that URL still round-trips
// through the portal's own oidc-client-ts session (../lib/auth.ts::
// startIdpLink) rather than a bare top-level navigation, because Keycloak's
// `kc_action=LINK_IDP` callback lands on /callback, which only completes via
// oidc-client-ts's own locally-stored PKCE/state — IdentityLink.vue reads
// the `provider_id` query param off the broker-built `link_url` and re-runs
// startIdpLink() with it rather than navigating to it directly. An
// "oauth21-direct" provider's `link_url` (the broker's own
// /v1/oauth/authorize/{alias}) has no such constraint and is navigated to
// as-is. DELETE /v1/identities/link/{provider} always returns 501 —
// unlinking is not implemented yet, so there is no unlink client here.

// ---------------------------------------------------------------------------
// Catalog — GET /v1/catalog (flat tool list)
// ---------------------------------------------------------------------------

export type ActionType = 'read' | 'state_change';

export interface CatalogTool {
  name: string;
  backend: string;
  description: string;
  capability: string;
  action_type: ActionType;
}

export interface CatalogResponse {
  tools: CatalogTool[];
}

/** Client-side grouping of catalog tools by backend (broker returns them flat). */
export interface BackendGroup {
  backend: string;
  tools: CatalogTool[];
  capabilities: string[];
}

export async function fetchCatalog(): Promise<CatalogResponse> {
  return apiFetch<CatalogResponse>('/catalog');
}

// ---------------------------------------------------------------------------
// X.509 proxy — GET/POST/DELETE /v1/x509/proxy
// ---------------------------------------------------------------------------

/** GET /v1/x509/proxy/status */
export interface ProxyStatus {
  cached: boolean;
  dn?: string | null;
  voms_attributes: string[];
  expires_at?: string | null;
  remaining_seconds?: number | null;
}

/** POST /v1/x509/proxy response (PEM is never returned). */
export interface ProxyMetadata {
  dn: string;
  voms_attributes: string[];
  expires_at: string;
  remaining_seconds: number;
}

export async function fetchProxyStatus(): Promise<ProxyStatus> {
  return apiFetch<ProxyStatus>('/x509/proxy/status');
}

/**
 * Request a new x509 proxy.
 *
 * `valid` is an "HH:MM" lifetime (e.g. "12:00"); `voms` is the VO name with no
 * leading slash (e.g. "atlas").
 *
 * IMPORTANT: The caller MUST clear the passphrase from Vue state immediately
 * after this call returns — regardless of success or failure.
 */
export async function requestProxy(
  passphrase: string,
  valid: string = '12:00',
  voms: string = 'atlas',
): Promise<ProxyMetadata> {
  return apiFetch<ProxyMetadata>('/x509/proxy', {
    method: 'POST',
    body: JSON.stringify({ passphrase, valid, voms }),
  });
}

export async function revokeProxy(): Promise<void> {
  return apiFetch<void>('/x509/proxy', { method: 'DELETE' });
}

// ---------------------------------------------------------------------------
// Dashboard summary (parallel fetch helper for the landing page)
// ---------------------------------------------------------------------------

export interface DashboardSummary {
  linkedCount: number;
  toolCount: number;
  proxyStatus: ProxyStatus;
}

export async function fetchDashboardSummary(): Promise<DashboardSummary> {
  const [identityData, catalog, proxyStatus] = await Promise.allSettled([
    fetchIdentities(),
    fetchCatalog(),
    fetchProxyStatus(),
  ]);

  const linkedCount =
    identityData.status === 'fulfilled'
      ? identityData.value.providers.filter((p) => p.linked).length
      : 0;

  const toolCount = catalog.status === 'fulfilled' ? catalog.value.tools.length : 0;

  const proxy: ProxyStatus =
    proxyStatus.status === 'fulfilled' ? proxyStatus.value : { cached: false, voms_attributes: [] };

  return { linkedCount, toolCount, proxyStatus: proxy };
}
