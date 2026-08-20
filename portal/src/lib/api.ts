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
import { tokenStatus } from './tokenDisplay';

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

/**
 * Bearer-authenticated fetch against an absolute *url* — the silent-renew-
 * on-401 logic shared by `apiFetch` (broker `/v1` paths, relative to
 * `API_BASE`) and `fetchOAuth21AuthorizeUrl` (an absolute `link_url` handed
 * back by GET /v1/identities, potentially on a different origin than
 * `API_BASE`). Callers still own status-code handling (`!res.ok`, `204`,
 * `.json()`) — this only owns getting a validly-Bearer'd `Response`.
 */
async function authFetch(url: string, init?: RequestInit): Promise<Response> {
  const token = await getAccessToken();
  if (!token && (await isOidcConfigured())) {
    // OIDC is configured but there's no session (or renewal already failed
    // inside getAccessToken) — skip the round trip, it would just 401.
    throwSessionExpired();
  }

  const doFetch = (bearer: string | null) =>
    fetch(url, {
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
  return res;
}

async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await authFetch(`${API_BASE}${path}`, init);
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
 * IdentityLink.vue knows which linking mechanism `link_url` belongs to.
 * "x509" is the synthetic grid-certificate entry the broker appends when any
 * backend authenticates with a VOMS proxy (see api/identities.py); it links
 * via `link_mechanism: "passphrase"` below, never a `link_url`. */
export type ProviderType = 'keycloak-brokered' | 'oauth21-direct' | 'x509';

/** How a linking flow starts: "redirect" — a browser navigation (the
 * keycloak-brokered client-side flow or an oauth21-direct `link_url`);
 * "passphrase" — an in-portal form that POSTs the user's Globus passphrase
 * to /v1/x509/proxy (X509IdentityCard.vue); "none" — no linking step exists
 * (broker-authoritative AF-native entries). */
export type LinkMechanism = 'redirect' | 'passphrase' | 'none';

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
  link_mechanism: LinkMechanism;
  /** Expiry (ISO-8601) of the caller's x509/VOMS proxy — only ever set on an
   * "x509" entry, and null there too when no valid proxy is stored. */
  proxy_expires_at?: string | null;
  /** Custody mode of an x509 entry's link: "auto-renew" — the passphrase is
   * stored in the AF vault and proxies re-mint hands-free; "until-expiry" —
   * only the proxy is stored (the user declined passphrase custody), so the
   * link lasts exactly as long as proxy_expires_at. Null when not linked, on
   * legacy x509 entries, and on every non-x509 entry. */
  x509_link_mode?: 'auto-renew' | 'until-expiry' | null;
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

// NOTE on linking mechanisms: a "keycloak-brokered" provider always carries
// `link_url: null` (issue #66 PR4) — IdentityLink.vue calls
// startIdpLink({ providerAlias: entry.id, ... }) directly using the
// provider's own `id`, which the broker guarantees equals its configured
// alias, so there's no URL to build or parse for these. Keycloak's
// `kc_action=LINK_IDP` callback lands on /callback, which only completes via
// oidc-client-ts's own locally-stored PKCE/state — a bare top-level
// navigation can't complete that handshake, which is why this provider type
// always goes through the client-side flow rather than a `link_url`
// navigation. An "oauth21-direct" provider carries a full `link_url` (the
// broker's own /v1/oauth/authorize/{alias}) — but a plain top-level
// navigation to it can't carry the SPA's Bearer either (browsers don't
// attach JS-held Authorization headers to top-level navigations), so
// IdentityLink.vue calls fetchOAuth21AuthorizeUrl() first and navigates to
// the `authorize_url` it returns instead of navigating to `link_url`
// directly. DELETE /v1/identities/link/{provider} returns 204 for an
// "oauth21-direct" alias (see unlinkIdentity() below) but still 501 for a
// "keycloak-brokered" one — Keycloak admin API unlink is out of scope
// (issue #86) — so IdentityLink.vue only surfaces the unlink action for
// "oauth21-direct" providers.

/**
 * Fetches the backend authorization server's authorize URL for an
 * "oauth21-direct" provider's `link_url`, using the SPA's own Bearer.
 *
 * `link_url` points at the broker's own `/v1/oauth/authorize/{alias}`
 * (content-negotiated — see api/oauth21.py::authorize): requesting it with
 * `Accept: application/json` gets back `{ authorize_url }` plus a
 * `Set-Cookie` for the linking flow's nonce, instead of the 302 a bare
 * browser navigation would receive. The caller is responsible for the actual
 * `window.location.href = authorize_url` navigation — this only performs
 * the Bearer'd fetch a top-level navigation couldn't.
 */
export async function fetchOAuth21AuthorizeUrl(linkUrl: string): Promise<string> {
  const res = await authFetch(linkUrl, { headers: { Accept: 'application/json' } });
  if (!res.ok) {
    const body = await res.text().catch(() => '');
    throw new APIError(res.status, res.statusText, body);
  }
  const data = (await res.json()) as { authorize_url: string };
  return data.authorize_url;
}

/**
 * Revokes a stored "oauth21-direct" identity token — DELETE
 * /v1/identities/link/{provider} (see api/identities.py::unlink_identity).
 * Returns 204 on success; still 501 for a "keycloak-brokered" provider,
 * which IdentityLink.vue never calls this for (see the linking-mechanisms
 * note above).
 */
export async function unlinkIdentity(provider: string): Promise<void> {
  return apiFetch<void>(`/identities/link/${encodeURIComponent(provider)}`, {
    method: 'DELETE',
  });
}

// ---------------------------------------------------------------------------
// Catalog — GET /v1/catalog (one entry per MCP server)
// ---------------------------------------------------------------------------

export type ActionType = 'read' | 'state_change';

export type AuthType = 'bearer' | 'x509' | 'none';

/** One tool as the caller would see it through /mcp: the (namespace-applied)
 * name, its description, and the same read/state_change resolution real
 * enforcement uses. Never the full input schema -- the payload stays light.
 * Returned by GET /v1/catalog/{backend}/tools (fetchServerTools below). */
export interface CatalogTool {
  name: string;
  description: string;
  action_type: ActionType;
}

/** Per-caller availability (issue #123) -- see broker/src/af_mcp_broker/
 * api/capabilities.py's _backend_status. Every registered backend is
 * listed, even one the caller can't currently use; status/status_detail say
 * why instead of a silent omission. */
export type BackendStatus =
  'available' | 'link_required' | 'capability_required' | 'unavailable' | 'misconfigured';

export interface CatalogServer {
  name: string;
  display_name: string;
  description: string;
  capability: string;
  auth_type: AuthType;
  action_type: ActionType;
  /** The identity_providers alias (or synthetic "x509" alias) that services
   * this server's credential, or null when auth_type is "none". */
  credential_provider: string | null;
  status: BackendStatus;
  /** Short, human, internals-free sentence -- never a URL or upstream error. */
  status_detail: string;
  /** Set only for admin-actionable statuses (capability_required,
   * misconfigured) -- quote it in a ticket so an admin can grep the audit
   * log. Null otherwise. */
  correlation_id: string | null;
}

export interface CatalogResponse {
  servers: CatalogServer[];
}

export async function fetchCatalog(): Promise<CatalogResponse> {
  return apiFetch<CatalogResponse>('/catalog');
}

// ---------------------------------------------------------------------------
// Per-backend tool listing — GET /v1/catalog/{backend}/tools. Fetched on
// expand by BackendCard.vue's Tools accordion, one backend at a time -- the
// catalog itself stays a single cheap request and the broker only fans out
// to the backend the user actually opened.
// ---------------------------------------------------------------------------

/** Mirrors broker/src/af_mcp_broker/api/catalog_tools.py's ToolListingStatus:
 * "ok" plus the aggregator's own tools/list failure classification. A
 * backend never vanishes for credential reasons -- `status`/`status_detail`
 * say why `tools` is empty instead (same issue #123 philosophy as the
 * catalog's per-server status). */
export type ToolListingStatus =
  'ok' | 'not_linked' | 'unauthorized' | 'unavailable' | 'capability_required';

export interface ServerToolsResponse {
  name: string;
  display_name: string;
  description: string;
  status: ToolListingStatus;
  /** Short, human, internals-free sentence -- same contract as the
   * catalog's status_detail. */
  status_detail: string;
  /** Empty whenever status is not "ok". */
  tools: CatalogTool[];
}

export async function fetchServerTools(name: string): Promise<ServerToolsResponse> {
  return apiFetch<ServerToolsResponse>(`/catalog/${encodeURIComponent(name)}/tools`);
}

// ---------------------------------------------------------------------------
// Capabilities — GET /v1/capabilities. Lists the caller's CURRENT capability
// grants (broker/src/af_mcp_broker/api/capabilities.py's get_capabilities()).
// TokensPage.vue's mint dialog uses this to offer a capability PAT's optional
// scope as checkboxes over exactly what the caller holds right now (issue
// #144 step 4) -- never a static, potentially-stale list.
// ---------------------------------------------------------------------------

export interface CapabilityGrant {
  capability: string;
  targets: string[];
  action_types: ActionType[];
}

export interface CapabilitiesResponse {
  subject: string;
  grants: CapabilityGrant[];
}

export async function fetchCapabilities(): Promise<CapabilitiesResponse> {
  return apiFetch<CapabilitiesResponse>('/capabilities');
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
  nickname?: string | null;
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
 * leading slash (e.g. "atlas"). `remember` is the custody consent: true (the
 * default) stores the passphrase encrypted in the AF vault for hands-free
 * renewal; false means the proxy works for its validity window and the user
 * re-links after it expires.
 *
 * IMPORTANT: The caller MUST clear the passphrase from Vue state immediately
 * after this call returns — regardless of success or failure.
 */
export async function requestProxy(
  passphrase: string,
  valid: string = '12:00',
  voms: string = 'atlas',
  remember: boolean = true,
): Promise<ProxyMetadata> {
  return apiFetch<ProxyMetadata>('/x509/proxy', {
    method: 'POST',
    body: JSON.stringify({ passphrase, valid, voms, remember }),
  });
}

export async function revokeProxy(): Promise<void> {
  return apiFetch<void>('/x509/proxy', { method: 'DELETE' });
}

// ---------------------------------------------------------------------------
// X.509 preflight — GET /v1/x509/preflight (the Grid Certificates checklist)
// ---------------------------------------------------------------------------

/** One row of the checklist — voms-token-service's contract, proxied through
 * the broker verbatim. `mode`/`readable_by_service` are absent on checks they
 * don't apply to (the .globus directory row); `detail` carries the actionable
 * fix (e.g. the chmod 400 command) when `ok` is false. */
export interface X509PreflightCheck {
  name: string;
  path: string;
  exists: boolean;
  mode?: string | null;
  readable_by_service?: boolean | null;
  ok: boolean;
  detail?: string | null;
}

export interface X509Preflight {
  unixname: string;
  root: string;
  ok: boolean;
  checks: X509PreflightCheck[];
}

/**
 * Fetches the caller's grid-certificate readiness checklist. Errors the
 * caller should expect: 501 — the facility's x509 entry mints via the legacy
 * path (no voms-token-service to ask); 502 — the service is unreachable.
 * See x509Identity.ts's x509PreflightErrorMessage for the display mapping.
 */
export async function fetchX509Preflight(): Promise<X509Preflight> {
  return apiFetch<X509Preflight>('/x509/preflight');
}

// ---------------------------------------------------------------------------
// Tokens — POST/GET/DELETE /v1/tokens. Mints a broker-issued identity PAT
// (issue #144 step 2a) -- see docs/auth.md's "Programmatic client bootstrap"
// section. Replaces the RFC 8693 token-exchange design (issue #24/#115):
// `lookup_id` replaces `jti`, `created_at` replaces `issued_at`, `expires_at`
// is nullable (a never-expiring PAT), and `last_used_at` is now populated.
// ---------------------------------------------------------------------------

/** POST /v1/tokens response. `token` is present ONLY here — the broker never
 * returns a previously-minted token's value again. `name` is unique per
 * principal among live (non-revoked, unexpired-or-never-expiring) tokens,
 * case-insensitively -- a collision is a 409 (see mintToken's caller). `note`
 * is optional, free-text, purely self-descriptive, and absent (`null`)
 * unless supplied. `expires_at` is `null` for a never-expiring PAT
 * (`neverExpires: true` in the mint request). `capability_grant` is `null`
 * for an ordinary identity PAT (this token's authority is always the
 * caller's CURRENT capabilities), or the sorted list of capability names a
 * capability PAT is scoped to at most (issue #144 step 4) -- see
 * tokenDisplay.ts's capabilityGrantLabel(). */
export interface MintedToken {
  token: string;
  lookup_id: string;
  created_at: string;
  expires_at: string | null;
  name: string;
  note: string | null;
  capability_grant: string[] | null;
}

/** GET /v1/tokens row — no `token` field, by design. `revoked_at` is null
 * until DELETE /v1/tokens/{lookup_id} is called -- revoked rows stay listed
 * (rather than disappearing, as PR #28 did) so the portal can show a
 * revoked/active/expired status; see tokenDisplay.ts's tokenStatus().
 * `last_used_at` is null until the PAT has authenticated at least one
 * request on /mcp (throttled server-side -- see token_registry.py -- so it
 * updates at most once every few minutes, not on every call). See
 * MintedToken.capability_grant for the meaning of that field here too. */
export interface TokenSummary {
  lookup_id: string;
  name: string;
  note: string | null;
  created_at: string;
  expires_at: string | null;
  revoked_at: string | null;
  last_used_at: string | null;
  capability_grant: string[] | null;
}

export async function mintToken(
  name?: string,
  note?: string,
  expiresInDays?: number,
  neverExpires?: boolean,
  capabilities?: string[],
): Promise<MintedToken> {
  return apiFetch<MintedToken>('/tokens', {
    method: 'POST',
    body: JSON.stringify({
      ...(name ? { name } : {}),
      ...(note ? { note } : {}),
      ...(expiresInDays !== undefined ? { expires_in_days: expiresInDays } : {}),
      ...(neverExpires ? { never_expires: true } : {}),
      ...(capabilities !== undefined ? { capabilities } : {}),
    }),
  });
}

export async function listTokens(): Promise<TokenSummary[]> {
  return apiFetch<TokenSummary[]>('/tokens');
}

export async function revokeToken(lookupId: string): Promise<void> {
  await apiFetch<{ lookup_id: string; revoked: boolean }>(
    `/tokens/${encodeURIComponent(lookupId)}`,
    { method: 'DELETE' },
  );
}

// ---------------------------------------------------------------------------
// Dashboard summary (parallel fetch helper for the landing page)
// ---------------------------------------------------------------------------

export interface DashboardSummary {
  linkedCount: number;
  serverCount: number;
  proxyStatus: ProxyStatus;
  activeTokenCount: number;
}

// ---------------------------------------------------------------------------
// Credentials — DELETE /v1/credential
// ---------------------------------------------------------------------------

/**
 * Purges every cached credential the broker holds for the caller
 * (CredentialCache.revoke_all) — called on sign-out (see Base.astro) so a
 * later sign-in doesn't inherit this session's minted tokens/proxies.
 */
export async function revokeAllCredentials(): Promise<void> {
  return apiFetch<void>('/credential', { method: 'DELETE' });
}

export async function fetchDashboardSummary(): Promise<DashboardSummary> {
  const [identityData, catalog, proxyStatus, tokens] = await Promise.allSettled([
    fetchIdentities(),
    fetchCatalog(),
    fetchProxyStatus(),
    listTokens(),
  ]);

  const linkedCount =
    identityData.status === 'fulfilled'
      ? identityData.value.providers.filter((p) => p.linked).length
      : 0;

  const serverCount = catalog.status === 'fulfilled' ? catalog.value.servers.length : 0;

  const proxy: ProxyStatus =
    proxyStatus.status === 'fulfilled' ? proxyStatus.value : { cached: false, voms_attributes: [] };

  const activeTokenCount =
    tokens.status === 'fulfilled'
      ? tokens.value.filter((t) => tokenStatus(t) === 'active').length
      : 0;

  return { linkedCount, serverCount, proxyStatus: proxy, activeTokenCount };
}
