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
 *
 * The one deliberate exception to all of the above: fetchMaintenanceStatus()
 * calls a bare fetch() with no Authorization header at all, because GET
 * /v1/admin/maintenance itself requires no authentication (it has to stay
 * reachable for a visitor maintenance mode is currently blocking on every
 * other route). Don't copy that shape for a new endpoint without checking —
 * it's a special case earned by the broker's own no-auth contract on that
 * one route, not a template for "public-ish" endpoints in general.
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
 * Thrown when a 401 means "your account isn't authorized for this
 * platform" (the broker's identity.py::TokenAudienceError, carrying a
 * `detail.error === "insufficient_scope"` body) rather than a stale
 * session. Distinct from SessionExpiredError because reload/re-auth can't
 * fix it — it's permanent until an administrator grants the missing token
 * audience (see docs/auth.md's "cascading failure" section). `correlationId`
 * is the id to quote when contacting them, the same convention
 * `serviceStatus.ts` already uses for `permission_required`.
 */
export class AccessDeniedError extends Error {
  constructor(
    message: string,
    public readonly correlationId: string | null,
  ) {
    super(message);
    this.name = 'AccessDeniedError';
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
 * Called with a final, still-401 *res* that authFetch is about to give up
 * on — distinguishes AccessDeniedError from a plain stale session by
 * reading the body once. Any shape other than the broker's structured
 * `insufficient_scope` detail (including an unparseable/empty body, the
 * common case for an actually expired token) falls through to the existing
 * SessionExpiredError handling — no behavior change for genuine expiry.
 */
async function throwForUnauthorized(res: Response): Promise<never> {
  const body: { detail?: unknown } | null = await res.json().catch(() => null);
  const detail = body?.detail;
  if (
    detail &&
    typeof detail === 'object' &&
    (detail as { error?: unknown }).error === 'insufficient_scope'
  ) {
    const { message, correlation_id } = detail as { message: string; correlation_id?: string };
    throw new AccessDeniedError(message, correlation_id ?? null);
  }
  throwSessionExpired();
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
      await throwForUnauthorized(res);
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
  /** True when the caller is a member of the broker's configured admin
   * group -- gates the portal's Admin nav entry and admin-only views. False
   * whenever the broker has no admin group configured. */
  is_admin: boolean;
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
 * Returned by GET /v1/catalog/{service}/tools (fetchServerTools below). */
export interface CatalogTool {
  name: string;
  description: string;
  action_type: ActionType;
}

/** Per-caller availability (issue #123) -- see broker/src/af_mcp_broker/
 * api/permissions.py's _service_status. Every registered service is
 * listed, even one the caller can't currently use; status/status_detail say
 * why instead of a silent omission. */
export type ServiceStatus =
  'available' | 'link_required' | 'permission_required' | 'unavailable' | 'misconfigured';

export interface CatalogServer {
  name: string;
  display_name: string;
  description: string;
  permission: string;
  auth_type: AuthType;
  action_type: ActionType;
  /** The identity_providers alias (or synthetic "x509" alias) that services
   * this server's credential, or null when auth_type is "none". */
  credential_provider: string | null;
  status: ServiceStatus;
  /** Short, human, internals-free sentence -- never a URL or upstream error. */
  status_detail: string;
  /** Set only for admin-actionable statuses (permission_required,
   * misconfigured) -- quote it in a ticket so an admin can grep the audit
   * log. Null otherwise. */
  correlation_id: string | null;
  /** True only for the broker's own af-mcp entry (issue #240) -- the
   * gateway's identity, catalog, and usage methods. It has no per-user
   * credential, no identity to link, and no backend that could be
   * unreachable, so ServiceCard drops those affordances for it. */
  builtin: boolean;
}

export interface CatalogResponse {
  servers: CatalogServer[];
}

export async function fetchCatalog(): Promise<CatalogResponse> {
  return apiFetch<CatalogResponse>('/catalog');
}

// ---------------------------------------------------------------------------
// Per-service tool listing — GET /v1/catalog/{service}/tools. Fetched on
// expand by ServiceCard.vue's Tools accordion, one backend at a time -- the
// catalog itself stays a single cheap request and the broker only fans out
// to the backend the user actually opened.
// ---------------------------------------------------------------------------

/** Mirrors broker/src/af_mcp_broker/api/catalog_tools.py's ToolListingStatus:
 * "ok" plus the aggregator's own tools/list failure classification. A
 * backend never vanishes for credential reasons -- `status`/`status_detail`
 * say why `tools` is empty instead (same issue #123 philosophy as the
 * catalog's per-server status). */
export type ToolListingStatus =
  'ok' | 'not_linked' | 'unauthorized' | 'unavailable' | 'permission_required';

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
// Permissions — GET /v1/permissions. Lists the caller's CURRENT permission
// grants (broker/src/af_mcp_broker/api/permissions.py's get_permissions()).
// TokensPage.vue's mint dialog uses this to offer a permission PAT's optional
// scope as checkboxes over exactly what the caller holds right now (issue
// #144 step 4) -- never a static, potentially-stale list.
// ---------------------------------------------------------------------------

export interface PermissionGrant {
  permission: string;
  targets: string[];
  action_types: ActionType[];
}

export interface PermissionsResponse {
  subject: string;
  grants: PermissionGrant[];
}

export async function fetchPermissions(): Promise<PermissionsResponse> {
  return apiFetch<PermissionsResponse>('/permissions');
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
 * (`neverExpires: true` in the mint request). `permission_grant` is `null`
 * for an ordinary identity PAT (this token's authority is always the
 * caller's CURRENT permissions), or the sorted list of permission names a
 * permission PAT is scoped to at most (issue #144 step 4) -- see
 * tokenDisplay.ts's permissionGrantLabel(). */
export interface MintedToken {
  token: string;
  lookup_id: string;
  created_at: string;
  expires_at: string | null;
  name: string;
  note: string | null;
  permission_grant: string[] | null;
}

/** GET /v1/tokens row — no `token` field, by design. `revoked_at` is null
 * until DELETE /v1/tokens/{lookup_id} is called -- revoked rows stay listed
 * (rather than disappearing, as PR #28 did) so the portal can show a
 * revoked/active/expired status; see tokenDisplay.ts's tokenStatus().
 * `last_used_at` is null until the PAT has authenticated at least one
 * request on /mcp (throttled server-side -- see token_registry.py -- so it
 * updates at most once every few minutes, not on every call). See
 * MintedToken.permission_grant for the meaning of that field here too. */
export interface TokenSummary {
  lookup_id: string;
  name: string;
  note: string | null;
  created_at: string;
  expires_at: string | null;
  revoked_at: string | null;
  last_used_at: string | null;
  permission_grant: string[] | null;
}

export async function mintToken(
  name?: string,
  note?: string,
  expiresInDays?: number,
  neverExpires?: boolean,
  permissions?: string[],
): Promise<MintedToken> {
  return apiFetch<MintedToken>('/tokens', {
    method: 'POST',
    body: JSON.stringify({
      ...(name ? { name } : {}),
      ...(note ? { note } : {}),
      ...(expiresInDays !== undefined ? { expires_in_days: expiresInDays } : {}),
      ...(neverExpires ? { never_expires: true } : {}),
      ...(permissions !== undefined ? { permissions } : {}),
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

// ---------------------------------------------------------------------------
// Usage — GET /v1/usage
// ---------------------------------------------------------------------------

export interface UsageTotals {
  calls: number;
  errors: number;
  duration_ms: number;
  result_bytes: number;
  // A tiktoken (o200k) ESTIMATE of the tool-result text injected into the
  // LLM client's context — not provider-reported usage, and not the user's
  // full LLM spend. estimated_cost_usd prices that estimate at the response's
  // cost_model input rate. Label both as estimates wherever they render.
  result_tokens_est: number;
  estimated_cost_usd: number;
}

export interface UsageByService {
  service: string;
  calls: number;
  errors: number;
  result_bytes: number;
  result_tokens_est: number;
  estimated_cost_usd: number;
}

export interface UsageByDay {
  /** ISO-8601 UTC calendar day. */
  date: string;
  calls: number;
  result_tokens_est: number;
}

export interface UsageResponse {
  subject: string;
  window_days: number;
  /** The price-table key whose input rate produced every estimated_cost_usd. */
  cost_model: string;
  totals: UsageTotals;
  by_service: UsageByService[];
  by_day: UsageByDay[];
}

/**
 * The caller's own tool-call usage over a trailing window (default 30
 * days). Passing *subject* asks for another subject's usage instead — the
 * broker rejects this with a 403 unless the caller is in the configured
 * admin group (see api/usage.py::get_usage).
 */
export async function fetchUsage(days = 30, subject?: string): Promise<UsageResponse> {
  const query = subject ? `days=${days}&subject=${encodeURIComponent(subject)}` : `days=${days}`;
  return apiFetch<UsageResponse>(`/usage?${query}`);
}

export interface UsageSubject {
  subject: string;
  unixname: string | null;
  email: string;
}

export interface UsageSubjectsResponse {
  subjects: UsageSubject[];
}

/**
 * Admin-only: distinct subjects with recorded usage over a trailing window,
 * resolved to unixname/email for display. Backs the admin usage-view
 * dropdown (see api/usage.py::get_usage_subjects) — the broker 403s this
 * for a non-admin caller.
 */
export async function fetchUsageSubjects(days = 30): Promise<UsageSubjectsResponse> {
  return apiFetch<UsageSubjectsResponse>(`/usage/subjects?days=${days}`);
}

// ---------------------------------------------------------------------------
// Maintenance mode — GET/POST /v1/admin/maintenance
// ---------------------------------------------------------------------------

export interface MaintenanceStatus {
  enabled: boolean;
  reason: string | null;
  enabled_by: string | null;
  enabled_at: number | null;
}

/**
 * GET /v1/admin/maintenance carries NO authentication requirement at all
 * (see broker api/admin.py) — the whole point is that a visitor currently
 * locked out by maintenance mode, including one with no session whatsoever,
 * can still learn why. Deliberately bypasses authFetch/apiFetch: authFetch
 * throws SessionExpiredError up front when there's no session to renew (see
 * its early-exit branch), which is exactly backwards for a banner that must
 * render for a logged-out or expired-session visitor. A plain, header-free
 * fetch is the correct client for a route the broker never checks auth on.
 */
export async function fetchMaintenanceStatus(): Promise<MaintenanceStatus> {
  const res = await fetch(`${API_BASE}/admin/maintenance`);
  if (!res.ok) {
    const body = await res.text().catch(() => '');
    throw new APIError(res.status, res.statusText, body);
  }
  return res.json() as Promise<MaintenanceStatus>;
}

/**
 * POST /v1/admin/maintenance — requires admin-group membership
 * (require_admin), so unlike fetchMaintenanceStatus this goes through the
 * normal Bearer-attaching apiFetch every other mutating call in this file
 * uses. 403 if the caller's admin membership isn't (or is no longer) valid;
 * 409 if another admin's concurrent write lost the Vault compare-and-set
 * race (see api/admin.py::set_maintenance_status).
 */
export async function setMaintenanceStatus(
  enabled: boolean,
  reason?: string,
): Promise<MaintenanceStatus> {
  return apiFetch<MaintenanceStatus>('/admin/maintenance', {
    method: 'POST',
    body: JSON.stringify({ enabled, ...(reason ? { reason } : {}) }),
  });
}
