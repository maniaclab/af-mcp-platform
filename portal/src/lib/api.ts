/**
 * api.ts — typed broker API client.
 *
 * Auth model: in production oauth2-proxy fronts BOTH the portal and the broker
 * on the same origin and injects the Authorization header on the upstream call.
 * The browser therefore never handles a token — same-origin requests ride the
 * oauth2-proxy session cookie. All requests use `credentials: 'same-origin'`.
 *
 * On a 401 the session has expired; callers should surface a "reload to
 * re-authenticate" prompt rather than treating it as a hard error.
 */

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

/** Thrown on HTTP 401 — the oauth2-proxy session cookie is gone or expired. */
export class SessionExpiredError extends Error {
  constructor() {
    super('Session expired');
    this.name = 'SessionExpiredError';
  }
}

async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    credentials: 'same-origin',
    ...init,
    headers: { 'Content-Type': 'application/json', ...(init?.headers ?? {}) },
  });
  if (res.status === 401) {
    throw new SessionExpiredError();
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

export interface LinkedAccount {
  provider: string;
  sub: string;
}

export interface AvailableProvider {
  provider: string;
  display_name: string;
  /** Human-readable description of what linking this provider enables. */
  enables: string;
}

export interface IdentitiesResponse {
  subject: string;
  email: string;
  unixname: string;
  uid: number;
  gid: number;
  groups: string[];
  linked_accounts: LinkedAccount[];
  available_providers: AvailableProvider[];
}

export async function fetchIdentities(): Promise<IdentitiesResponse> {
  return apiFetch<IdentitiesResponse>('/identities');
}

export async function startIdentityLink(provider: string): Promise<{ redirect_url: string }> {
  return apiFetch<{ redirect_url: string }>('/identities/link', {
    method: 'POST',
    body: JSON.stringify({ provider }),
  });
}

// NOTE: DELETE /v1/identities/link/{provider} always returns 501 — unlinking is
// done through the Keycloak account console, so there is no unlink client here.

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

  const linkedCount = identityData.status === 'fulfilled'
    ? identityData.value.linked_accounts.length
    : 0;

  const toolCount = catalog.status === 'fulfilled'
    ? catalog.value.tools.length
    : 0;

  const proxy: ProxyStatus = proxyStatus.status === 'fulfilled'
    ? proxyStatus.value
    : { cached: false, voms_attributes: [] };

  return { linkedCount, toolCount, proxyStatus: proxy };
}
