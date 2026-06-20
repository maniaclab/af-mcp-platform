/**
 * api.ts — typed broker API client.
 *
 * All requests require Authorization: Bearer <AF Keycloak token>.
 * The token is read from the <meta name="af-token"> tag that Base.astro
 * injects from the oauth2-proxy Authorization header.
 *
 * Base URL is configured via import.meta.env.PUBLIC_BROKER_URL (default:
 * same origin, path /v1).
 */

const BASE_URL = (import.meta.env.PUBLIC_BROKER_URL ?? '/v1') as string;

// ---------------------------------------------------------------------------
// Token
// ---------------------------------------------------------------------------

/** Returns the AF Keycloak bearer token injected by oauth2-proxy. */
export function getToken(): string | null {
  if (typeof document === 'undefined') return null;
  const meta = document.querySelector<HTMLMetaElement>('meta[name="af-token"]');
  return meta?.content ?? null;
}

function authHeaders(): HeadersInit {
  const token = getToken();
  return {
    'Content-Type': 'application/json',
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
  };
}

async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE_URL}${path}`, {
    ...init,
    headers: { ...authHeaders(), ...(init?.headers ?? {}) },
  });
  if (!res.ok) {
    const body = await res.text().catch(() => '');
    throw new APIError(res.status, res.statusText, body);
  }
  // 204 No Content — return undefined cast to T
  if (res.status === 204) return undefined as unknown as T;
  return res.json() as Promise<T>;
}

// ---------------------------------------------------------------------------
// Error type
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

// ---------------------------------------------------------------------------
// Identities
// ---------------------------------------------------------------------------

export interface Identity {
  provider: string;       // e.g. "atlas-iam", "cern", "gitlab"
  display_name: string;
  linked: boolean;
  subject?: string;       // linked subject identifier, if available
  linked_at?: string;     // ISO timestamp
  capabilities_unlocked: string[];
  description: string;
}

export interface IdentitiesResponse {
  identities: Identity[];
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

export async function unlinkIdentity(provider: string): Promise<void> {
  return apiFetch<void>(`/identities/link/${encodeURIComponent(provider)}`, {
    method: 'DELETE',
  });
}

// ---------------------------------------------------------------------------
// Capabilities
// ---------------------------------------------------------------------------

export interface Capability {
  name: string;
  description: string;
  granted: boolean;
  required_provider?: string;
}

export async function fetchCapabilities(): Promise<Capability[]> {
  return apiFetch<Capability[]>('/capabilities');
}

// ---------------------------------------------------------------------------
// Catalog
// ---------------------------------------------------------------------------

export type ActionType = 'read' | 'state_change';

export interface ToolEntry {
  name: string;
  description: string;
  action_type: ActionType;
}

export interface CatalogEntry {
  backend: string;
  prefix: string;
  tools: ToolEntry[];
  capability: string;
  action_type: ActionType;
  description?: string;
}

export async function fetchCatalog(): Promise<CatalogEntry[]> {
  return apiFetch<CatalogEntry[]>('/catalog');
}

// ---------------------------------------------------------------------------
// X.509 proxy
// ---------------------------------------------------------------------------

export interface ProxyStatus {
  has_proxy: boolean;
  expires_at?: string;          // ISO 8601 timestamp
  remaining_seconds?: number;
  voms_attributes?: string[];   // e.g. ["/atlas/Role=production"]
  subject_dn?: string;          // e.g. "/DC=ch/DC=cern/OU=Users/CN=kratsg"
}

export interface ProxyMeta {
  subject_dn: string;
  expires_at: string;
  voms_attributes: string[];
}

export async function fetchProxyStatus(): Promise<ProxyStatus> {
  return apiFetch<ProxyStatus>('/x509/proxy/status');
}

/**
 * Request a new x509 proxy.
 *
 * IMPORTANT: The caller MUST clear the passphrase from Vue state
 * immediately after this call returns — regardless of success or failure.
 */
export async function requestProxy(
  passphrase: string,
  valid: string = '12h',
  voms: string = '/atlas',
): Promise<ProxyMeta> {
  return apiFetch<ProxyMeta>('/x509/proxy', {
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
    ? identityData.value.identities.filter(i => i.linked).length
    : 0;

  const toolCount = catalog.status === 'fulfilled'
    ? catalog.value.reduce((sum, b) => sum + b.tools.length, 0)
    : 0;

  const proxy: ProxyStatus = proxyStatus.status === 'fulfilled'
    ? proxyStatus.value
    : { has_proxy: false };

  return { linkedCount, toolCount, proxyStatus: proxy };
}
