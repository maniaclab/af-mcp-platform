/**
 * Smoke tests for the typed broker API client.
 *
 * These are deliberately narrow — enough that `npm test` (and therefore
 * `pixi run -e portal test`) fails loudly if someone renames an exported
 * class or breaks the fetch contract. Expand these when we touch api.ts.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  APIError,
  AccessDeniedError,
  SessionExpiredError,
  clearIdentitiesCache,
  fetchEntitlements,
  fetchPermissions,
  fetchDashboardSummary,
  fetchIdentities,
  fetchMaintenanceStatus,
  fetchOAuth21AuthorizeUrl,
  fetchProxyStatus,
  fetchServerTools,
  fetchX509Preflight,
  listTokens,
  requestKrb5Ticket,
  requestProxy,
  mintToken,
  revokeAllCredentials,
  revokeToken,
  setMaintenanceStatus,
  unlinkIdentity,
} from '../api';
import * as auth from '../auth';

// Stash + restore the real fetch. The tests below install a per-test mock.
const realFetch = globalThis.fetch;

// api.ts gets its Bearer from auth.ts, not from a cookie — mock the module so
// these tests control the token/renewal/config-detection outcomes directly
// instead of exercising the real oidc-client-ts + /config.json machinery.
vi.mock('../auth', () => ({
  getAccessToken: vi.fn(),
  renewAccessToken: vi.fn(),
  isOidcConfigured: vi.fn(),
}));

beforeEach(() => {
  vi.restoreAllMocks();
  // The fetchIdentities() cache is sessionStorage-backed — jsdom's
  // sessionStorage persists across tests in the same file, so clear it
  // explicitly rather than relying on per-test isolation.
  window.sessionStorage.clear();
  // Default: a configured environment with a valid token, matching most
  // tests below; individual tests override as needed.
  vi.mocked(auth.getAccessToken).mockResolvedValue('test-token');
  vi.mocked(auth.isOidcConfigured).mockResolvedValue(true);
  vi.mocked(auth.renewAccessToken).mockResolvedValue(null);
});

afterEach(() => {
  globalThis.fetch = realFetch;
});

// A fresh Response per call — a single shared instance would blow up on a
// second .json() read (the body stream is one-shot), which the identities
// cache tests below rely on triggering (TTL expiry, cache-clear) more than
// once against the same mock.
function mockJson(status: number, body: unknown) {
  return vi.fn().mockImplementation(() =>
    Promise.resolve(
      new Response(JSON.stringify(body), {
        status,
        headers: { 'Content-Type': 'application/json' },
      }),
    ),
  );
}

describe('api client', () => {
  it('exports the error classes distinctly', () => {
    expect(new APIError(500, 'boom', 'x')).toBeInstanceOf(Error);
    expect(new SessionExpiredError()).toBeInstanceOf(Error);
    expect(new AccessDeniedError('denied', 'abc123')).toBeInstanceOf(Error);
    // Different classes so callers can discriminate with instanceof.
    expect(new SessionExpiredError()).not.toBeInstanceOf(APIError);
    expect(new AccessDeniedError('denied', 'abc123')).not.toBeInstanceOf(SessionExpiredError);
  });

  it('sends the access token as a Bearer header', async () => {
    globalThis.fetch = mockJson(200, {
      subject: 's',
      email: 'e',
      unixname: 'u',
      uid: 1,
      gid: 2,
      groups: [],
      providers: [],
    });
    await fetchIdentities();
    expect(globalThis.fetch).toHaveBeenCalledWith(
      expect.any(String),
      expect.objectContaining({
        headers: expect.objectContaining({ Authorization: 'Bearer test-token' }),
      }),
    );
  });

  it('throws SessionExpiredError without hitting the network when there is no token', async () => {
    vi.mocked(auth.getAccessToken).mockResolvedValue(null);
    globalThis.fetch = vi.fn();
    await expect(fetchIdentities()).rejects.toBeInstanceOf(SessionExpiredError);
    expect(globalThis.fetch).not.toHaveBeenCalled();
  });

  it('proceeds without a token when OIDC is not configured (dev-bypass mode)', async () => {
    vi.mocked(auth.getAccessToken).mockResolvedValue(null);
    vi.mocked(auth.isOidcConfigured).mockResolvedValue(false);
    globalThis.fetch = mockJson(200, {
      subject: 's',
      email: 'e',
      unixname: 'u',
      uid: 1,
      gid: 2,
      groups: [],
      providers: [],
    });
    await expect(fetchIdentities()).resolves.toMatchObject({ email: 'e' });
    const [, init] = vi.mocked(globalThis.fetch).mock.calls[0] as [string, RequestInit];
    expect(init.headers).not.toHaveProperty('Authorization');
  });

  it('retries once via silent renew on a 401, then succeeds', async () => {
    vi.mocked(auth.renewAccessToken).mockResolvedValue('renewed-token');
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(new Response('', { status: 401 }))
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            subject: 's',
            email: 'e',
            unixname: 'u',
            uid: 1,
            gid: 2,
            groups: [],
            providers: [],
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        ),
      );
    globalThis.fetch = fetchMock;
    await expect(fetchIdentities()).resolves.toMatchObject({ email: 'e' });
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(fetchMock.mock.calls[1][1]).toMatchObject({
      headers: expect.objectContaining({ Authorization: 'Bearer renewed-token' }),
    });
  });

  it('throws SessionExpiredError when renewal fails and the retry still 401s', async () => {
    vi.mocked(auth.renewAccessToken).mockResolvedValue(null);
    globalThis.fetch = vi.fn().mockResolvedValue(new Response('', { status: 401 }));
    await expect(fetchIdentities()).rejects.toBeInstanceOf(SessionExpiredError);
    expect(globalThis.fetch).toHaveBeenCalledTimes(1);
  });

  it('throws AccessDeniedError (not SessionExpiredError) when the 401 carries an insufficient_scope detail', async () => {
    // The broker sends this shape (identity.py's TokenAudienceError) when a
    // token is validly signed but missing the expected audience — a
    // permanent, admin-only fix, not a stale session, so it must not be
    // presented as one.
    vi.mocked(auth.renewAccessToken).mockResolvedValue(null);
    globalThis.fetch = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          detail: {
            error: 'insufficient_scope',
            message: 'Your account is not authorized yet. Quote this ID: abc123',
            correlation_id: 'abc123',
          },
        }),
        { status: 401, headers: { 'Content-Type': 'application/json' } },
      ),
    );
    const rejection = await fetchIdentities().catch((e) => e);
    expect(rejection).toBeInstanceOf(AccessDeniedError);
    expect(rejection).not.toBeInstanceOf(SessionExpiredError);
    expect(rejection.message).toBe('Your account is not authorized yet. Quote this ID: abc123');
    expect(rejection.correlationId).toBe('abc123');
  });

  it('returns the parsed body on 200', async () => {
    globalThis.fetch = mockJson(200, {
      subject: 's',
      email: 'e',
      unixname: 'u',
      uid: 1,
      gid: 2,
      groups: [],
      providers: [
        {
          id: 'atlas-iam',
          type: 'keycloak-brokered',
          display_name: 'ATLAS IAM',
          enables: 'VOMS proxy generation',
          linked: true,
          link_url: null,
          link_mechanism: 'redirect',
          proxy_expires_at: null,
        },
        {
          id: 'x509',
          type: 'x509',
          display_name: 'Grid certificate (x509)',
          enables: 'VOMS proxy minting for x509-authenticated backends',
          linked: true,
          link_url: null,
          link_mechanism: 'passphrase',
          proxy_expires_at: '2026-08-18T21:30:00+00:00',
        },
      ],
    });
    const result = await fetchIdentities();
    expect(result.email).toBe('e');
    expect(result.providers).toHaveLength(2);
    expect(result.providers[0]).toMatchObject({ id: 'atlas-iam', linked: true });
    expect(result.providers[1]).toMatchObject({
      id: 'x509',
      link_mechanism: 'passphrase',
      proxy_expires_at: '2026-08-18T21:30:00+00:00',
    });
  });

  it('raises APIError with the response body on non-2xx', async () => {
    globalThis.fetch = vi
      .fn()
      .mockResolvedValue(new Response('nope', { status: 500, statusText: 'Server Error' }));
    await expect(fetchIdentities()).rejects.toMatchObject({
      name: 'APIError',
      status: 500,
      body: 'nope',
    });
  });
});

describe('fetchIdentities() sessionStorage cache', () => {
  const identity = {
    subject: 's',
    email: 'e',
    unixname: 'u',
    uid: 1,
    gid: 2,
    groups: [],
    providers: [],
  };

  it('fetches from the broker and caches the response on first call', async () => {
    globalThis.fetch = mockJson(200, identity);
    await expect(fetchIdentities()).resolves.toMatchObject({ email: 'e' });
    expect(globalThis.fetch).toHaveBeenCalledTimes(1);
    expect(window.sessionStorage.getItem('af-portal.identities')).not.toBeNull();
  });

  it('returns the cached response within the TTL without hitting the broker', async () => {
    globalThis.fetch = mockJson(200, identity);
    await fetchIdentities();
    expect(globalThis.fetch).toHaveBeenCalledTimes(1);

    await expect(fetchIdentities()).resolves.toMatchObject({ email: 'e' });
    // Still just the one call from the first fetchIdentities() above.
    expect(globalThis.fetch).toHaveBeenCalledTimes(1);
  });

  it('re-fetches from the broker once the cache entry has expired', async () => {
    vi.useFakeTimers();
    try {
      globalThis.fetch = mockJson(200, identity);
      await fetchIdentities();
      expect(globalThis.fetch).toHaveBeenCalledTimes(1);

      vi.advanceTimersByTime(5 * 60 * 1000 + 1);

      await fetchIdentities();
      expect(globalThis.fetch).toHaveBeenCalledTimes(2);
    } finally {
      vi.useRealTimers();
    }
  });

  it('clears the cache when SessionExpiredError is thrown from any api call', async () => {
    globalThis.fetch = mockJson(200, identity);
    await fetchIdentities();
    expect(window.sessionStorage.getItem('af-portal.identities')).not.toBeNull();

    // Force a SessionExpiredError (no token, OIDC configured) from a
    // *different* endpoint than the one whose cache we're checking — this is
    // the "any api call" case, since fetchIdentities() itself would just
    // serve the still-fresh cache without ever reaching apiFetch().
    vi.mocked(auth.getAccessToken).mockResolvedValue(null);
    globalThis.fetch = vi.fn();
    await expect(fetchProxyStatus()).rejects.toBeInstanceOf(SessionExpiredError);
    expect(window.sessionStorage.getItem('af-portal.identities')).toBeNull();
  });

  it('clearIdentitiesCache() removes a populated cache entry', async () => {
    globalThis.fetch = mockJson(200, identity);
    await fetchIdentities();
    expect(window.sessionStorage.getItem('af-portal.identities')).not.toBeNull();

    clearIdentitiesCache();
    expect(window.sessionStorage.getItem('af-portal.identities')).toBeNull();

    await fetchIdentities();
    expect(globalThis.fetch).toHaveBeenCalledTimes(2);
  });
});

describe('fetchOAuth21AuthorizeUrl()', () => {
  const LINK_URL =
    'https://mcp.example.com/v1/oauth/authorize/rucio-mcp-atlas?return=%2Fidentities%2F';

  it('sends the Bearer and Accept: application/json against the absolute link_url', async () => {
    globalThis.fetch = mockJson(200, {
      authorize_url: 'https://backend-as.example/authorize?client_id=x',
    });
    await fetchOAuth21AuthorizeUrl(LINK_URL);
    expect(globalThis.fetch).toHaveBeenCalledWith(
      LINK_URL,
      expect.objectContaining({
        headers: expect.objectContaining({
          Authorization: 'Bearer test-token',
          Accept: 'application/json',
        }),
      }),
    );
  });

  it('returns the authorize_url from the parsed JSON body', async () => {
    globalThis.fetch = mockJson(200, {
      authorize_url: 'https://backend-as.example/authorize?client_id=x',
    });
    await expect(fetchOAuth21AuthorizeUrl(LINK_URL)).resolves.toBe(
      'https://backend-as.example/authorize?client_id=x',
    );
  });

  it('raises APIError with the response body on non-2xx', async () => {
    globalThis.fetch = vi
      .fn()
      .mockResolvedValue(new Response('nope', { status: 503, statusText: 'Service Unavailable' }));
    await expect(fetchOAuth21AuthorizeUrl(LINK_URL)).rejects.toMatchObject({
      name: 'APIError',
      status: 503,
      body: 'nope',
    });
  });

  it('throws SessionExpiredError without hitting the network when there is no token', async () => {
    vi.mocked(auth.getAccessToken).mockResolvedValue(null);
    globalThis.fetch = vi.fn();
    await expect(fetchOAuth21AuthorizeUrl(LINK_URL)).rejects.toBeInstanceOf(SessionExpiredError);
    expect(globalThis.fetch).not.toHaveBeenCalled();
  });
});

describe('unlinkIdentity()', () => {
  it('sends a DELETE against /identities/link/{provider} with the Bearer', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue(new Response(null, { status: 204 }));
    await unlinkIdentity('rucio-mcp-atlas');
    expect(globalThis.fetch).toHaveBeenCalledWith(
      expect.stringContaining('/identities/link/rucio-mcp-atlas'),
      expect.objectContaining({
        method: 'DELETE',
        headers: expect.objectContaining({ Authorization: 'Bearer test-token' }),
      }),
    );
  });

  it('encodes the provider id in the URL path', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue(new Response(null, { status: 204 }));
    await unlinkIdentity('a/b');
    expect(globalThis.fetch).toHaveBeenCalledWith(
      expect.stringContaining('/identities/link/a%2Fb'),
      expect.anything(),
    );
  });

  it('resolves to undefined on a 204 response', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue(new Response(null, { status: 204 }));
    await expect(unlinkIdentity('rucio-mcp-atlas')).resolves.toBeUndefined();
  });

  it('raises APIError with the response body on non-2xx (e.g. 501 for keycloak-brokered)', async () => {
    globalThis.fetch = vi
      .fn()
      .mockResolvedValue(
        new Response('not implemented', { status: 501, statusText: 'Not Implemented' }),
      );
    await expect(unlinkIdentity('atlas-iam')).rejects.toMatchObject({
      name: 'APIError',
      status: 501,
      body: 'not implemented',
    });
  });

  it('throws SessionExpiredError without hitting the network when there is no token', async () => {
    vi.mocked(auth.getAccessToken).mockResolvedValue(null);
    globalThis.fetch = vi.fn();
    await expect(unlinkIdentity('rucio-mcp-atlas')).rejects.toBeInstanceOf(SessionExpiredError);
    expect(globalThis.fetch).not.toHaveBeenCalled();
  });
});

describe('revokeAllCredentials()', () => {
  it('sends DELETE /v1/credential with the Bearer', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue(new Response(null, { status: 204 }));
    await revokeAllCredentials();
    expect(globalThis.fetch).toHaveBeenCalledWith(
      expect.stringContaining('/credential'),
      expect.objectContaining({
        method: 'DELETE',
        headers: expect.objectContaining({ Authorization: 'Bearer test-token' }),
      }),
    );
  });

  it('raises APIError with the response body on non-2xx', async () => {
    globalThis.fetch = vi
      .fn()
      .mockResolvedValue(new Response('nope', { status: 500, statusText: 'Server Error' }));
    await expect(revokeAllCredentials()).rejects.toMatchObject({
      name: 'APIError',
      status: 500,
      body: 'nope',
    });
  });
});

describe('fetchDashboardSummary()', () => {
  it('counts only linked providers, regardless of provider type', async () => {
    globalThis.fetch = vi.fn((input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes('/identities')) {
        return Promise.resolve(
          new Response(
            JSON.stringify({
              subject: 's',
              email: 'e',
              unixname: 'u',
              uid: 1,
              gid: 2,
              groups: [],
              providers: [
                {
                  id: 'atlas-iam',
                  type: 'keycloak-brokered',
                  display_name: 'ATLAS IAM',
                  enables: '',
                  linked: true,
                  link_url: null,
                },
                {
                  id: 'rucio-mcp-atlas',
                  type: 'oauth21-direct',
                  display_name: 'Rucio (ATLAS)',
                  enables: '',
                  linked: false,
                  link_url: '/v1/oauth/authorize/rucio-mcp-atlas',
                },
                {
                  id: 'cern',
                  type: 'keycloak-brokered',
                  display_name: 'CERN SSO',
                  enables: '',
                  linked: true,
                  link_url: null,
                },
              ],
            }),
            { status: 200, headers: { 'Content-Type': 'application/json' } },
          ),
        );
      }
      if (url.includes('/catalog')) {
        return Promise.resolve(
          new Response(
            JSON.stringify({
              servers: [
                {
                  name: 'rucio',
                  display_name: 'Rucio',
                  description: 'ATLAS distributed data management',
                  permission: 'read_data',
                  auth_type: 'bearer',
                  action_type: 'read',
                  credential_provider: 'atlas-iam',
                  tools: [],
                },
                {
                  name: 'docs',
                  display_name: 'Docs',
                  description: 'Facility documentation',
                  permission: '__none__',
                  auth_type: 'none',
                  action_type: 'read',
                  credential_provider: null,
                  tools: [],
                },
              ],
            }),
            { status: 200, headers: { 'Content-Type': 'application/json' } },
          ),
        );
      }
      if (url.includes('/tokens')) {
        return Promise.resolve(
          new Response(
            JSON.stringify([
              {
                lookup_id: 'a',
                name: 'active-1',
                note: null,
                created_at: '2024-01-01T00:00:00Z',
                expires_at: null,
                revoked_at: null,
                last_used_at: null,
                permission_grant: null,
              },
              {
                lookup_id: 'b',
                name: 'active-2',
                note: null,
                created_at: '2024-01-01T00:00:00Z',
                expires_at: null,
                revoked_at: null,
                last_used_at: null,
                permission_grant: null,
              },
              {
                lookup_id: 'c',
                name: 'revoked-1',
                note: null,
                created_at: '2024-01-01T00:00:00Z',
                expires_at: null,
                revoked_at: '2024-02-01T00:00:00Z',
                last_used_at: null,
                permission_grant: null,
              },
            ]),
            { status: 200, headers: { 'Content-Type': 'application/json' } },
          ),
        );
      }
      return Promise.resolve(
        new Response(JSON.stringify({ cached: false, voms_attributes: [] }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }),
      );
    });

    const summary = await fetchDashboardSummary();
    expect(summary.linkedCount).toBe(2);
    expect(summary.serverCount).toBe(2);
    expect(summary.activeTokenCount).toBe(2);
  });
});

describe('permissions client (issue #144 step 4: permission PATs)', () => {
  it('fetchPermissions returns the parsed grants and the callers raw groups', async () => {
    globalThis.fetch = mockJson(200, {
      subject: 'sub-abc',
      groups: ['atlas', 'af-admins'],
      grants: [
        { permission: 'read_data', targets: ['rucio'], action_types: ['read'] },
        { permission: 'submit_jobs', targets: ['panda'], action_types: ['state_change'] },
      ],
    });

    const result = await fetchPermissions();

    expect(result.subject).toBe('sub-abc');
    expect(result.groups).toEqual(['atlas', 'af-admins']);
    expect(result.grants.map((g) => g.permission)).toEqual(['read_data', 'submit_jobs']);
  });

  it('fetchEntitlements returns the static group -> permission table', async () => {
    globalThis.fetch = mockJson(200, {
      group_permissions: {
        atlas: ['read_data', 'submit_jobs'],
        'af-admins': ['admin'],
      },
    });

    const result = await fetchEntitlements();

    expect(result.group_permissions.atlas).toEqual(['read_data', 'submit_jobs']);
    expect(result.group_permissions['af-admins']).toEqual(['admin']);
  });
});

describe('tokens client (issue #144 step 2a: broker-issued identity PAT)', () => {
  it('mintToken posts name and returns the one-shot token', async () => {
    const fetchMock = mockJson(200, {
      token: 'mcp_pat_abc123_fake-secret',
      lookup_id: 'abc123',
      created_at: '2026-07-21T00:00:00+00:00',
      expires_at: '2026-10-19T00:00:00+00:00',
      name: 'claude-desktop',
      note: null,
    });
    globalThis.fetch = fetchMock;

    const result = await mintToken('claude-desktop');

    expect(result.token).toBe('mcp_pat_abc123_fake-secret');
    expect(result.lookup_id).toBe('abc123');
    const [, init] = fetchMock.mock.calls[0];
    expect(init.method).toBe('POST');
    expect(JSON.parse(init.body as string)).toEqual({ name: 'claude-desktop' });
  });

  it('mintToken omits name when not provided', async () => {
    const fetchMock = mockJson(200, {
      token: 't',
      lookup_id: 'lookup-2',
      created_at: '2026-07-21T00:00:00+00:00',
      expires_at: '2026-10-19T00:00:00+00:00',
      name: 'mcp-20260721-lookup2a',
      note: null,
    });
    globalThis.fetch = fetchMock;

    await mintToken();

    const [, init] = fetchMock.mock.calls[0];
    expect(JSON.parse(init.body as string)).toEqual({});
  });

  it('mintToken passes expiresInDays through as expires_in_days', async () => {
    const fetchMock = mockJson(200, {
      token: 't',
      lookup_id: 'lookup-3',
      created_at: '2026-07-21T00:00:00+00:00',
      expires_at: '2026-07-28T00:00:00+00:00',
      name: 'x',
      note: null,
    });
    globalThis.fetch = fetchMock;

    await mintToken('x', undefined, 7);

    const [, init] = fetchMock.mock.calls[0];
    expect(JSON.parse(init.body as string)).toEqual({ name: 'x', expires_in_days: 7 });
  });

  it('mintToken passes neverExpires through as never_expires', async () => {
    const fetchMock = mockJson(200, {
      token: 't',
      lookup_id: 'lookup-4',
      created_at: '2026-07-21T00:00:00+00:00',
      expires_at: null,
      name: 'x',
      note: null,
    });
    globalThis.fetch = fetchMock;

    await mintToken('x', undefined, undefined, true);

    const [, init] = fetchMock.mock.calls[0];
    expect(JSON.parse(init.body as string)).toEqual({ name: 'x', never_expires: true });
  });

  it('listTokens returns the parsed array and never a token value', async () => {
    globalThis.fetch = mockJson(200, [
      {
        lookup_id: 'lookup-1',
        name: 'claude-desktop',
        note: null,
        created_at: '2026-07-21T00:00:00+00:00',
        expires_at: '2026-10-19T00:00:00+00:00',
        revoked_at: null,
        last_used_at: null,
        permission_grant: null,
      },
    ]);

    const rows = await listTokens();
    expect(rows).toHaveLength(1);
    expect(rows[0].revoked_at).toBeNull();
    expect(rows[0].last_used_at).toBeNull();
    expect(rows[0].permission_grant).toBeNull();
    expect(rows[0]).not.toHaveProperty('token');
  });

  it("listTokens surfaces a permission PAT row's scoped permission_grant", async () => {
    globalThis.fetch = mockJson(200, [
      {
        lookup_id: 'lookup-scoped',
        name: 'ci-bot',
        note: null,
        created_at: '2026-07-21T00:00:00+00:00',
        expires_at: '2026-10-19T00:00:00+00:00',
        revoked_at: null,
        last_used_at: null,
        permission_grant: ['read_data', 'submit_jobs'],
      },
    ]);

    const rows = await listTokens();
    expect(rows[0].permission_grant).toEqual(['read_data', 'submit_jobs']);
  });

  it('mintToken passes permissions through and returns the resulting permission_grant', async () => {
    const fetchMock = mockJson(200, {
      token: 't',
      lookup_id: 'lookup-5',
      created_at: '2026-07-21T00:00:00+00:00',
      expires_at: '2026-10-19T00:00:00+00:00',
      name: 'ci-bot',
      note: null,
      permission_grant: ['read_data'],
    });
    globalThis.fetch = fetchMock;

    const result = await mintToken('ci-bot', undefined, undefined, undefined, ['read_data']);

    const [, init] = fetchMock.mock.calls[0];
    expect(JSON.parse(init.body as string)).toEqual({
      name: 'ci-bot',
      permissions: ['read_data'],
    });
    expect(result.permission_grant).toEqual(['read_data']);
  });

  it('mintToken omits permissions when not provided', async () => {
    const fetchMock = mockJson(200, {
      token: 't',
      lookup_id: 'lookup-6',
      created_at: '2026-07-21T00:00:00+00:00',
      expires_at: '2026-10-19T00:00:00+00:00',
      name: 'x',
      note: null,
      permission_grant: null,
    });
    globalThis.fetch = fetchMock;

    await mintToken('x');

    const [, init] = fetchMock.mock.calls[0];
    expect(JSON.parse(init.body as string)).toEqual({ name: 'x' });
  });

  it('revokeToken DELETEs the lookup_id-scoped path', async () => {
    const fetchMock = mockJson(200, { lookup_id: 'lookup-1', revoked: true });
    globalThis.fetch = fetchMock;

    await revokeToken('lookup-1');

    const [url, init] = fetchMock.mock.calls[0];
    expect(String(url)).toContain('/tokens/lookup-1');
    expect(init.method).toBe('DELETE');
  });

  it('revokeToken URL-encodes the lookup_id', async () => {
    const fetchMock = mockJson(200, { lookup_id: 'weird/id', revoked: true });
    globalThis.fetch = fetchMock;

    await revokeToken('weird/id');

    const [url] = fetchMock.mock.calls[0];
    expect(String(url)).toContain('/tokens/weird%2Fid');
  });

  it('mintToken maps a 401 to SessionExpiredError', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue(new Response('', { status: 401 }));
    await expect(mintToken()).rejects.toBeInstanceOf(SessionExpiredError);
  });
});

describe('requestProxy() custody consent', () => {
  it('sends remember: true by default (hands-free renewal preserved)', async () => {
    globalThis.fetch = mockJson(201, {
      dn: '/CN=x',
      voms_attributes: [],
      expires_at: '2026-08-27T00:00:00+00:00',
      remaining_seconds: 100,
    });
    await requestProxy('hunter2');
    const [, init] = vi.mocked(globalThis.fetch).mock.calls[0] as [string, RequestInit];
    expect(JSON.parse(init.body as string)).toMatchObject({
      passphrase: 'hunter2',
      remember: true,
    });
  });

  it('sends remember: false when the user unchecks the consent box', async () => {
    globalThis.fetch = mockJson(201, {
      dn: '/CN=x',
      voms_attributes: [],
      expires_at: '2026-08-27T00:00:00+00:00',
      remaining_seconds: 100,
    });
    await requestProxy('hunter2', '12:00', 'atlas', false);
    const [, init] = vi.mocked(globalThis.fetch).mock.calls[0] as [string, RequestInit];
    expect(JSON.parse(init.body as string)).toMatchObject({ remember: false });
  });
});

describe('requestKrb5Ticket', () => {
  it('POSTs username/password and returns ticket metadata', async () => {
    globalThis.fetch = mockJson(201, {
      target: 'condor',
      principal: 'auser@ATLAS.EXAMPLE.ORG',
      realm: 'ATLAS.EXAMPLE.ORG',
      expires_at: '2026-09-04T00:00:00+00:00',
      remaining_seconds: 86400,
      renew_until: '2026-09-10T00:00:00+00:00',
    });

    const result = await requestKrb5Ticket('auser', 'hunter2');

    const [url, init] = vi.mocked(globalThis.fetch).mock.calls[0] as [string, RequestInit];
    expect(String(url)).toContain('/krb5/ticket');
    expect(init.method).toBe('POST');
    expect(JSON.parse(init.body as string)).toEqual({ username: 'auser', password: 'hunter2' });
    expect(result).toEqual({
      target: 'condor',
      principal: 'auser@ATLAS.EXAMPLE.ORG',
      realm: 'ATLAS.EXAMPLE.ORG',
      expires_at: '2026-09-04T00:00:00+00:00',
      remaining_seconds: 86400,
      renew_until: '2026-09-10T00:00:00+00:00',
    });
  });

  it('includes target/lifetime/renewable_lifetime in the body when supplied', async () => {
    globalThis.fetch = mockJson(201, {
      target: 'condor',
      principal: 'auser@ATLAS.EXAMPLE.ORG',
      realm: 'ATLAS.EXAMPLE.ORG',
      expires_at: '2026-09-04T00:00:00+00:00',
      remaining_seconds: 86400,
      renew_until: null,
    });

    await requestKrb5Ticket('auser', 'hunter2', 'condor', '24h', '7d');

    const [, init] = vi.mocked(globalThis.fetch).mock.calls[0] as [string, RequestInit];
    expect(JSON.parse(init.body as string)).toEqual({
      username: 'auser',
      password: 'hunter2',
      target: 'condor',
      lifetime: '24h',
      renewable_lifetime: '7d',
    });
  });

  it.each([400, 403, 422, 429, 502])(
    'raises APIError with the response body on a %i response',
    async (status) => {
      globalThis.fetch = vi
        .fn()
        .mockResolvedValue(new Response('nope', { status, statusText: 'Error' }));
      await expect(requestKrb5Ticket('auser', 'wrong')).rejects.toMatchObject({
        name: 'APIError',
        status,
        body: 'nope',
      });
    },
  );
});

describe('fetchX509Preflight()', () => {
  it('GETs /x509/preflight and returns the checklist verbatim', async () => {
    const body = {
      unixname: 'auser',
      root: '/home/auser/.globus',
      ok: false,
      checks: [
        {
          name: 'userkey',
          path: '/home/auser/.globus/userkey.pem',
          exists: true,
          mode: '0644',
          readable_by_service: true,
          ok: false,
          detail: 'run: chmod 400 ~/.globus/userkey.pem',
        },
      ],
    };
    globalThis.fetch = mockJson(200, body);
    await expect(fetchX509Preflight()).resolves.toEqual(body);
    const [url] = vi.mocked(globalThis.fetch).mock.calls[0] as [string, RequestInit];
    expect(url).toContain('/x509/preflight');
  });
});

describe('fetchServerTools()', () => {
  it('GETs the per-backend tools path and returns the listing verbatim', async () => {
    const body = {
      name: 'rucio',
      display_name: 'Rucio',
      description: 'ATLAS data management',
      status: 'ok',
      status_detail: 'Methods listed.',
      tools: [{ name: 'rucio_list_dids', description: 'List DIDs.', action_type: 'read' }],
    };
    globalThis.fetch = mockJson(200, body);
    await expect(fetchServerTools('rucio')).resolves.toEqual(body);
    const [url] = vi.mocked(globalThis.fetch).mock.calls[0] as [string, RequestInit];
    expect(url).toContain('/catalog/rucio/tools');
  });

  it('URL-encodes the backend name', async () => {
    globalThis.fetch = mockJson(200, {
      name: 'a/b',
      display_name: 'A/B',
      description: '',
      status: 'unavailable',
      status_detail: 'Temporarily unavailable. Try again shortly.',
      tools: [],
    });
    await fetchServerTools('a/b');
    const [url] = vi.mocked(globalThis.fetch).mock.calls[0] as [string, RequestInit];
    expect(url).toContain('/catalog/a%2Fb/tools');
  });
});

describe('fetchMaintenanceStatus()', () => {
  it('GETs /admin/maintenance and returns the status verbatim', async () => {
    const body = { enabled: true, reason: 'upgrade', enabled_by: 'sub-1', enabled_at: 123.4 };
    globalThis.fetch = mockJson(200, body);
    await expect(fetchMaintenanceStatus()).resolves.toEqual(body);
    const [url] = vi.mocked(globalThis.fetch).mock.calls[0] as [string, RequestInit];
    expect(url).toContain('/admin/maintenance');
  });

  it('sends no Authorization header even when a Bearer is available', async () => {
    globalThis.fetch = mockJson(200, {
      enabled: false,
      reason: null,
      enabled_by: null,
      enabled_at: null,
    });
    await fetchMaintenanceStatus();
    const [, init] = vi.mocked(globalThis.fetch).mock.calls[0] as [string, RequestInit];
    expect((init?.headers as Record<string, string> | undefined)?.Authorization).toBeUndefined();
  });

  it('succeeds with no session at all, unlike every authFetch-backed call', async () => {
    // The whole point of this route: a visitor with no valid (or renewable)
    // OIDC session must still be able to see the maintenance banner —
    // authFetch would throw SessionExpiredError before ever calling fetch()
    // in this exact scenario (see authFetch's early-exit branch).
    vi.mocked(auth.getAccessToken).mockResolvedValue(null);
    vi.mocked(auth.isOidcConfigured).mockResolvedValue(true);
    globalThis.fetch = mockJson(200, {
      enabled: false,
      reason: null,
      enabled_by: null,
      enabled_at: null,
    });
    await expect(fetchMaintenanceStatus()).resolves.toEqual({
      enabled: false,
      reason: null,
      enabled_by: null,
      enabled_at: null,
    });
  });

  it('raises APIError with the response body on non-2xx', async () => {
    globalThis.fetch = vi
      .fn()
      .mockResolvedValue(new Response('nope', { status: 500, statusText: 'Server Error' }));
    await expect(fetchMaintenanceStatus()).rejects.toMatchObject({
      name: 'APIError',
      status: 500,
    });
  });

  it('propagates a raw network failure (DNS/connection error) rather than swallowing it', async () => {
    // The exact scenario the banner exists for -- a real fetch() rejection,
    // not merely a non-2xx response. Same pattern as auth.test.ts's
    // getBrokerOrigin() network-failure test.
    globalThis.fetch = vi.fn().mockRejectedValue(new Error('network down'));
    await expect(fetchMaintenanceStatus()).rejects.toThrow('network down');
  });
});

describe('setMaintenanceStatus()', () => {
  it('POSTs enabled/reason to /admin/maintenance with a Bearer and returns the status', async () => {
    const body = { enabled: true, reason: 'upgrade', enabled_by: 'sub-1', enabled_at: 123.4 };
    globalThis.fetch = mockJson(200, body);
    await expect(setMaintenanceStatus(true, 'upgrade')).resolves.toEqual(body);
    const [url, init] = vi.mocked(globalThis.fetch).mock.calls[0] as [string, RequestInit];
    expect(url).toContain('/admin/maintenance');
    expect(init.method).toBe('POST');
    expect(JSON.parse(init.body as string)).toEqual({ enabled: true, reason: 'upgrade' });
    expect((init.headers as Record<string, string>).Authorization).toBe('Bearer test-token');
  });

  it('omits reason from the body when not supplied', async () => {
    globalThis.fetch = mockJson(200, {
      enabled: false,
      reason: null,
      enabled_by: null,
      enabled_at: null,
    });
    await setMaintenanceStatus(false);
    const [, init] = vi.mocked(globalThis.fetch).mock.calls[0] as [string, RequestInit];
    expect(JSON.parse(init.body as string)).toEqual({ enabled: false });
  });

  it('raises APIError on a 403 (non-admin caller)', async () => {
    globalThis.fetch = vi
      .fn()
      .mockResolvedValue(
        new Response('{"detail":"forbidden"}', { status: 403, statusText: 'Forbidden' }),
      );
    await expect(setMaintenanceStatus(true)).rejects.toMatchObject({
      name: 'APIError',
      status: 403,
    });
  });

  it('raises APIError on a 409 (concurrent admin write)', async () => {
    globalThis.fetch = vi
      .fn()
      .mockResolvedValue(
        new Response('{"detail":"conflict"}', { status: 409, statusText: 'Conflict' }),
      );
    await expect(setMaintenanceStatus(true)).rejects.toMatchObject({
      name: 'APIError',
      status: 409,
    });
  });
});
