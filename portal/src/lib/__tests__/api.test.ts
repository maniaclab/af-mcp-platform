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
  SessionExpiredError,
  clearIdentitiesCache,
  fetchCapabilities,
  fetchDashboardSummary,
  fetchIdentities,
  fetchOAuth21AuthorizeUrl,
  fetchProxyStatus,
  listTokens,
  mintToken,
  revokeAllCredentials,
  revokeToken,
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
  it('exports the two error classes distinctly', () => {
    expect(new APIError(500, 'boom', 'x')).toBeInstanceOf(Error);
    expect(new SessionExpiredError()).toBeInstanceOf(Error);
    // Different classes so callers can discriminate with instanceof.
    expect(new SessionExpiredError()).not.toBeInstanceOf(APIError);
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
        },
      ],
    });
    const result = await fetchIdentities();
    expect(result.email).toBe('e');
    expect(result.providers).toHaveLength(1);
    expect(result.providers[0]).toMatchObject({ id: 'atlas-iam', linked: true });
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
                  capability: 'read_data',
                  auth_type: 'bearer',
                  action_type: 'read',
                  credential_provider: 'atlas-iam',
                  tools: [],
                },
                {
                  name: 'docs',
                  display_name: 'Docs',
                  description: 'Facility documentation',
                  capability: '__none__',
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
                capability_grant: null,
              },
              {
                lookup_id: 'b',
                name: 'active-2',
                note: null,
                created_at: '2024-01-01T00:00:00Z',
                expires_at: null,
                revoked_at: null,
                last_used_at: null,
                capability_grant: null,
              },
              {
                lookup_id: 'c',
                name: 'revoked-1',
                note: null,
                created_at: '2024-01-01T00:00:00Z',
                expires_at: null,
                revoked_at: '2024-02-01T00:00:00Z',
                last_used_at: null,
                capability_grant: null,
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

describe('capabilities client (issue #144 step 4: capability PATs)', () => {
  it('fetchCapabilities returns the parsed grants', async () => {
    globalThis.fetch = mockJson(200, {
      subject: 'sub-abc',
      grants: [
        { capability: 'read_data', targets: ['rucio'], action_types: ['read'] },
        { capability: 'submit_jobs', targets: ['panda'], action_types: ['state_change'] },
      ],
    });

    const result = await fetchCapabilities();

    expect(result.subject).toBe('sub-abc');
    expect(result.grants.map((g) => g.capability)).toEqual(['read_data', 'submit_jobs']);
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
        capability_grant: null,
      },
    ]);

    const rows = await listTokens();
    expect(rows).toHaveLength(1);
    expect(rows[0].revoked_at).toBeNull();
    expect(rows[0].last_used_at).toBeNull();
    expect(rows[0].capability_grant).toBeNull();
    expect(rows[0]).not.toHaveProperty('token');
  });

  it("listTokens surfaces a capability PAT row's scoped capability_grant", async () => {
    globalThis.fetch = mockJson(200, [
      {
        lookup_id: 'lookup-scoped',
        name: 'ci-bot',
        note: null,
        created_at: '2026-07-21T00:00:00+00:00',
        expires_at: '2026-10-19T00:00:00+00:00',
        revoked_at: null,
        last_used_at: null,
        capability_grant: ['read_data', 'submit_jobs'],
      },
    ]);

    const rows = await listTokens();
    expect(rows[0].capability_grant).toEqual(['read_data', 'submit_jobs']);
  });

  it('mintToken passes capabilities through and returns the resulting capability_grant', async () => {
    const fetchMock = mockJson(200, {
      token: 't',
      lookup_id: 'lookup-5',
      created_at: '2026-07-21T00:00:00+00:00',
      expires_at: '2026-10-19T00:00:00+00:00',
      name: 'ci-bot',
      note: null,
      capability_grant: ['read_data'],
    });
    globalThis.fetch = fetchMock;

    const result = await mintToken('ci-bot', undefined, undefined, undefined, ['read_data']);

    const [, init] = fetchMock.mock.calls[0];
    expect(JSON.parse(init.body as string)).toEqual({
      name: 'ci-bot',
      capabilities: ['read_data'],
    });
    expect(result.capability_grant).toEqual(['read_data']);
  });

  it('mintToken omits capabilities when not provided', async () => {
    const fetchMock = mockJson(200, {
      token: 't',
      lookup_id: 'lookup-6',
      created_at: '2026-07-21T00:00:00+00:00',
      expires_at: '2026-10-19T00:00:00+00:00',
      name: 'x',
      note: null,
      capability_grant: null,
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
