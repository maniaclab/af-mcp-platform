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
  fetchIdentities,
  fetchProxyStatus,
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
      linked_accounts: [],
      available_providers: [],
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
      linked_accounts: [],
      available_providers: [],
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
            linked_accounts: [],
            available_providers: [],
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
      linked_accounts: [],
      available_providers: [],
    });
    const result = await fetchIdentities();
    expect(result.email).toBe('e');
    expect(result.linked_accounts).toEqual([]);
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
    linked_accounts: [],
    available_providers: [],
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
