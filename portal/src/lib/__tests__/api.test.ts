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
  fetchIdentities,
  mintToken,
  listTokens,
  revokeToken,
} from '../api';

// Stash + restore the real fetch. The tests below install a per-test mock.
const realFetch = globalThis.fetch;

beforeEach(() => {
  vi.restoreAllMocks();
});

afterEach(() => {
  globalThis.fetch = realFetch;
});

function mockJson(status: number, body: unknown) {
  return vi.fn().mockResolvedValue(
    new Response(JSON.stringify(body), {
      status,
      headers: { 'Content-Type': 'application/json' },
    }),
  );
}

describe('api client', () => {
  it('exports the two error classes distinctly', () => {
    expect(new APIError(500, 'boom', 'x')).toBeInstanceOf(Error);
    expect(new SessionExpiredError()).toBeInstanceOf(Error);
    // Different classes so callers can discriminate with instanceof.
    expect(new SessionExpiredError()).not.toBeInstanceOf(APIError);
  });

  it('maps a 401 to SessionExpiredError', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue(new Response('', { status: 401 }));
    await expect(fetchIdentities()).rejects.toBeInstanceOf(SessionExpiredError);
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

describe('tokens client (issue #24)', () => {
  it('mintToken posts ttl_seconds and note, returns the one-shot token', async () => {
    const fetchMock = mockJson(200, {
      token: 'eyJraWQ...fake',
      jti: 'jti-1',
      issued_at: '2026-07-21T00:00:00+00:00',
      expires_at: '2026-07-21T01:00:00+00:00',
      note: 'claude-desktop',
    });
    globalThis.fetch = fetchMock;

    const result = await mintToken(3600, 'claude-desktop');

    expect(result.token).toBe('eyJraWQ...fake');
    expect(result.jti).toBe('jti-1');
    const [, init] = fetchMock.mock.calls[0];
    expect(init.method).toBe('POST');
    expect(JSON.parse(init.body as string)).toEqual({ ttl_seconds: 3600, note: 'claude-desktop' });
  });

  it('mintToken omits note when not provided', async () => {
    const fetchMock = mockJson(200, {
      token: 't',
      jti: 'jti-2',
      issued_at: '2026-07-21T00:00:00+00:00',
      expires_at: '2026-07-21T01:00:00+00:00',
    });
    globalThis.fetch = fetchMock;

    await mintToken(3600);

    const [, init] = fetchMock.mock.calls[0];
    expect(JSON.parse(init.body as string)).toEqual({ ttl_seconds: 3600 });
  });

  it('listTokens returns the parsed array and never a token value', async () => {
    globalThis.fetch = mockJson(200, [
      {
        jti: 'jti-1',
        issued_at: '2026-07-21T00:00:00+00:00',
        expires_at: '2026-07-21T01:00:00+00:00',
        source: 'manual',
        note: null,
        last_used_at: null,
      },
    ]);

    const rows = await listTokens();
    expect(rows).toHaveLength(1);
    expect(rows[0].source).toBe('manual');
    expect(rows[0]).not.toHaveProperty('token');
  });

  it('revokeToken DELETEs the jti-scoped path', async () => {
    const fetchMock = mockJson(200, { jti: 'jti-1', revoked: true });
    globalThis.fetch = fetchMock;

    await revokeToken('jti-1');

    const [url, init] = fetchMock.mock.calls[0];
    expect(String(url)).toContain('/tokens/jti-1');
    expect(init.method).toBe('DELETE');
  });

  it('revokeToken URL-encodes the jti', async () => {
    const fetchMock = mockJson(200, { jti: 'weird/jti', revoked: true });
    globalThis.fetch = fetchMock;

    await revokeToken('weird/jti');

    const [url] = fetchMock.mock.calls[0];
    expect(String(url)).toContain('/tokens/weird%2Fjti');
  });

  it('mintToken maps a 401 to SessionExpiredError', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue(new Response('', { status: 401 }));
    await expect(mintToken(3600)).rejects.toBeInstanceOf(SessionExpiredError);
  });
});
