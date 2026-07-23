/**
 * Tests for the OIDC wrapper. Each test imports a fresh copy of ../auth
 * (via vi.resetModules() + dynamic import) because the module caches its
 * runtime-config fetch and UserManager in module-level singletons — reusing
 * one import across tests would leak state between them.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const realFetch = globalThis.fetch;

beforeEach(() => {
  vi.resetModules();
});

afterEach(() => {
  globalThis.fetch = realFetch;
  vi.doUnmock('oidc-client-ts');
});

function mockConfig(config: unknown) {
  globalThis.fetch = vi.fn().mockResolvedValue(
    new Response(JSON.stringify(config), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    }),
  );
}

describe('auth — OIDC not configured (dev-bypass mode)', () => {
  beforeEach(() => {
    mockConfig({
      oidc: { issuer: '', clientId: '', scope: 'openid profile email' },
      brokerOrigin: '',
    });
  });

  it('getUser() resolves null without constructing a UserManager', async () => {
    const { getUser } = await import('../auth');
    await expect(getUser()).resolves.toBeNull();
  });

  it('isOidcConfigured() resolves false', async () => {
    const { isOidcConfigured } = await import('../auth');
    await expect(isOidcConfigured()).resolves.toBe(false);
  });

  it('getAccessToken() resolves null', async () => {
    const { getAccessToken } = await import('../auth');
    await expect(getAccessToken()).resolves.toBeNull();
  });

  it('login() and logout() warn and resolve without throwing', async () => {
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const { login, logout } = await import('../auth');
    await expect(login()).resolves.toBeUndefined();
    await expect(logout()).resolves.toBeUndefined();
    expect(warnSpy).toHaveBeenCalled();
  });

  it('handleCallback() rejects rather than crashing', async () => {
    const { handleCallback } = await import('../auth');
    await expect(handleCallback()).rejects.toThrow(/not configured/i);
  });
});

describe('auth — /config.json unreachable', () => {
  it('degrades to unconfigured instead of throwing', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue(new Response('', { status: 500 }));
    vi.spyOn(console, 'warn').mockImplementation(() => {});
    const { getUser, isOidcConfigured } = await import('../auth');
    await expect(isOidcConfigured()).resolves.toBe(false);
    await expect(getUser()).resolves.toBeNull();
  });
});

describe('auth — OIDC configured', () => {
  const signinRedirect = vi.fn().mockResolvedValue(undefined);
  const signinSilent = vi.fn();
  const getUserMock = vi.fn();

  beforeEach(() => {
    signinRedirect.mockClear();
    signinSilent.mockClear();
    getUserMock.mockClear();
    mockConfig({
      oidc: {
        issuer: 'https://kc.example.com/realms/test',
        clientId: 'test-client',
        scope: 'openid mcp-gateway',
      },
      brokerOrigin: 'https://mcp.example.com',
    });
    // Plain `function` (not arrow) implementations — auth.ts calls both of
    // these with `new`, and mockImplementation with an arrow function isn't
    // a valid constructor.
    vi.doMock('oidc-client-ts', () => ({
      UserManager: vi.fn().mockImplementation(function (settings: unknown) {
        return {
          settings,
          signinRedirect,
          signinSilent,
          getUser: getUserMock,
          signoutRedirect: vi.fn(),
        };
      }),
      WebStorageStateStore: vi.fn().mockImplementation(function (opts: unknown) {
        return opts;
      }),
    }));
  });

  it('isOidcConfigured() resolves true', async () => {
    const { isOidcConfigured } = await import('../auth');
    await expect(isOidcConfigured()).resolves.toBe(true);
  });

  it('login() calls signinRedirect with the current path as state', async () => {
    const { login } = await import('../auth');
    await login();
    expect(signinRedirect).toHaveBeenCalledWith(
      expect.objectContaining({
        state: expect.objectContaining({ returnUrl: expect.any(String) }),
      }),
    );
  });

  it('getAccessToken() returns the cached token when not expired', async () => {
    getUserMock.mockResolvedValue({ expired: false, access_token: 'live-token' });
    const { getAccessToken } = await import('../auth');
    await expect(getAccessToken()).resolves.toBe('live-token');
    expect(signinSilent).not.toHaveBeenCalled();
  });

  it('getAccessToken() renews via signinSilent() when expired', async () => {
    getUserMock.mockResolvedValue({ expired: true, access_token: 'stale-token' });
    signinSilent.mockResolvedValue({ access_token: 'fresh-token' });
    const { getAccessToken } = await import('../auth');
    await expect(getAccessToken()).resolves.toBe('fresh-token');
    expect(signinSilent).toHaveBeenCalledTimes(1);
  });

  it('renewAccessToken() returns null when signinSilent() throws', async () => {
    signinSilent.mockRejectedValue(new Error('no refresh token'));
    const { renewAccessToken } = await import('../auth');
    await expect(renewAccessToken()).resolves.toBeNull();
  });
});
