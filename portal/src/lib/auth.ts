/**
 * auth.ts — thin wrapper around oidc-client-ts's `UserManager` for the portal SPA.
 *
 * OIDC configuration (Keycloak issuer, portal client id, scope) is NOT baked
 * into the build. It's fetched at runtime from `/config.json`, a static file
 * the Helm chart renders from `portal.oidc.*` values into a ConfigMap and
 * mounts over the build's placeholder copy (see
 * `charts/af-mcp-platform/templates/configmap-portal-config.yaml` and the
 * checked-in `portal/public/config.json` dev stub). That keeps one built
 * portal image deployable against any realm/client/institution via values,
 * the same way the broker takes `KEYCLOAK_ISSUER` from an env var rather than
 * a build constant. If `oidc.issuer` or `oidc.clientId` come back empty — the
 * dev-without-ConfigMap case — every exported function below degrades to a
 * no-op/null instead of throwing, so `pixi run -e portal dev` still works
 * against a bypass-mode broker with no Keycloak in the loop at all.
 *
 * Token storage: sessionStorage, not localStorage — see #42 for the settled
 * decision. Tradeoff: a token stolen via XSS is scoped to the tab's lifetime
 * rather than surviving indefinitely across tabs/restarts, at the cost of
 * losing the session on tab close (a fresh, likely-silent SSO redirect fixes
 * that immediately). The portal's XSS surface is bounded — it renders only
 * build-time constants and Vue-escaped typed broker responses, under the CSP
 * in nginx.conf.template — which is why this tradeoff was judged acceptable
 * over the alternatives (localStorage widens the same-origin blast radius to
 * every tab indefinitely; an httpOnly cookie would require a backend session
 * layer we deliberately don't have).
 */
import { UserManager, WebStorageStateStore, type User } from 'oidc-client-ts';

interface RuntimeConfig {
  oidc: {
    issuer: string;
    clientId: string;
    scope: string;
  };
  brokerOrigin: string;
}

/** Custom OIDC state round-tripped through Keycloak so callback.astro knows where to send the user back. */
interface AuthState {
  returnUrl: string;
}

function redirectUri(): string {
  return `${window.location.origin}/callback`;
}

let configPromise: Promise<RuntimeConfig> | null = null;

function loadConfig(): Promise<RuntimeConfig> {
  if (!configPromise) {
    configPromise = fetch('/config.json').then((res) => {
      if (!res.ok) throw new Error(`GET /config.json failed: ${res.status}`);
      return res.json() as Promise<RuntimeConfig>;
    });
  }
  return configPromise;
}

let managerPromise: Promise<UserManager | null> | null = null;

/**
 * Lazily builds the `UserManager` from the runtime config. Returns null (and
 * warns once) if OIDC isn't configured or `/config.json` couldn't be loaded —
 * callers treat that the same as "no session, nothing to do" rather than as
 * an error.
 */
function getUserManager(): Promise<UserManager | null> {
  if (!managerPromise) {
    managerPromise = loadConfig()
      .then((cfg) => {
        if (!cfg.oidc.issuer || !cfg.oidc.clientId) {
          console.warn(
            '[auth] OIDC not configured (empty portal.oidc.issuer/clientId) — running in unauthenticated / dev-bypass mode.',
          );
          return null;
        }
        // sessionStorage backs both the User (userStore) and the in-flight
        // signin request state (stateStore — the PKCE code_verifier plus our
        // own AuthState). oidc-client-ts otherwise defaults stateStore to
        // localStorage, which would contradict the sessionStorage-only
        // decision above.
        const store = new WebStorageStateStore({ store: window.sessionStorage });
        return new UserManager({
          authority: cfg.oidc.issuer,
          client_id: cfg.oidc.clientId,
          scope: cfg.oidc.scope,
          redirect_uri: redirectUri(),
          post_logout_redirect_uri: `${window.location.origin}/`,
          response_type: 'code',
          userStore: store,
          stateStore: store,
          // Silent renew goes through the refresh_token grant (a plain
          // fetch() to the token endpoint) rather than a hidden iframe —
          // Keycloak's Standard flow issues a refresh token alongside the
          // access token, and oidc-client-ts's signinSilent() prefers it
          // automatically whenever one is present. That keeps the CSP down
          // to connect-src; no frame-src is needed. We call signinSilent()
          // explicitly (see renewAccessToken()) instead of enabling
          // automaticSilentRenew's background timer.
          automaticSilentRenew: false,
        });
      })
      .catch((err: unknown) => {
        console.warn('[auth] could not load /config.json — treating as unauthenticated.', err);
        return null;
      });
  }
  return managerPromise;
}

/**
 * Whether OIDC is configured at all (non-empty `oidc.issuer`/`clientId` in
 * `/config.json`). api.ts uses this to tell "no session in a configured
 * environment" (SessionExpiredError) apart from "no OIDC in the loop" (local
 * dev against a BROKER_DEV_INSECURE_PRINCIPAL bypass broker, which ignores
 * auth entirely and doesn't need a Bearer at all).
 */
export async function isOidcConfigured(): Promise<boolean> {
  return (await getUserManager()) !== null;
}

/** Returns the current authenticated user, or null if there is none (or it's expired). */
export async function getUser(): Promise<User | null> {
  const manager = await getUserManager();
  if (!manager) return null;
  const user = await manager.getUser();
  return user && !user.expired ? user : null;
}

/**
 * Starts the Authorization Code + PKCE redirect to Keycloak. Stashes the
 * current path in the OIDC request's `state`, which round-trips through
 * Keycloak untouched and comes back on the `User` returned from
 * signinRedirectCallback() — that's how callback.astro knows where to send
 * the user after the exchange completes.
 */
export async function login(): Promise<void> {
  const manager = await getUserManager();
  if (!manager) {
    console.warn('[auth] login() called but OIDC is not configured — ignoring.');
    return;
  }
  const state: AuthState = { returnUrl: window.location.pathname + window.location.search };
  await manager.signinRedirect({ state });
}

/** Clears the local session and redirects to Keycloak's end-session endpoint. */
export async function logout(): Promise<void> {
  const manager = await getUserManager();
  if (!manager) {
    console.warn('[auth] logout() called but OIDC is not configured — ignoring.');
    return;
  }
  await manager.signoutRedirect();
}

/**
 * Forces a silent-renew attempt via the refresh_token grant, regardless of
 * whether the locally cached token looks expired yet. Used both by
 * getAccessToken() (for the ordinary expired-token case) and by api.ts on an
 * unexpected 401 (e.g. the broker rejected a token that looked unexpired
 * locally — clock skew, revocation). Returns the refreshed access token, or
 * null if renewal failed (no refresh token, revoked, network error, or OIDC
 * not configured).
 */
export async function renewAccessToken(): Promise<string | null> {
  const manager = await getUserManager();
  if (!manager) return null;
  try {
    const user = await manager.signinSilent();
    return user?.access_token ?? null;
  } catch {
    return null;
  }
}

/**
 * Returns the current access token, transparently renewing it if expired.
 * Returns null if there's no session to renew (never logged in, renewal
 * failed, or OIDC not configured).
 */
export async function getAccessToken(): Promise<string | null> {
  const manager = await getUserManager();
  if (!manager) return null;
  const user = await manager.getUser();
  if (!user) return null;
  if (!user.expired) return user.access_token;
  return renewAccessToken();
}

/**
 * Completes the Authorization Code exchange after Keycloak redirects back to
 * /callback. Returns the return path stashed by login(), defaulting to '/'
 * for a callback reached some other way (e.g. a stale bookmark).
 */
export async function handleCallback(): Promise<string> {
  const manager = await getUserManager();
  if (!manager) {
    throw new Error('OIDC is not configured');
  }
  const user = await manager.signinRedirectCallback();
  const state = user.state as AuthState | undefined;
  return state?.returnUrl || '/';
}
