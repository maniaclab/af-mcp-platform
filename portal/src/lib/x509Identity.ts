/**
 * x509Identity.ts — display/error logic behind the Identities page's x509
 * card (X509IdentityCard.vue).
 *
 * Kept as plain functions (no DOM access, no Vue) following linkedBanner.ts's
 * pattern, so the card's states are unit testable without a component
 * harness. The card itself owns the passphrase form and the POST to
 * /v1/x509/proxy (via api.ts's requestProxy); this module only turns its
 * outcomes into user-facing strings.
 */
import { APIError, SessionExpiredError } from './api';

/**
 * Extracts FastAPI's `{"detail": "..."}` from an APIError body, or null when
 * the body isn't that shape (e.g. an HTML error page from a proxy hop).
 *
 * Generic APIError-detail parsing with nothing x509-specific in it — exported
 * so krb5Identity.ts's krb5LinkErrorMessage can reuse it rather than
 * duplicating it.
 */
export function apiErrorDetail(err: APIError): string | null {
  try {
    const parsed = JSON.parse(err.body) as { detail?: unknown };
    return typeof parsed.detail === 'string' ? parsed.detail : null;
  } catch {
    return null;
  }
}

/**
 * User-facing message for a failed POST /v1/x509/proxy link attempt.
 *
 * The endpoint's contract (see broker/src/af_mcp_broker/api/credentials.py's
 * create_proxy and app.py's RateLimitError handler): 400 is a bad passphrase
 * (the user's to fix — and it burns the unlock rate-limit budget), 429 is
 * that budget exhausted, 502 is a voms-token-service infra failure that must
 * NOT read as "wrong passphrase". The broker's own `detail` is preferred
 * when present; the fallbacks keep each status readable when it isn't.
 */
export function x509LinkErrorMessage(err: unknown): string {
  if (err instanceof SessionExpiredError) {
    return 'Session expired — reload the page to re-authenticate.';
  }
  if (err instanceof APIError) {
    const detail = apiErrorDetail(err);
    if (detail) return detail;
    if (err.status === 400) {
      return 'Passphrase rejected — check your grid certificate passphrase and try again.';
    }
    if (err.status === 429) {
      return 'Too many failed attempts — wait a few minutes and try again.';
    }
    if (err.status === 502) {
      return 'Proxy minting is temporarily unavailable — try again later.';
    }
  }
  if (err instanceof Error && err.message) return err.message;
  return 'Linking failed. Try again.';
}

/**
 * Short human form of the x509 entry's `proxy_expires_at` (ISO-8601), e.g.
 * "Aug 18, 09:30 PM GMT" — or null when absent/unparseable so the card can
 * simply omit the expiry line instead of rendering "Invalid Date".
 */
export function formatProxyExpiry(iso: string | null | undefined): string | null {
  if (!iso) return null;
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return null;
  return date.toLocaleString('en-US', {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    timeZoneName: 'short',
  });
}

/**
 * One-line custody description for a linked x509 entry, from the identities
 * response's `x509_link_mode` (+ `proxy_expires_at`): "auto-renew" links
 * renew hands-free from the vault-stored passphrase; "until-expiry" links
 * (the user declined passphrase custody) last exactly as long as the proxy.
 * Null when there is no mode — unlinked, a legacy entry, or a non-x509 row —
 * so the card simply omits the line.
 */
export function x509LinkModeLabel(
  mode: 'auto-renew' | 'until-expiry' | null | undefined,
  proxyExpiresAt: string | null | undefined,
): string | null {
  if (mode === 'auto-renew') {
    return 'Auto-renews — passphrase stored encrypted in the AF vault';
  }
  if (mode === 'until-expiry') {
    const expiry = formatProxyExpiry(proxyExpiresAt);
    return expiry
      ? `Valid until ${expiry} — re-link after expiry`
      : 'Valid until proxy expiry — re-link after expiry';
  }
  return null;
}

/** Friendly names for voms-token-service's known preflight check ids; an
 * unknown id passes through so new service-side checks still render. */
const PREFLIGHT_CHECK_LABELS: Record<string, string> = {
  globus_dir: '.globus directory',
  usercert: 'Certificate (usercert.pem)',
  userkey: 'Private key (userkey.pem)',
};

export function preflightCheckLabel(name: string): string {
  return PREFLIGHT_CHECK_LABELS[name] ?? name;
}

/**
 * User-facing message for a failed GET /v1/x509/preflight fetch.
 *
 * The endpoint's contract (broker api/credentials.py::x509_preflight): 501 —
 * the facility's x509 entry mints via the legacy path, so there is no
 * voms-token-service to ask (a permanent state, not a retryable one); 502 —
 * the service is unreachable right now. The broker's own `detail` is
 * preferred when present.
 */
export function x509PreflightErrorMessage(err: unknown): string {
  if (err instanceof SessionExpiredError) {
    return 'Session expired — reload the page to re-authenticate.';
  }
  if (err instanceof APIError) {
    const detail = apiErrorDetail(err);
    if (detail) return detail;
    if (err.status === 501) {
      return 'The certificate checklist is not available on this facility.';
    }
    if (err.status === 502) {
      return 'The certificate checklist is temporarily unavailable — try again later.';
    }
  }
  if (err instanceof Error && err.message) return err.message;
  return 'Could not load the certificate checklist. Try again.';
}
