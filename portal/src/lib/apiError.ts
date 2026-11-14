/**
 * apiError.ts — the shared plumbing that turns a thrown API failure into a
 * user-facing string. Every `*ErrorMessage` mapper (x509Identity.ts,
 * krb5Identity.ts, servicexIdentity.ts, credmonStatus.ts, maintenanceBanner.ts)
 * and every component catch block builds on these three helpers, so a change
 * to how errors read (the support reference, say) lands everywhere at once.
 */
import { APIError, SessionExpiredError } from './api';

/**
 * Extracts FastAPI's `{"detail": "..."}` from an APIError body, or null when
 * the body isn't that shape (e.g. an HTML error page from a proxy hop).
 *
 * af-mcp-platform#288: a 5xx response also carries a `correlation_id`
 * alongside `detail` (app.py's `_http_exception_handler`) — appended here so
 * every caller of this function gets it for free, as something a user can
 * quote back to AF support, rather than every per-status branch needing its
 * own copy of this formatting. A detail that already quotes the id (the
 * ServiceX link rejection, #342) is returned as-is rather than repeating it.
 */
export function apiErrorDetail(err: APIError): string | null {
  try {
    const parsed = JSON.parse(err.body) as { detail?: unknown; correlation_id?: unknown };
    if (typeof parsed.detail !== 'string') return null;
    if (
      typeof parsed.correlation_id === 'string' &&
      !parsed.detail.includes(parsed.correlation_id)
    ) {
      return `${parsed.detail} (reference: ${parsed.correlation_id})`;
    }
    return parsed.detail;
  } catch {
    return null;
  }
}

/** An Error's message, or `fallback` for a non-Error throw or an empty message. */
export function errorMessage(err: unknown, fallback: string): string {
  return err instanceof Error && err.message ? err.message : fallback;
}

export interface ApiErrorMessages {
  /** Wording for a SessionExpiredError. */
  sessionExpired: string;
  /** Canned wording per HTTP status, used when the body carries no broker `detail`. */
  byStatus?: Record<number, string>;
  /** Wording for an APIError with no `detail` and no `byStatus` entry; defaults to the error's own message. */
  unmapped?: (err: APIError) => string;
  /** Wording for anything else that was thrown and has no message of its own. */
  fallback: string;
}

/**
 * The skeleton shared by every endpoint's error mapper: a session-expiry
 * sentence, then the broker's own `detail` (it is already the exact message
 * the user needs), then the endpoint's per-status wording, then the error's
 * message, then a canned fallback. Each caller supplies only its wording.
 */
export function describeApiError(err: unknown, messages: ApiErrorMessages): string {
  if (err instanceof SessionExpiredError) return messages.sessionExpired;
  if (err instanceof APIError) {
    const detail = apiErrorDetail(err);
    if (detail) return detail;
    const canned = messages.byStatus?.[err.status];
    if (canned) return canned;
    if (messages.unmapped) return messages.unmapped(err);
  }
  return errorMessage(err, messages.fallback);
}
