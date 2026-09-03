/**
 * krb5Identity.ts — display/error logic behind the Identities page's
 * Kerberos-ticket card. Kept as plain functions (no DOM access, no Vue)
 * following x509Identity.ts's pattern, so the card's states are unit
 * testable without a component harness. The card itself owns the
 * username/password form and the POST to /v1/krb5/ticket (via api.ts's
 * requestKrb5Ticket); this module only turns its outcomes into user-facing
 * strings.
 */
import { APIError, SessionExpiredError } from './api';
import { apiErrorDetail } from './x509Identity';

/**
 * User-facing message for a failed POST /v1/krb5/ticket link attempt.
 *
 * The endpoint's contract (see broker/src/af_mcp_broker/api/credentials.py's
 * create_krb5_ticket and credentials/krb5_service.py's Krb5Token*Error
 * classes): 400 is a bad CERN username/password, 403 is a revoked/expired
 * CERN account, 422 is a malformed username or ticket lifetime, 429 is the
 * service's own rate limit, 502 is a krb5-token-service infra failure. The
 * broker's own `detail` is preferred when present; the fallbacks keep each
 * status readable when it isn't.
 */
export function krb5LinkErrorMessage(err: unknown): string {
  if (err instanceof SessionExpiredError) {
    return 'Your session expired — reload the page and try again.';
  }
  if (err instanceof APIError) {
    const detail = apiErrorDetail(err);
    if (detail) return detail;
    if (err.status === 400) return 'Incorrect CERN username or password.';
    if (err.status === 403) {
      return 'This CERN account is revoked or its password has expired. Contact CERN account support.';
    }
    if (err.status === 422) return 'The given username or ticket lifetime was invalid.';
    if (err.status === 429) return 'Too many attempts — wait a moment and try again.';
    if (err.status === 502) {
      return 'The Kerberos ticket service is temporarily unavailable — retry later.';
    }
    return `Request failed (${err.status}).`;
  }
  if (err instanceof Error) return err.message;
  return 'Could not mint a Kerberos ticket.';
}
