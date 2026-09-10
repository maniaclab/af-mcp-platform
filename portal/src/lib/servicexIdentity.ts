/**
 * servicexIdentity.ts — display/error logic behind the Identities page's
 * servicex-token card (ServiceXIdentityCard.vue).
 *
 * Kept as plain functions (no DOM access, no Vue), following
 * x509Identity.ts's/krb5Identity.ts's pattern, so the card's states are
 * unit testable without a component harness. The card itself owns the
 * refresh-token paste form and the POST to /v1/servicex/link (via api.ts's
 * linkServiceXToken); this module only turns its outcomes into user-facing
 * strings.
 */
import { apiErrorDetail } from './x509Identity';
import { APIError, SessionExpiredError } from './api';

/**
 * User-facing message for a failed POST /v1/servicex/link attempt.
 *
 * The endpoint's contract (broker/src/af_mcp_broker/api/credentials.py's
 * link_servicex): 400 is a refresh token servicex-token-service rejected
 * (the user's to fix — paste a fresh one), 502 is a servicex-token-service
 * infra failure that must NOT read as "bad token". The broker's own
 * `detail` is preferred when present; the fallbacks keep each status
 * readable when it isn't.
 */
export function servicexLinkErrorMessage(err: unknown): string {
  if (err instanceof SessionExpiredError) {
    return 'Session expired — reload the page to re-authenticate.';
  }
  if (err instanceof APIError) {
    const detail = apiErrorDetail(err);
    if (detail) return detail;
    if (err.status === 400) {
      return 'Token rejected — check your ServiceX personal token and try again.';
    }
    if (err.status === 502) {
      return 'ServiceX token redemption is temporarily unavailable — try again later.';
    }
  }
  if (err instanceof Error && err.message) return err.message;
  return 'Linking failed. Try again.';
}
