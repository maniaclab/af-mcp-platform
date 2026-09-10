/**
 * Tests for servicexIdentity.ts — the display/error logic behind the
 * Identities page's ServiceX card. Kept as plain functions (no DOM, no Vue)
 * following x509Identity.ts's/krb5Identity.ts's pattern, so the card's
 * states are unit testable without a component harness.
 */
import { describe, expect, it } from 'vitest';
import { APIError, SessionExpiredError } from '../api';
import { servicexLinkErrorMessage } from '../servicexIdentity';

describe('servicexLinkErrorMessage', () => {
  it('returns a fixed message for SessionExpiredError', () => {
    expect(servicexLinkErrorMessage(new SessionExpiredError())).toMatch(/session/i);
  });

  it('prefers the server detail when present on a 400', () => {
    const err = new APIError(
      400,
      'Bad Request',
      JSON.stringify({
        detail: 'servicex-token-service rejected the given refresh token.',
      }),
    );
    expect(servicexLinkErrorMessage(err)).toBe(
      'servicex-token-service rejected the given refresh token.',
    );
  });

  it('has a specific message for 400 (bad refresh token)', () => {
    const err = new APIError(400, 'Bad Request', 'not-json');
    expect(servicexLinkErrorMessage(err)).toMatch(/token/i);
  });

  it('has a specific message for 502 (service unavailable)', () => {
    const err = new APIError(502, 'Bad Gateway', 'not-json');
    expect(servicexLinkErrorMessage(err)).toMatch(/unavailable/i);
  });

  it('includes the correlation_id on a 502 so it can be quoted to support (af-mcp-platform#288)', () => {
    const err = new APIError(
      502,
      'Bad Gateway',
      JSON.stringify({
        detail: 'ServiceX token redemption is temporarily unavailable — retry later.',
        correlation_id: 'abc123def456',
      }),
    );
    expect(servicexLinkErrorMessage(err)).toContain('reference: abc123def456');
  });

  it('falls back to APIError.message for other statuses (matches x509LinkErrorMessage)', () => {
    const err = new APIError(500, 'Internal Server Error', 'not-json');
    expect(servicexLinkErrorMessage(err)).toBe(err.message);
  });

  it('uses .message for a plain Error', () => {
    expect(servicexLinkErrorMessage(new Error('boom'))).toBe('boom');
  });

  it('has a fixed fallback for a non-Error thrown value', () => {
    expect(servicexLinkErrorMessage('not-an-error')).toBe('Linking failed. Try again.');
  });
});
