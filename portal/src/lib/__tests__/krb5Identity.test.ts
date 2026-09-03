/**
 * Tests for krb5Identity.ts — the display/error logic behind the Identities
 * page's Kerberos-ticket card. Kept as plain functions (no DOM, no Vue)
 * following x509Identity.ts's pattern, so the card's states are unit
 * testable without a component harness.
 */
import { describe, expect, it } from 'vitest';
import { APIError, SessionExpiredError } from '../api';
import { krb5LinkErrorMessage } from '../krb5Identity';

describe('krb5LinkErrorMessage', () => {
  it('returns a fixed message for SessionExpiredError', () => {
    expect(krb5LinkErrorMessage(new SessionExpiredError())).toMatch(/session/i);
  });

  it('prefers the server detail when present on a 400', () => {
    const err = new APIError(
      400,
      'Bad Request',
      JSON.stringify({
        detail: 'krb5-token-service rejected the given CERN username/password.',
      }),
    );
    expect(krb5LinkErrorMessage(err)).toBe(
      'krb5-token-service rejected the given CERN username/password.',
    );
  });

  it('has a specific message for 400 (bad username/password)', () => {
    const err = new APIError(400, 'Bad Request', 'not-json');
    expect(krb5LinkErrorMessage(err)).toMatch(/username|password/i);
  });

  it('has a specific message for 403 (account revoked/expired)', () => {
    const err = new APIError(403, 'Forbidden', 'not-json');
    expect(krb5LinkErrorMessage(err)).toMatch(/revoked|expired/i);
  });

  it('has a specific message for 422 (malformed input)', () => {
    const err = new APIError(422, 'Unprocessable Content', 'not-json');
    expect(krb5LinkErrorMessage(err)).toMatch(/invalid/i);
  });

  it('has a specific message for 429 (rate-limited)', () => {
    const err = new APIError(429, 'Too Many Requests', 'not-json');
    expect(krb5LinkErrorMessage(err)).toMatch(/too many/i);
  });

  it('has a specific message for 502 (service unavailable)', () => {
    const err = new APIError(502, 'Bad Gateway', 'not-json');
    expect(krb5LinkErrorMessage(err)).toMatch(/unavailable/i);
  });

  it('falls back to a generic message for other APIError statuses', () => {
    const err = new APIError(500, 'Internal Server Error', 'not-json');
    expect(krb5LinkErrorMessage(err)).toBe('Request failed (500).');
  });

  it('uses .message for a plain Error', () => {
    expect(krb5LinkErrorMessage(new Error('boom'))).toBe('boom');
  });

  it('has a fixed fallback for a non-Error thrown value', () => {
    expect(krb5LinkErrorMessage('not-an-error')).toMatch(/kerberos ticket/i);
  });
});
