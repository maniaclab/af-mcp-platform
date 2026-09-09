/**
 * Tests for krb5Identity.ts — the display/error logic behind the Identities
 * page's Kerberos-ticket card. Kept as plain functions (no DOM, no Vue)
 * following x509Identity.ts's pattern, so the card's states are unit
 * testable without a component harness.
 */
import { describe, expect, it } from 'vitest';
import { APIError, SessionExpiredError } from '../api';
import { describeKrb5Source, krb5LinkErrorMessage } from '../krb5Identity';

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

  it('includes the correlation_id on a 502 so it can be quoted to support (af-mcp-platform#288)', () => {
    const err = new APIError(
      502,
      'Bad Gateway',
      JSON.stringify({
        detail: 'Kerberos ticket renewal is temporarily unavailable — retry later.',
        correlation_id: 'abc123def456',
      }),
    );
    expect(krb5LinkErrorMessage(err)).toContain('reference: abc123def456');
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

describe('describeKrb5Source', () => {
  it('says nothing needed to happen for a cache hit', () => {
    expect(describeKrb5Source('cache')).toMatch(/already.*valid/i);
  });

  it('says nothing needed to happen for a vault hit', () => {
    expect(describeKrb5Source('vault')).toMatch(/already.*valid/i);
  });

  it('says it renewed hands-free for tier 3', () => {
    expect(describeKrb5Source('renew')).toMatch(/renewed/i);
  });

  it('says it reminted from the linked keytab for tier 4', () => {
    expect(describeKrb5Source('keytab_remint')).toMatch(/keytab/i);
  });

  it('says it minted with the given password for tier 5', () => {
    expect(describeKrb5Source('password_mint')).toMatch(/password/i);
  });

  it('says the keytab was validated and linked', () => {
    expect(describeKrb5Source('keytab_link')).toMatch(/linked/i);
  });

  it('returns an empty string for null (a ticket minted before this field existed)', () => {
    expect(describeKrb5Source(null)).toBe('');
  });

  it('returns an empty string for an unrecognized tier rather than throwing', () => {
    expect(describeKrb5Source('some_future_tier')).toBe('');
  });
});
