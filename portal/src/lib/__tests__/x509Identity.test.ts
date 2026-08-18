/**
 * Tests for x509Identity.ts — the display/error logic behind the Identities
 * page's x509 card (X509IdentityCard.vue). Kept as plain functions (no DOM,
 * no Vue) following linkedBanner.ts's pattern, so the card's states are unit
 * testable without a component harness.
 */
import { describe, expect, it } from 'vitest';
import { APIError, SessionExpiredError } from '../api';
import { formatProxyExpiry, x509LinkErrorMessage } from '../x509Identity';

describe('x509LinkErrorMessage', () => {
  it('surfaces the broker detail on a 400 bad passphrase', () => {
    const err = new APIError(
      400,
      'Bad Request',
      JSON.stringify({
        detail:
          'voms-token-service rejected the Globus key passphrase — check ' +
          'the passphrase and certificate validity.',
      }),
    );
    expect(x509LinkErrorMessage(err)).toContain('passphrase');
    expect(x509LinkErrorMessage(err)).not.toContain('400 Bad Request');
  });

  it('falls back to a friendly bad-passphrase message when 400 has no detail', () => {
    const err = new APIError(400, 'Bad Request', 'not-json');
    expect(x509LinkErrorMessage(err)).toMatch(/passphrase/i);
  });

  it('surfaces the broker detail on a 429 rate limit', () => {
    const err = new APIError(
      429,
      'Too Many Requests',
      JSON.stringify({
        detail: 'Too many failed unlock attempts. Try again in 300 seconds.',
        retry_after_seconds: 300,
      }),
    );
    expect(x509LinkErrorMessage(err)).toContain('Too many failed unlock attempts');
  });

  it('falls back to a friendly rate-limit message when 429 has no detail', () => {
    const err = new APIError(429, 'Too Many Requests', '');
    expect(x509LinkErrorMessage(err)).toMatch(/too many/i);
  });

  it('maps a 502 service outage to a retry-later message', () => {
    const err = new APIError(
      502,
      'Bad Gateway',
      JSON.stringify({ detail: 'Proxy minting is temporarily unavailable — retry later.' }),
    );
    expect(x509LinkErrorMessage(err)).toContain('temporarily unavailable');
  });

  it('lets SessionExpiredError read as a session problem, not a passphrase one', () => {
    expect(x509LinkErrorMessage(new SessionExpiredError())).toMatch(/session/i);
  });

  it('falls back to a generic message for anything else', () => {
    expect(x509LinkErrorMessage(new Error('boom'))).toBe('boom');
    expect(x509LinkErrorMessage('not-an-error')).toMatch(/failed/i);
  });
});

describe('formatProxyExpiry', () => {
  it('returns null when there is no expiry', () => {
    expect(formatProxyExpiry(null)).toBeNull();
    expect(formatProxyExpiry(undefined)).toBeNull();
  });

  it('formats an ISO timestamp as a short human date', () => {
    const formatted = formatProxyExpiry('2026-08-18T21:30:00+00:00');
    expect(formatted).toBeTruthy();
    expect(formatted).toContain('Aug');
    expect(formatted).toContain('18');
  });

  it('returns null for an unparseable timestamp rather than "Invalid Date"', () => {
    expect(formatProxyExpiry('not-a-date')).toBeNull();
  });
});
