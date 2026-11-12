/**
 * Tests for x509Identity.ts — the display/error logic behind the Identities
 * page's x509 card (X509IdentityCard.vue). Kept as plain functions (no DOM,
 * no Vue) following linkedBanner.ts's pattern, so the card's states are unit
 * testable without a component harness.
 */
import { describe, expect, it } from 'vitest';
import { APIError, SessionExpiredError } from '../api';
import {
  apiErrorDetail,
  formatProxyExpiry,
  PROXY_EXPIRY_WARNING_SECONDS,
  preflightCheckLabel,
  preflightModeMismatch,
  preflightRequiredModeLabel,
  proxyExpiryState,
  x509LinkErrorMessage,
  x509LinkModeLabel,
  x509PreflightErrorMessage,
} from '../x509Identity';

describe('apiErrorDetail', () => {
  it('returns the detail unchanged when no correlation_id is present', () => {
    const err = new APIError(502, 'Bad Gateway', JSON.stringify({ detail: 'boom' }));
    expect(apiErrorDetail(err)).toBe('boom');
  });

  it('appends the correlation_id when present, so it can be quoted to support (af-mcp-platform#288)', () => {
    const err = new APIError(
      502,
      'Bad Gateway',
      JSON.stringify({ detail: 'boom', correlation_id: 'abc123def456' }),
    );
    expect(apiErrorDetail(err)).toBe('boom (reference: abc123def456)');
  });

  it('ignores a non-string correlation_id rather than rendering "undefined"', () => {
    const err = new APIError(
      502,
      'Bad Gateway',
      JSON.stringify({ detail: 'boom', correlation_id: 12345 }),
    );
    expect(apiErrorDetail(err)).toBe('boom');
  });

  it('returns null when detail is missing, regardless of correlation_id', () => {
    const err = new APIError(
      502,
      'Bad Gateway',
      JSON.stringify({ correlation_id: 'abc123def456' }),
    );
    expect(apiErrorDetail(err)).toBeNull();
  });
});

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

  it('includes the correlation_id on a 502 so it can be quoted to support (af-mcp-platform#288)', () => {
    const err = new APIError(
      502,
      'Bad Gateway',
      JSON.stringify({
        detail: 'Proxy minting is temporarily unavailable — retry later.',
        correlation_id: 'abc123def456',
      }),
    );
    expect(x509LinkErrorMessage(err)).toContain('reference: abc123def456');
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

describe('x509LinkModeLabel', () => {
  it('describes auto-renew custody', () => {
    const label = x509LinkModeLabel('auto-renew', null);
    expect(label).toMatch(/auto-renew/i);
    expect(label).toMatch(/vault/i);
  });

  it('describes until-expiry custody with the formatted expiry', () => {
    const label = x509LinkModeLabel('until-expiry', '2026-08-18T21:30:00+00:00');
    expect(label).toMatch(/valid until/i);
    expect(label).toContain('Aug');
    expect(label).toMatch(/re-link/i);
  });

  it('still describes until-expiry when the expiry is absent or unparseable', () => {
    for (const expiry of [null, undefined, 'not-a-date']) {
      const label = x509LinkModeLabel('until-expiry', expiry);
      expect(label).toMatch(/valid until/i);
      expect(label).not.toContain('Invalid Date');
    }
  });

  it('returns null when there is no mode (unlinked, legacy, non-x509)', () => {
    expect(x509LinkModeLabel(null, null)).toBeNull();
    expect(x509LinkModeLabel(undefined, '2026-08-18T21:30:00+00:00')).toBeNull();
  });
});

describe('preflightCheckLabel', () => {
  it('maps the known check names to friendly labels', () => {
    expect(preflightCheckLabel('globus_dir')).toBe('.globus directory');
    expect(preflightCheckLabel('usercert')).toBe('Certificate (usercert.pem)');
    expect(preflightCheckLabel('userkey')).toBe('Private key (userkey.pem)');
  });

  it('passes unknown names through so new service checks still render', () => {
    expect(preflightCheckLabel('crl_freshness')).toBe('crl_freshness');
  });
});

describe('preflightRequiredModeLabel', () => {
  it('lists the service-reported modes', () => {
    expect(
      preflightRequiredModeLabel({
        name: 'userkey',
        path: '/home/a/.globus/userkey.pem',
        exists: true,
        ok: true,
        required_modes: ['0400', '0600'],
      }),
    ).toBe('0400 or 0600');
  });

  it('says "Any" when the service sets no requirement', () => {
    expect(
      preflightRequiredModeLabel({
        name: 'usercert',
        path: '/home/a/.globus/usercert.pem',
        exists: true,
        ok: true,
        mode: '0644',
      }),
    ).toBe('Any');
  });
});

describe('preflightModeMismatch', () => {
  const key = {
    name: 'userkey',
    path: '/home/a/.globus/userkey.pem',
    exists: true,
    ok: false,
    required_modes: ['0400', '0600'],
  };

  it('is true when the found mode is outside the required set', () => {
    expect(preflightModeMismatch({ ...key, mode: '0644' })).toBe(true);
  });

  it('is false when the found mode is allowed', () => {
    expect(preflightModeMismatch({ ...key, mode: '0600' })).toBe(false);
  });

  it('is false when there is no found mode or no requirement', () => {
    expect(preflightModeMismatch({ ...key, exists: false })).toBe(false);
    expect(preflightModeMismatch({ ...key, mode: '0644', required_modes: null })).toBe(false);
  });
});

describe('x509PreflightErrorMessage', () => {
  it('lets SessionExpiredError read as a session problem', () => {
    expect(x509PreflightErrorMessage(new SessionExpiredError())).toMatch(/session/i);
  });

  it('maps 501 (legacy entry) to a not-available-here message', () => {
    const err = new APIError(501, 'Not Implemented', '');
    expect(x509PreflightErrorMessage(err)).toMatch(/not available/i);
  });

  it('maps 502 to a retry-later message', () => {
    const err = new APIError(502, 'Bad Gateway', '');
    expect(x509PreflightErrorMessage(err)).toMatch(/temporarily unavailable/i);
  });

  it('prefers the broker detail when present', () => {
    const err = new APIError(
      501,
      'Not Implemented',
      JSON.stringify({ detail: 'The x509 entry mints via the legacy path.' }),
    );
    expect(x509PreflightErrorMessage(err)).toContain('legacy path');
  });

  it('falls back to a generic message for anything else', () => {
    expect(x509PreflightErrorMessage('nope')).toMatch(/could not/i);
  });
});

describe('proxyExpiryState', () => {
  const HOUR = 3600;

  it('warns at one hour', () => {
    expect(PROXY_EXPIRY_WARNING_SECONDS).toBe(HOUR);
  });

  it('is "expiring" for a proxy that cannot renew itself with under an hour left', () => {
    expect(proxyExpiryState(HOUR - 1, false)).toBe('expiring');
    expect(proxyExpiryState(1, false)).toBe('expiring');
  });

  it('is "ok" at exactly an hour and beyond', () => {
    expect(proxyExpiryState(HOUR, false)).toBe('ok');
    expect(proxyExpiryState(2 * HOUR, false)).toBe('ok');
  });

  it('never warns about an auto-renewing proxy that is still valid', () => {
    expect(proxyExpiryState(60, true)).toBe('ok');
  });

  it('is "expired" at zero or below, even when auto-renewing, since renewal has failed', () => {
    expect(proxyExpiryState(0, false)).toBe('expired');
    expect(proxyExpiryState(-5, true)).toBe('expired');
  });
});
