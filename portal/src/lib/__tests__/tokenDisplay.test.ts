import { describe, expect, it } from 'vitest';
import {
  EXPIRY_WARNING_DAYS,
  NOTE_MAX_LENGTH,
  expiresIn,
  expiresSoon,
  soonestExpiringToken,
  permissionGrantLabel,
  shortLookupId,
  tokenStatus,
  truncateNote,
} from '../tokenDisplay';

describe('tokenStatus', () => {
  const NOW = Date.parse('2026-07-21T12:00:00Z');

  it('is "active" when not revoked and not expired', () => {
    const status = tokenStatus({ revoked_at: null, expires_at: '2026-07-21T13:00:00Z' }, NOW);
    expect(status).toBe('active');
  });

  it('is "revoked" when revoked_at is set, even if not yet expired', () => {
    const status = tokenStatus(
      { revoked_at: '2026-07-21T11:00:00Z', expires_at: '2026-07-21T13:00:00Z' },
      NOW,
    );
    expect(status).toBe('revoked');
  });

  it('is "expired" when past expires_at and never revoked', () => {
    const status = tokenStatus({ revoked_at: null, expires_at: '2026-07-21T11:00:00Z' }, NOW);
    expect(status).toBe('expired');
  });

  it('prefers "revoked" over "expired" when both are true', () => {
    const status = tokenStatus(
      { revoked_at: '2026-07-21T10:00:00Z', expires_at: '2026-07-21T11:00:00Z' },
      NOW,
    );
    expect(status).toBe('revoked');
  });

  it('treats expires_at exactly equal to now as expired', () => {
    const status = tokenStatus({ revoked_at: null, expires_at: '2026-07-21T12:00:00Z' }, NOW);
    expect(status).toBe('expired');
  });

  it('defaults `now` to Date.now() when not supplied', () => {
    const farFuture = new Date(Date.now() + 3600_000).toISOString();
    expect(tokenStatus({ revoked_at: null, expires_at: farFuture })).toBe('active');
  });

  it('is "active" (never expired) when expires_at is null', () => {
    const status = tokenStatus({ revoked_at: null, expires_at: null }, NOW);
    expect(status).toBe('active');
  });

  it('is "revoked" (not "active") when expires_at is null but revoked_at is set', () => {
    const status = tokenStatus({ revoked_at: '2026-07-21T11:00:00Z', expires_at: null }, NOW);
    expect(status).toBe('revoked');
  });
});

describe('shortLookupId', () => {
  it('truncates a long lookup_id to 8 chars plus an ellipsis', () => {
    expect(shortLookupId('abcdef1234567890')).toBe('abcdef12…');
  });

  it('returns a lookup_id of 8 chars or fewer unchanged', () => {
    expect(shortLookupId('abcd1234')).toBe('abcd1234');
    expect(shortLookupId('short')).toBe('short');
  });

  it('handles an empty string', () => {
    expect(shortLookupId('')).toBe('');
  });
});

describe('truncateNote', () => {
  it('returns null unchanged when there is no note', () => {
    expect(truncateNote(null)).toBeNull();
  });

  it('returns a short note unchanged', () => {
    expect(truncateNote('for the CI bot')).toBe('for the CI bot');
  });

  it('returns a note at exactly the default max length (NOTE_MAX_LENGTH) unchanged', () => {
    const note = 'x'.repeat(NOTE_MAX_LENGTH);
    expect(truncateNote(note)).toBe(note);
  });

  it('truncates a note longer than the default max length with an ellipsis', () => {
    const note = 'x'.repeat(NOTE_MAX_LENGTH + 10);
    const result = truncateNote(note);
    expect(result).toBe(`${'x'.repeat(NOTE_MAX_LENGTH)}…`);
  });

  it('accepts a custom max length', () => {
    expect(truncateNote('abcdefghij', 5)).toBe('abcde…');
  });
});

describe('permissionGrantLabel', () => {
  it('describes an identity PAT (null grant) as full account access', () => {
    expect(permissionGrantLabel(null)).toBe('Full account access');
  });

  it('describes a permission PAT scoped to one permission', () => {
    expect(permissionGrantLabel(['read_data'])).toBe('read_data');
  });

  it('sorts multiple permissions for a stable display order', () => {
    expect(permissionGrantLabel(['submit_jobs', 'read_data'])).toBe('read_data, submit_jobs');
  });

  it('describes an empty (but non-null) grant distinctly from an identity PAT', () => {
    expect(permissionGrantLabel([])).toBe('No permissions');
  });
});

describe('expiry warning', () => {
  const NOW = Date.parse('2026-07-21T12:00:00Z');
  const DAY = 24 * 3600 * 1000;
  const iso = (ms: number) => new Date(NOW + ms).toISOString();

  it('warns for an active token that expires within the window', () => {
    expect(expiresSoon({ revoked_at: null, expires_at: iso(EXPIRY_WARNING_DAYS * DAY) }, NOW)).toBe(
      true,
    );
  });

  it('stays quiet past the window, for no expiry, and for revoked or expired tokens', () => {
    expect(
      expiresSoon({ revoked_at: null, expires_at: iso(EXPIRY_WARNING_DAYS * DAY + 1) }, NOW),
    ).toBe(false);
    expect(expiresSoon({ revoked_at: null, expires_at: null }, NOW)).toBe(false);
    expect(expiresSoon({ revoked_at: iso(-DAY), expires_at: iso(DAY) }, NOW)).toBe(false);
    expect(expiresSoon({ revoked_at: null, expires_at: iso(-DAY) }, NOW)).toBe(false);
  });

  it('words the time left in hours up to a day and days after', () => {
    expect(expiresIn(iso(5 * 3600 * 1000), NOW)).toBe('in 5 hours');
    expect(expiresIn(iso(1000), NOW)).toBe('in 1 hour');
    expect(expiresIn(iso(3 * DAY - 1000), NOW)).toBe('in 3 days');
  });
});

describe('soonestExpiringToken', () => {
  const NOW = Date.parse('2026-07-21T12:00:00Z');
  const row = (name: string, expires_at: string | null, revoked_at: string | null = null) => ({
    name,
    expires_at,
    revoked_at,
  });

  it('picks the active token that expires first, with its name and expiry', () => {
    expect(
      soonestExpiringToken(
        [
          row('later', '2026-09-01T00:00:00Z'),
          row('sooner', '2026-08-01T00:00:00Z'),
          row('revoked', '2026-07-22T00:00:00Z', '2026-07-20T00:00:00Z'),
          row('expired', '2026-07-01T00:00:00Z'),
          row('never', null),
        ],
        NOW,
      ),
    ).toEqual({ name: 'sooner', expires_at: '2026-08-01T00:00:00Z' });
  });

  it('is null when no active token expires', () => {
    expect(soonestExpiringToken([row('never', null)], NOW)).toBeNull();
    expect(soonestExpiringToken([], NOW)).toBeNull();
  });
});
