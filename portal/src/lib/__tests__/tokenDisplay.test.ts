import { describe, expect, it } from 'vitest';
import { shortLookupId, tokenStatus, truncateNote } from '../tokenDisplay';

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

  it('returns a note at exactly the max length unchanged', () => {
    const note = 'x'.repeat(80);
    expect(truncateNote(note)).toBe(note);
  });

  it('truncates a note longer than the max length with an ellipsis', () => {
    const note = 'x'.repeat(90);
    const result = truncateNote(note);
    expect(result).toBe(`${'x'.repeat(80)}…`);
  });

  it('accepts a custom max length', () => {
    expect(truncateNote('abcdefghij', 5)).toBe('abcde…');
  });
});
