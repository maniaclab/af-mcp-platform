import { describe, expect, it } from 'vitest';
import { shortJti, tokenStatus } from '../tokenDisplay';

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
});

describe('shortJti', () => {
  it('truncates a long jti to 8 chars plus an ellipsis', () => {
    expect(shortJti('abcdef1234567890')).toBe('abcdef12…');
  });

  it('returns a jti of 8 chars or fewer unchanged', () => {
    expect(shortJti('abcd1234')).toBe('abcd1234');
    expect(shortJti('short')).toBe('short');
  });

  it('handles an empty string', () => {
    expect(shortJti('')).toBe('');
  });
});
