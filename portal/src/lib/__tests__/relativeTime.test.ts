import { describe, expect, it } from 'vitest';

import { formatDateTime, formatRelative, formatRemaining } from '../relativeTime';

const NOW = Date.UTC(2026, 9, 2, 12, 0, 0);

describe('formatRelative', () => {
  it.each([
    [NOW - 30_000, '30 seconds ago'],
    [NOW - 5 * 60_000, '5 minutes ago'],
    [NOW - 3 * 3_600_000, '3 hours ago'],
    [NOW - 2 * 86_400_000, '2 days ago'],
    [NOW + 4 * 3_600_000, 'in 4 hours'],
  ])('formats %d relative to now as %s', (target, expected) => {
    expect(formatRelative(target, NOW)).toBe(expected);
  });
});

describe('formatDateTime', () => {
  const date = new Date(NOW);

  it('matches the short form without a year by default', () => {
    expect(formatDateTime(date)).toBe(
      date.toLocaleString('en-US', {
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        timeZoneName: 'short',
      }),
    );
    expect(formatDateTime(date)).not.toContain('2026');
  });

  it('includes the year when asked', () => {
    expect(formatDateTime(date, { year: true })).toBe(
      date.toLocaleString('en-US', {
        month: 'short',
        day: 'numeric',
        year: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        timeZoneName: 'short',
      }),
    );
    expect(formatDateTime(date, { year: true })).toContain('2026');
  });
});

describe('formatRemaining', () => {
  const at = (seconds: number) => new Date(NOW + seconds * 1000);

  it.each([
    [3 * 3600 + 25 * 60 + 59, '3h 25m remaining'],
    [3600, '1h 0m remaining'],
    [45 * 60, '45m remaining'],
    [30, '0m remaining'],
    [0, 'expired'],
    [-60, 'expired'],
  ])('formats %d seconds ahead as %s', (seconds, expected) => {
    expect(formatRemaining(at(seconds), new Date(NOW))).toBe(expected);
  });

  it('defaults now to the current time', () => {
    expect(formatRemaining(new Date(Date.now() + 2 * 3600 * 1000 + 30_000))).toBe(
      '2h 0m remaining',
    );
  });
});
