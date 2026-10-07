import { describe, expect, it } from 'vitest';

import { formatRelative } from '../relativeTime';

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
