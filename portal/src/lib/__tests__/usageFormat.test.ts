import { describe, expect, it } from 'vitest';
import { formatShare } from '../usageFormat';

describe('formatShare', () => {
  it.each([
    [0, '0%'],
    [0.75, '75%'],
    [1, '100%'],
    [0.004, '<1%'],
    [0.012, '1%'],
  ])('formats %s as %s', (fraction, text) => {
    expect(formatShare(fraction)).toBe(text);
  });
});
