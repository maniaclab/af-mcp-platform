import { describe, expect, it } from 'vitest';
import { formatShare, formatCount } from '../usageFormat';

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

describe('formatCount', () => {
  it.each([
    [0, '0'],
    [999, '999'],
    [12345, '12,345'],
    [1234567, '1,234,567'],
  ])('formats %s as %s', (n, text) => {
    expect(formatCount(n)).toBe(text);
  });
});
