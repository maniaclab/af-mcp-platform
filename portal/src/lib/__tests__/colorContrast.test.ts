import { describe, expect, it } from 'vitest';
import { contrastRatio, parseHexColor, relativeLuminance } from '../colorContrast';

describe('parseHexColor', () => {
  it('parses a 6-digit hex color', () => {
    expect(parseHexColor('#0a0e1a')).toEqual([10, 14, 26]);
  });

  it('parses and expands a 3-digit hex color', () => {
    expect(parseHexColor('#fff')).toEqual([255, 255, 255]);
  });

  it('throws for anything that is not a hex color', () => {
    expect(() => parseHexColor('rgb(0 0 0 / 0.5)')).toThrow();
  });
});

describe('relativeLuminance', () => {
  it('is 0 for black and 1 for white', () => {
    expect(relativeLuminance('#000000')).toBeCloseTo(0, 5);
    expect(relativeLuminance('#ffffff')).toBeCloseTo(1, 5);
  });
});

describe('contrastRatio', () => {
  it('is 21:1 for black on white', () => {
    expect(contrastRatio('#000000', '#ffffff')).toBeCloseTo(21, 1);
  });

  it('is 1:1 for a color against itself', () => {
    expect(contrastRatio('#046d66', '#046d66')).toBeCloseTo(1, 5);
  });

  it('is order-independent', () => {
    expect(contrastRatio('#0a0e1a', '#e9edf2')).toBeCloseTo(
      contrastRatio('#e9edf2', '#0a0e1a'),
      5,
    );
  });
});
