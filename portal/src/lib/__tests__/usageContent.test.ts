/**
 * Tests for usageContent.ts: turning GET /v1/usage's `by_content_type` into
 * display rows, including the "unattributed" remainder for calls recorded
 * without a breakdown (their totals are larger than the breakdown's sum).
 */
import { describe, expect, it } from 'vitest';
import { contentTypeLabel, contentTypeRows, UNATTRIBUTED } from '../usageContent';

const totals = (bytes: number, tokens: number) => ({
  calls: 1,
  errors: 0,
  duration_ms: 1,
  result_bytes: bytes,
  result_tokens_est: tokens,
});

describe('contentTypeLabel', () => {
  it.each([
    ['text', 'Text'],
    ['image', 'Images'],
    ['structured', 'Structured'],
    ['audio', 'Audio'],
    ['resource', 'Resources'],
    ['resource_link', 'Resource links'],
  ])('names %s as %s', (type, label) => {
    expect(contentTypeLabel(type)).toBe(label);
  });

  it('shows an unknown type under its own name', () => {
    expect(contentTypeLabel('hologram')).toBe('hologram');
  });
});

describe('contentTypeRows', () => {
  it('lists each type, largest token share first, with its share of the token total', () => {
    const rows = contentTypeRows(totals(1000, 1000), [
      { content_type: 'image', blocks: 1, bytes: 400, tokens_est: 250 },
      { content_type: 'text', blocks: 4, bytes: 600, tokens_est: 750 },
    ]);
    expect(rows.map((r) => r.contentType)).toEqual(['text', 'image']);
    expect(rows[0]).toMatchObject({
      label: 'Text',
      blocks: 4,
      bytes: 600,
      tokens: 750,
      share: 0.75,
    });
    expect(rows[1].share).toBe(0.25);
  });

  it('breaks token ties by bytes, then by name', () => {
    const rows = contentTypeRows(totals(30, 0), [
      { content_type: 'resource_link', blocks: 1, bytes: 10, tokens_est: 0 },
      { content_type: 'audio', blocks: 1, bytes: 20, tokens_est: 0 },
      { content_type: 'blob', blocks: 1, bytes: 10, tokens_est: 0 },
    ]);
    expect(rows.map((r) => r.contentType)).toEqual(['audio', 'blob', 'resource_link']);
  });

  it('adds an unattributed row when totals exceed the breakdown, never hiding the remainder', () => {
    const rows = contentTypeRows(totals(1000, 900), [
      { content_type: 'text', blocks: 4, bytes: 600, tokens_est: 700 },
    ]);
    const last = rows[rows.length - 1];
    expect(last).toMatchObject({
      contentType: UNATTRIBUTED,
      label: 'Unattributed',
      blocks: null,
      bytes: 400,
      tokens: 200,
    });
    expect(rows.reduce((s, r) => s + r.tokens, 0)).toBe(900);
    expect(rows.reduce((s, r) => s + r.bytes, 0)).toBe(1000);
  });

  it('shows everything as unattributed when no call has a breakdown', () => {
    const rows = contentTypeRows(totals(500, 100), []);
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ contentType: UNATTRIBUTED, bytes: 500, tokens: 100, share: 1 });
  });

  it('omits the unattributed row when the breakdown accounts for the totals', () => {
    const rows = contentTypeRows(totals(600, 700), [
      { content_type: 'text', blocks: 4, bytes: 600, tokens_est: 700 },
    ]);
    expect(rows.map((r) => r.contentType)).toEqual(['text']);
  });

  it('keeps an unattributed row for bytes alone, since a type like audio carries bytes but no tokens', () => {
    const rows = contentTypeRows(totals(1000, 700), [
      { content_type: 'text', blocks: 4, bytes: 600, tokens_est: 700 },
    ]);
    expect(rows[rows.length - 1]).toMatchObject({
      contentType: UNATTRIBUTED,
      bytes: 400,
      tokens: 0,
    });
  });

  it('returns no rows for an empty window', () => {
    expect(contentTypeRows(totals(0, 0), [])).toEqual([]);
  });

  it('has a zero share, not NaN, when no tokens were estimated', () => {
    const rows = contentTypeRows(totals(20, 0), [
      { content_type: 'audio', blocks: 1, bytes: 20, tokens_est: 0 },
    ]);
    expect(rows[0].share).toBe(0);
  });
});
