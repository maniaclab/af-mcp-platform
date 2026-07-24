import { describe, expect, it } from 'vitest';
import { extractLinkedParam } from '../linkedBanner';

describe('extractLinkedParam', () => {
  it('returns null linkedId and empty remainingSearch when there is no query string', () => {
    expect(extractLinkedParam('')).toEqual({ linkedId: null, remainingSearch: '' });
  });

  it('returns null linkedId when linked is absent but other params exist', () => {
    expect(extractLinkedParam('?foo=bar')).toEqual({
      linkedId: null,
      remainingSearch: '?foo=bar',
    });
  });

  it('extracts linked and clears remainingSearch when it is the only param', () => {
    expect(extractLinkedParam('?linked=rucio-mcp-atlas')).toEqual({
      linkedId: 'rucio-mcp-atlas',
      remainingSearch: '',
    });
  });

  it('extracts linked and preserves other params in remainingSearch', () => {
    const result = extractLinkedParam('?foo=bar&linked=rucio-mcp-atlas&baz=qux');
    expect(result.linkedId).toBe('rucio-mcp-atlas');
    // Order of remaining params doesn't matter to callers — just that both survive.
    const remaining = new URLSearchParams(result.remainingSearch.replace(/^\?/, ''));
    expect(remaining.get('foo')).toBe('bar');
    expect(remaining.get('baz')).toBe('qux');
    expect(remaining.has('linked')).toBe(false);
  });
});
