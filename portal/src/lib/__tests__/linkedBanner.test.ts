import { describe, expect, it } from 'vitest';
import { extractLinkedErrorParams, extractLinkedParam } from '../linkedBanner';

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

describe('extractLinkedErrorParams', () => {
  it('returns null when there is no query string', () => {
    expect(extractLinkedErrorParams('')).toBeNull();
  });

  it('returns null when linked_error is absent but other params exist', () => {
    expect(extractLinkedErrorParams('?foo=bar')).toBeNull();
  });

  it('extracts code and alias, defaulting description to null, when only linked_error and linked_error_alias are present', () => {
    expect(
      extractLinkedErrorParams('?linked_error_alias=rucio-mcp-atlas&linked_error=server_error'),
    ).toEqual({
      alias: 'rucio-mcp-atlas',
      code: 'server_error',
      description: null,
      remainingSearch: '',
    });
  });

  it('extracts description when present', () => {
    const result = extractLinkedErrorParams(
      '?linked_error_alias=rucio-mcp-atlas&linked_error=server_error&linked_error_description=An+unexpected+error+occurred',
    );
    expect(result).toEqual({
      alias: 'rucio-mcp-atlas',
      code: 'server_error',
      description: 'An unexpected error occurred',
      remainingSearch: '',
    });
  });

  it('falls back to the error code as alias when linked_error_alias is absent', () => {
    const result = extractLinkedErrorParams('?linked_error=server_error');
    expect(result?.alias).toBe('server_error');
  });

  it('strips linked_error_uri from remainingSearch without surfacing it in the result', () => {
    const result = extractLinkedErrorParams(
      '?linked_error_alias=rucio-mcp-atlas&linked_error=server_error&linked_error_uri=https://backend-as.example/errors/server_error',
    );
    expect(result).toEqual({
      alias: 'rucio-mcp-atlas',
      code: 'server_error',
      description: null,
      remainingSearch: '',
    });
  });

  it('preserves other params in remainingSearch', () => {
    const result = extractLinkedErrorParams(
      '?foo=bar&linked_error_alias=rucio-mcp-atlas&linked_error=server_error&baz=qux',
    );
    const remaining = new URLSearchParams(result?.remainingSearch.replace(/^\?/, ''));
    expect(remaining.get('foo')).toBe('bar');
    expect(remaining.get('baz')).toBe('qux');
    expect(remaining.has('linked_error')).toBe(false);
    expect(remaining.has('linked_error_alias')).toBe(false);
  });
});
