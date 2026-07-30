import { describe, expect, it } from 'vitest';
import {
  extractLinkedErrorParams,
  extractLinkedParam,
  resolveLinkedBanner,
  resolveLinkedErrorBanner,
} from '../linkedBanner';

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

describe('resolveLinkedBanner', () => {
  const providers = [
    { id: 'rucio-mcp-atlas', display_name: 'Rucio (ATLAS)' },
    { id: 'atlas-oidc', display_name: 'ATLAS IAM' },
  ];

  it('returns null when linkedId is null', () => {
    expect(resolveLinkedBanner(providers, null)).toBeNull();
  });

  it('returns the display_name when linkedId matches a known provider', () => {
    expect(resolveLinkedBanner(providers, 'atlas-oidc')).toBe('ATLAS IAM');
  });

  it('returns null when linkedId does not match any known provider', () => {
    // A stale bookmark or someone poking at the URL — the OAuth callback
    // would only ever set a real id, so an unrecognized one isn't a
    // genuine success and shouldn't render a "Linked successfully" banner.
    expect(resolveLinkedBanner(providers, 'fake-provider-name-that-doesnt-exist')).toBeNull();
  });
});

describe('resolveLinkedErrorBanner', () => {
  const providers = [
    { id: 'rucio-mcp-atlas', display_name: 'Rucio (ATLAS)' },
    { id: 'atlas-oidc', display_name: 'ATLAS IAM' },
  ];

  it('returns null when linkedError is null', () => {
    expect(resolveLinkedErrorBanner(providers, null)).toBeNull();
  });

  it('returns null when the alias does not match any known provider', () => {
    expect(
      resolveLinkedErrorBanner(providers, {
        alias: 'fake-provider-name-that-doesnt-exist',
        code: 'server_error',
        description: null,
        remainingSearch: '',
      }),
    ).toBeNull();
  });

  it('builds message from display_name and description when alias matches', () => {
    expect(
      resolveLinkedErrorBanner(providers, {
        alias: 'atlas-oidc',
        code: 'server_error',
        description: 'An unexpected error occurred',
        remainingSearch: '',
      }),
    ).toBe('Linking ATLAS IAM failed: An unexpected error occurred');
  });

  it('falls back to the error code when description is null', () => {
    expect(
      resolveLinkedErrorBanner(providers, {
        alias: 'atlas-oidc',
        code: 'server_error',
        description: null,
        remainingSearch: '',
      }),
    ).toBe('Linking ATLAS IAM failed: server_error');
  });
});
