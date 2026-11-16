/**
 * Tests for apiError.ts — the shared APIError-to-message plumbing behind every
 * `*ErrorMessage` mapper and every component catch block.
 */
import { describe, expect, it } from 'vitest';
import { APIError, SessionExpiredError } from '../api';
import { apiErrorDetail, describeApiError, errorMessage } from '../apiError';

describe('apiErrorDetail', () => {
  it('returns the detail unchanged when no request_id is present', () => {
    const err = new APIError(502, 'Bad Gateway', JSON.stringify({ detail: 'boom' }));
    expect(apiErrorDetail(err)).toBe('boom');
  });

  it('appends the request_id when present, so it can be quoted to support (af-mcp-platform#288)', () => {
    const err = new APIError(
      502,
      'Bad Gateway',
      JSON.stringify({ detail: 'boom', request_id: 'abc123def456' }),
    );
    expect(apiErrorDetail(err)).toBe('boom (reference: abc123def456)');
  });

  it('does not repeat a request_id the detail already quotes', () => {
    const err = new APIError(
      502,
      'Bad Gateway',
      JSON.stringify({ detail: 'boom [abc123def456]', request_id: 'abc123def456' }),
    );
    expect(apiErrorDetail(err)).toBe('boom [abc123def456]');
  });

  it('ignores a non-string request_id rather than rendering "undefined"', () => {
    const err = new APIError(
      502,
      'Bad Gateway',
      JSON.stringify({ detail: 'boom', request_id: 12345 }),
    );
    expect(apiErrorDetail(err)).toBe('boom');
  });

  it('returns null when detail is missing, regardless of request_id', () => {
    const err = new APIError(502, 'Bad Gateway', JSON.stringify({ request_id: 'abc123def456' }));
    expect(apiErrorDetail(err)).toBeNull();
  });

  it('returns null for a body that is not JSON', () => {
    expect(apiErrorDetail(new APIError(502, 'Bad Gateway', '<html>nope</html>'))).toBeNull();
  });
});

describe('errorMessage', () => {
  it("returns an Error's message", () => {
    expect(errorMessage(new Error('boom'), 'fallback')).toBe('boom');
  });

  it('returns the fallback for a non-Error throw', () => {
    expect(errorMessage('oops', 'fallback')).toBe('fallback');
  });

  it('returns the fallback for an Error with an empty message', () => {
    expect(errorMessage(new Error(''), 'fallback')).toBe('fallback');
  });
});

describe('describeApiError', () => {
  const messages = {
    sessionExpired: 'expired',
    byStatus: { 400: 'bad request', 502: 'upstream down' },
    fallback: 'generic failure',
  };

  it('maps SessionExpiredError to the sessionExpired wording', () => {
    expect(describeApiError(new SessionExpiredError(), messages)).toBe('expired');
  });

  it("prefers the broker's detail, with its request reference, over the status table", () => {
    const err = new APIError(
      502,
      'Bad Gateway',
      JSON.stringify({ detail: 'broker says', request_id: 'abc123' }),
    );
    expect(describeApiError(err, messages)).toBe('broker says (reference: abc123)');
  });

  it('uses the status table when the body has no detail', () => {
    expect(describeApiError(new APIError(400, 'Bad Request', 'x'), messages)).toBe('bad request');
  });

  it("falls through to the APIError's own message for an unlisted status", () => {
    const err = new APIError(418, 'Teapot', 'x');
    expect(describeApiError(err, messages)).toBe(err.message);
  });

  it('lets the caller word an unlisted status via unmapped', () => {
    const err = new APIError(500, 'Server Error', 'x');
    expect(
      describeApiError(err, { ...messages, unmapped: (e) => `Request failed (${e.status}).` }),
    ).toBe('Request failed (500).');
  });

  it("returns a plain Error's message", () => {
    expect(describeApiError(new Error('network down'), messages)).toBe('network down');
  });

  it('returns the fallback for a non-Error throw', () => {
    expect(describeApiError(null, messages)).toBe('generic failure');
  });
});
