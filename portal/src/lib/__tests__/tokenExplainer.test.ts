/**
 * Tests for tokenExplainer.ts: the one place the portal states how token
 * counts are estimated. The numbers must match the broker's constants
 * (audit/image_tokens.py); broker/tests/test_token_explainer_docs.py asserts
 * that against the source, this asserts the text carries them.
 */
import { describe, expect, it } from 'vitest';
import { TOKEN_DOCS_URL, TOKEN_ESTIMATE_RULES, TOKEN_ESTIMATE_SUMMARY } from '../tokenExplainer';

describe('tokenExplainer', () => {
  it('says the counts are estimates and names the text encoding', () => {
    expect(TOKEN_ESTIMATE_SUMMARY.toLowerCase()).toContain('estimate');
    expect(TOKEN_ESTIMATE_RULES.text).toContain('tiktoken');
    expect(TOKEN_ESTIMATE_RULES.text).toContain('o200k_base');
  });

  it('states the image rule with the assumed tier limits and the worked example', () => {
    expect(TOKEN_ESTIMATE_RULES.image).toContain('28x28');
    expect(TOKEN_ESTIMATE_RULES.image).toContain('2576');
    expect(TOKEN_ESTIMATE_RULES.image).toContain('4784');
    expect(TOKEN_ESTIMATE_RULES.image).toContain('640x480');
    expect(TOKEN_ESTIMATE_RULES.image).toContain('414');
  });

  it('says audio, binary blobs and resource links add no tokens, and when structured counts', () => {
    expect(TOKEN_ESTIMATE_RULES.other).toMatch(/audio/i);
    expect(TOKEN_ESTIMATE_RULES.other).toMatch(/no tokens/i);
    expect(TOKEN_ESTIMATE_RULES.structured).toMatch(/no text/i);
  });

  it('links to the docs section', () => {
    expect(TOKEN_DOCS_URL).toBe(
      'https://maniaclab.github.io/af-mcp-platform/observability/#how-token-counts-are-estimated',
    );
  });
});
