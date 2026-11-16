/**
 * tokenExplainer.ts — the portal's statement of how token counts are
 * estimated. The rules and numbers mirror the broker's measurement
 * (broker/src/af_mcp_broker/audit/measure.py, image_tokens.py) and the docs
 * section TOKEN_DOCS_URL points at; broker/tests/unit/test_token_explainer_docs.py
 * fails when any of them drift apart.
 */

export const TOKEN_DOCS_URL =
  'https://maniaclab.github.io/af-mcp-platform/observability/#how-token-counts-are-estimated';

export const TOKEN_ESTIMATE_SUMMARY =
  'Token counts are estimates of what tool results add to your assistant’s context, not provider-reported usage.';

export const TOKEN_ESTIMATE_RULES = {
  text: 'Text is counted with tiktoken (o200k_base encoding).',
  image:
    'Images are counted as Claude vision does: one token per 28x28 px patch after downscaling to the high-resolution limits (2576 px long edge, at most 4784 tokens per image). A 640x480 image is about 414 tokens.',
  other: 'Audio, binary blobs and resource links add bytes but no tokens.',
  structured: 'Structured content is counted only when the result has no text block.',
} as const;
