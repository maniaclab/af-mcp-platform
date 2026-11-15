// @vitest-environment node
import { describe, expect, it } from 'vitest';
import { renderMarkdown } from '../markdown';

// Astro renders every `client:load` island in plain Node, where DOMPurify has
// no DOM and cannot sanitize. The renderer must fall back to escaped text
// there rather than return unsanitized HTML.
describe('renderMarkdown without a DOM', () => {
  it('escapes the source instead of returning unsanitized HTML', () => {
    expect(renderMarkdown('<img src=x onerror=alert(1)> **bold**')).toBe(
      '&lt;img src=x onerror=alert(1)&gt; **bold**',
    );
  });

  it('escapes inline input the same way', () => {
    expect(renderMarkdown('<script>x</script>', { inline: true })).toBe(
      '&lt;script&gt;x&lt;/script&gt;',
    );
  });
});
