/**
 * markdown.ts — renders Markdown from backend MCP servers (tool and service
 * descriptions) to HTML that is safe to bind with `v-html`.
 *
 * Backend text is untrusted, so rendering is two layers deep: marked turns raw
 * HTML and images into plain text before they can become elements, then
 * DOMPurify allows only the formatting tags below and http(s)/mailto links.
 * The output carries no inline `style` or event-handler attributes, so it
 * needs nothing beyond the portal's hash-pinned CSP (no 'unsafe-inline').
 */
import DOMPurify from 'dompurify';
import { Marked, type Tokens } from 'marked';

const ALLOWED_TAGS = [
  'a',
  'blockquote',
  'br',
  'code',
  'del',
  'em',
  'h1',
  'h2',
  'h3',
  'h4',
  'h5',
  'h6',
  'hr',
  'li',
  'ol',
  'p',
  'pre',
  'strong',
  'table',
  'tbody',
  'td',
  'th',
  'thead',
  'tr',
  'ul',
];

/** No images (an external one is a tracking beacon), no data:/javascript: links. */
const ALLOWED_URI_REGEXP = /^(?:https?:|mailto:)/i;

function escapeHtml(text: string): string {
  return text
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

const marked = new Marked({
  gfm: true,
  renderer: {
    // Raw HTML in a description is shown as the text it is, never as markup.
    html: ({ text }: Tokens.HTML | Tokens.Tag) => escapeHtml(text),
    // The alt text survives; the image itself is never fetched.
    image: ({ text }: Tokens.Image) => escapeHtml(text),
  },
});

let hookRegistered = false;

/** Registered lazily because DOMPurify has no `addHook` without a DOM (server-side rendering). */
function registerLinkHook(): void {
  if (hookRegistered) return;
  hookRegistered = true;
  DOMPurify.addHook('afterSanitizeAttributes', (node) => {
    if (node.tagName === 'A' && node.hasAttribute('href')) {
      node.setAttribute('target', '_blank');
      node.setAttribute('rel', 'noopener noreferrer');
    }
  });
}

/**
 * Sanitized HTML for *source*. *inline* drops the wrapping paragraph, for text
 * that sits inside another element (an argument's description, a card line).
 *
 * Without a DOM (the Node pass that Astro renders islands in) DOMPurify cannot
 * sanitize, so the text is escaped instead of risking unsanitized output.
 */
export function renderMarkdown(source: string, { inline = false } = {}): string {
  if (source.trim() === '') return '';
  if (!DOMPurify.isSupported) return escapeHtml(source);
  registerLinkHook();
  const html = inline
    ? marked.parseInline(source, { async: false })
    : marked.parse(source, { async: false });
  return DOMPurify.sanitize(html, {
    ALLOWED_TAGS,
    ALLOWED_ATTR: ['href', 'title'],
    ALLOWED_URI_REGEXP,
  });
}
