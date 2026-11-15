/**
 * Tests for markdown.ts — descriptions come from backend MCP servers, so the
 * rendered HTML is untrusted input that ends up in `v-html`.
 */
import { describe, expect, it } from 'vitest';
import { renderMarkdown } from '../markdown';

/** Parses rendered HTML so assertions inspect elements, not substrings. */
function parse(html: string): HTMLElement {
  const root = document.createElement('div');
  root.innerHTML = html;
  return root;
}

describe('renderMarkdown formatting', () => {
  it('renders emphasis, code and lists', () => {
    const root = parse(renderMarkdown('Use **bold**, *italic* and `code`.\n\n- one\n- two'));
    expect(root.querySelector('strong')?.textContent).toBe('bold');
    expect(root.querySelector('em')?.textContent).toBe('italic');
    expect(root.querySelector('code')?.textContent).toBe('code');
    expect([...root.querySelectorAll('li')].map((li) => li.textContent)).toEqual(['one', 'two']);
  });

  it('renders fenced code blocks', () => {
    const root = parse(renderMarkdown('```\nrucio list-dids\n```'));
    expect(root.querySelector('pre > code')?.textContent).toBe('rucio list-dids\n');
  });

  it('renders a paragraph as a block and inline mode without the wrapping paragraph', () => {
    expect(parse(renderMarkdown('hello')).querySelector('p')?.textContent).toBe('hello');
    const inline = parse(renderMarkdown('hello `x`', { inline: true }));
    expect(inline.querySelector('p')).toBeNull();
    expect(inline.querySelector('code')?.textContent).toBe('x');
  });

  it('returns an empty string for empty input', () => {
    expect(renderMarkdown('')).toBe('');
  });
});

describe('renderMarkdown links', () => {
  it('opens http(s) links in a new tab without leaking the opener', () => {
    const a = parse(renderMarkdown('[docs](https://example.org/x)')).querySelector('a');
    expect(a?.getAttribute('href')).toBe('https://example.org/x');
    expect(a?.getAttribute('target')).toBe('_blank');
    expect(a?.getAttribute('rel')).toBe('noopener noreferrer');
  });

  it('keeps mailto links', () => {
    const a = parse(renderMarkdown('[mail](mailto:a@example.org)')).querySelector('a');
    expect(a?.getAttribute('href')).toBe('mailto:a@example.org');
  });

  it.each([
    'javascript:alert(1)',
    'JaVaScRiPt:alert(1)',
    'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
    'vbscript:msgbox(1)',
  ])('drops the href of a %s link', (href) => {
    const a = parse(renderMarkdown(`[click](${href})`)).querySelector('a');
    expect(a?.getAttribute('href') ?? null).toBeNull();
  });
});

describe('renderMarkdown sanitization', () => {
  const payloads: [string, string][] = [
    ['script tag', 'before <script>window.pwned = 1</script> after'],
    ['inline event handler', '<img src=x onerror="window.pwned = 1">'],
    ['iframe', '<iframe src="https://evil.example"></iframe>'],
    ['svg onload', '<svg onload="window.pwned = 1"></svg>'],
    ['style attribute', '<p style="background:url(https://evil.example)">hi</p>'],
    ['form', '<form action="https://evil.example"><input name=x></form>'],
    ['object', '<object data="https://evil.example"></object>'],
    ['markdown image', '![tracker](https://evil.example/pixel.png)'],
    ['link with onclick', '<a href="https://example.org" onclick="window.pwned = 1">x</a>'],
  ];

  it.each(payloads)('strips %s', (_name, payload) => {
    const html = renderMarkdown(payload);
    const root = parse(html);
    expect(root.querySelector('script, iframe, svg, img, form, input, object')).toBeNull();
    for (const el of root.querySelectorAll('*')) {
      for (const attr of el.getAttributeNames()) {
        expect(attr.startsWith('on')).toBe(false);
        expect(attr).not.toBe('style');
        expect(attr).not.toBe('src');
      }
    }
    expect((window as unknown as { pwned?: number }).pwned).toBeUndefined();
  });

  it('shows raw HTML as literal text instead of passing it through', () => {
    const root = parse(renderMarkdown('use <b>this</b> carefully'));
    expect(root.querySelector('b')).toBeNull();
    expect(root.textContent).toContain('<b>this</b>');
  });

  it('keeps the alt text of an image as plain text', () => {
    const root = parse(renderMarkdown('![a diagram](https://example.org/d.png)'));
    expect(root.textContent).toContain('a diagram');
  });
});
