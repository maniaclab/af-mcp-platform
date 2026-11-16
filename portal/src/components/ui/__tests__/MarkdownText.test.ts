/**
 * MarkdownText loads the Markdown renderer (marked + DOMPurify) with a dynamic
 * import when it first mounts, so the library is not part of any page's entry
 * chunk. Until the import resolves, the source shows as plain text; the same
 * text is what the server-side pass renders.
 */
import { flushPromises, mount } from '@vue/test-utils';
import { describe, expect, it, vi } from 'vitest';

vi.mock('../../../lib/markdown', () => ({
  renderMarkdown: (source: string, { inline = false } = {}) =>
    inline ? `<em>${source}</em>` : `<p><em>${source}</em></p>`,
}));

// Each test gets a fresh module graph, so the renderer starts "not yet loaded".
// markdownRenderer.value is null until markdown.ts has been imported.
async function freshModules() {
  vi.resetModules();
  const { markdownRenderer, loadMarkdownRenderer } = await import('../../../lib/markdownRenderer');
  const MarkdownText = (await import('../MarkdownText.vue')).default;
  return { MarkdownText, markdownRenderer, loadMarkdownRenderer };
}

describe('MarkdownText lazy renderer', () => {
  it('does not load the renderer when the component module is imported', async () => {
    const { markdownRenderer } = await freshModules();
    expect(markdownRenderer.value).toBeNull();
  });

  it('shows the source as plain text until the renderer has loaded', async () => {
    const { MarkdownText } = await freshModules();
    const wrapper = mount(MarkdownText, { props: { source: 'a **b** <i>c</i>' } });

    expect(wrapper.text()).toBe('a **b** <i>c</i>');
    expect(wrapper.find('em').exists()).toBe(false);
    expect(wrapper.find('i').exists()).toBe(false);
  });

  it('renders Markdown once the renderer has loaded', async () => {
    const { MarkdownText } = await freshModules();
    const wrapper = mount(MarkdownText, { props: { source: 'hello' } });
    await flushPromises();

    expect(wrapper.find('em').text()).toBe('hello');
  });

  it('renders inline sources in a span without a paragraph', async () => {
    const { MarkdownText } = await freshModules();
    const wrapper = mount(MarkdownText, { props: { source: 'hello', inline: true } });
    await flushPromises();

    expect(wrapper.element.tagName).toBe('SPAN');
    expect(wrapper.find('p').exists()).toBe(false);
    expect(wrapper.find('em').text()).toBe('hello');
  });

  it('loads the renderer once for any number of instances and renders later ones at once', async () => {
    const { MarkdownText, loadMarkdownRenderer } = await freshModules();
    mount(MarkdownText, { props: { source: 'one' } });
    const shared = loadMarkdownRenderer();
    await flushPromises();
    const second = mount(MarkdownText, { props: { source: 'two' } });

    expect(loadMarkdownRenderer()).toBe(shared);
    expect(second.find('em').text()).toBe('two');
  });
});
