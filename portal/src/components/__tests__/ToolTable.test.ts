/**
 * Component tests for ToolTable.vue's per-method rendering: the read/write
 * badge's tooltip names the tool's specific permission (not just
 * read/write), and a docstring with more than a one-paragraph summary
 * collapses behind a "Show more" toggle so a service with many methods stays
 * scannable instead of turning into a wall of prose.
 */
import { flushPromises, mount } from '@vue/test-utils';
import { describe, expect, it } from 'vitest';
import type { CatalogTool } from '../../lib/api';
import { loadMarkdownRenderer } from '../../lib/markdownRenderer';
import ToolTable from '../ToolTable.vue';

function tool(overrides: Partial<CatalogTool> = {}): CatalogTool {
  return {
    name: 'rucio_list_dids',
    description: 'List DIDs matching a pattern.',
    action_type: 'read',
    permission: 'read_data',
    ...overrides,
  };
}

describe('permission tooltip', () => {
  it("names the tool's specific permission, not just read/write", () => {
    const wrapper = mount(ToolTable, { props: { tools: [tool({ permission: 'read_data' })] } });
    expect(wrapper.text()).toContain('Requires Read data (read_data).');
  });

  it('says no specific permission is required for a "__none__" tool', () => {
    const wrapper = mount(ToolTable, { props: { tools: [tool({ permission: '__none__' })] } });
    expect(wrapper.text()).toContain('No specific permission required.');
  });
});

describe('collapsible description', () => {
  it('shows only the first paragraph by default when a docstring has more', () => {
    const wrapper = mount(ToolTable, {
      props: {
        tools: [
          tool({
            description: 'Short teaser sentence.\n\nA much longer second paragraph of detail.',
          }),
        ],
      },
    });

    expect(wrapper.text()).toContain('Short teaser sentence.');
    expect(wrapper.text()).not.toContain('A much longer second paragraph of detail.');
    expect(wrapper.find('.tool-table__more-toggle').text()).toBe('Show more');
  });

  it('reveals the rest of the description on toggle', async () => {
    const wrapper = mount(ToolTable, {
      props: {
        tools: [
          tool({
            description: 'Short teaser sentence.\n\nA much longer second paragraph of detail.',
          }),
        ],
      },
    });

    await wrapper.find('.tool-table__more-toggle').trigger('click');

    expect(wrapper.text()).toContain('A much longer second paragraph of detail.');
    expect(wrapper.find('.tool-table__more-toggle').text()).toBe('Show less');
  });

  it('renders no toggle for a single-paragraph description with no args/returns', () => {
    const wrapper = mount(ToolTable, {
      props: { tools: [tool({ description: 'Just one short sentence.' })] },
    });

    expect(wrapper.find('.tool-table__more-toggle').exists()).toBe(false);
  });

  it('offers a toggle when a single-paragraph summary still has a parsed Args block', () => {
    const wrapper = mount(ToolTable, {
      props: {
        tools: [
          tool({ description: 'One short paragraph.\n\nArgs:\n  scope: The scope to search.' }),
        ],
      },
    });

    expect(wrapper.find('.tool-table__more-toggle').exists()).toBe(true);
    expect(wrapper.text()).not.toContain('The scope to search.');
  });
});

describe('markdown descriptions', () => {
  it('renders Markdown in the teaser and in the expanded detail', async () => {
    const wrapper = mount(ToolTable, {
      props: {
        tools: [
          tool({
            description:
              'Search with **wildcards**.\n\nSee `rucio_list_dids`.\n\n- first\n- second\n\nArgs:\n  scope: The `scope` to search.\n\nReturns:\n  A **list** of DIDs.',
          }),
        ],
      },
    });

    await loadMarkdownRenderer();
    await flushPromises();

    expect(wrapper.find('strong').text()).toBe('wildcards');
    await wrapper.find('.tool-table__more-toggle').trigger('click');
    expect(wrapper.find('li').text()).toBe('first');
    expect(wrapper.find('.tool-table__arg-desc code').text()).toBe('scope');
    expect(wrapper.find('.tool-table__returns strong').text()).toBe('list');
  });

  it('strips scripts, handlers and unsafe links from a backend-supplied description', async () => {
    const wrapper = mount(ToolTable, {
      props: {
        tools: [
          tool({
            description:
              '<img src=x onerror="window.pwned = 1"> [go](javascript:alert(1))\n\n<script>window.pwned = 1</script>\n\n[ok](https://example.org)',
          }),
        ],
      },
    });
    await wrapper.find('.tool-table__more-toggle').trigger('click');
    await loadMarkdownRenderer();
    await flushPromises();

    expect(wrapper.find('script, img').exists()).toBe(false);
    const hrefs = wrapper.findAll('a').map((a) => a.attributes('href') ?? null);
    expect(hrefs).toEqual([null, 'https://example.org']);
    for (const a of wrapper.findAll('a[href]')) {
      expect(a.attributes('rel')).toBe('noopener noreferrer');
      expect(a.attributes('target')).toBe('_blank');
    }
    expect((window as unknown as { pwned?: number }).pwned).toBeUndefined();
  });
});
