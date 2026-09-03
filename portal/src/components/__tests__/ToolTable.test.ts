/**
 * Component tests for ToolTable.vue's per-method rendering: the read/write
 * badge's tooltip now names the tool's specific permission (not just
 * read/write), and a docstring with more than a one-paragraph summary
 * collapses behind a "Show more" toggle so a service with many methods stays
 * scannable instead of turning into a wall of prose.
 */
import { mount } from '@vue/test-utils';
import { describe, expect, it } from 'vitest';
import type { CatalogTool } from '../../lib/api';
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
    expect(wrapper.text()).toContain('Requires read_data.');
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
