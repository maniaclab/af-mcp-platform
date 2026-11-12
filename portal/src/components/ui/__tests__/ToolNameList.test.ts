/**
 * Component tests for ToolNameList.vue: a list of literal tool names, one per
 * item, that collapses its tail behind a disclosure when it is long.
 */
import { mount } from '@vue/test-utils';
import { describe, expect, it } from 'vitest';
import ToolNameList from '../ToolNameList.vue';

const names = (count: number) => Array.from({ length: count }, (_, i) => `condor_tool_${i + 1}`);

describe('ToolNameList', () => {
  it('renders each name as its own list item in mono, not as a joined string', () => {
    const w = mount(ToolNameList, { props: { names: ['condor_a', 'condor_b'] } });

    const items = w.findAll('li');
    expect(items.map((li) => li.text())).toEqual(['condor_a', 'condor_b']);
    expect(items[0].find('code').text()).toBe('condor_a');
    expect(w.text()).not.toContain(',');
  });

  it('renders nothing for an empty list', () => {
    const w = mount(ToolNameList, { props: { names: [] } });

    expect(w.find('ul').exists()).toBe(false);
    expect(w.find('button').exists()).toBe(false);
  });

  it('shows a list of up to the preview length in full, with no disclosure', () => {
    const w = mount(ToolNameList, { props: { names: names(3) } });

    expect(w.findAll('li')).toHaveLength(3);
    expect(w.find('button').exists()).toBe(false);
  });

  it('shows the first few names and a count of the rest behind a disclosure', async () => {
    const w = mount(ToolNameList, { props: { names: names(10) } });

    expect(w.findAll('li').map((li) => li.text())).toEqual(names(3));
    const toggle = w.get('button');
    expect(toggle.text()).toBe('7 more');
    expect(toggle.attributes('aria-expanded')).toBe('false');

    await toggle.trigger('click');

    expect(w.findAll('li').map((li) => li.text())).toEqual(names(10));
    expect(w.get('button').attributes('aria-expanded')).toBe('true');
  });

  it('keeps names whole: the list is flagged so a name never wraps mid-word', () => {
    const w = mount(ToolNameList, { props: { names: ['condor_create_output_download_url'] } });

    expect(w.get('ul').classes()).toContain('tnl');
  });
});
