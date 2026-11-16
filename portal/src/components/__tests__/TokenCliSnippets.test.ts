/**
 * Component contract test for TokenCliSnippets.vue: the snippets are built
 * from the `brokerOrigin` prop.
 */
import { flushPromises, mount } from '@vue/test-utils';
import { describe, expect, it } from 'vitest';
import TokenCliSnippets from '../TokenCliSnippets.vue';

describe('TokenCliSnippets', () => {
  it('builds the curl and Python snippets from the broker origin', async () => {
    const wrapper = mount(TokenCliSnippets, {
      props: { brokerOrigin: 'https://broker.example.org' },
      attachTo: document.body,
    });

    await wrapper.get('button[aria-expanded]').trigger('click');
    await flushPromises();

    expect(wrapper.get('h2').text()).toBe('Use from the command line');
    const text = document.body.textContent ?? '';
    expect(text).toContain('https://broker.example.org');
    wrapper.unmount();
  });
});
