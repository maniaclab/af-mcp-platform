/**
 * Component tests for ConnectClient.vue — the Overview page's "connect a
 * client" section: the MCP endpoint as a copy field, numbered steps for
 * Claude, and a curl snippet for clients that cannot sign in with a browser.
 */
import { flushPromises, mount } from '@vue/test-utils';
import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../lib/auth', () => ({
  getBrokerOrigin: vi.fn(),
}));

import { getBrokerOrigin } from '../../lib/auth';
import ConnectClient from '../ConnectClient.vue';

beforeEach(() => {
  vi.mocked(getBrokerOrigin).mockResolvedValue('https://mcp.example.org');
});

async function mountSection() {
  const wrapper = mount(ConnectClient);
  await flushPromises();
  return wrapper;
}

describe('ConnectClient', () => {
  it('shows the endpoint with a trailing slash in a copy field', async () => {
    const wrapper = await mountSection();

    const fields = wrapper.findAll('.af-copy');
    expect(fields[0]!.find('code').text()).toBe('https://mcp.example.org/mcp/');
    expect(fields[0]!.find('button').attributes('aria-label')).toBe(
      'Copy endpoint URL to clipboard',
    );
  });

  it('shows a loading line instead of an empty field until the origin resolves', () => {
    vi.mocked(getBrokerOrigin).mockReturnValue(new Promise(() => {}));
    const wrapper = mount(ConnectClient);

    expect(wrapper.find('.af-copy').exists()).toBe(false);
    expect(wrapper.text()).toContain('Loading…');
  });

  it('lists the three Claude steps as a numbered list', async () => {
    const wrapper = await mountSection();

    const steps = wrapper.findAll('ol > li');
    expect(steps).toHaveLength(3);
    expect(steps[0]!.text()).toContain('Settings → Connectors → Add custom connector');
    expect(steps[1]!.text()).toContain('opens a browser window');
    expect(steps[2]!.find('a').attributes('href')).toBe('/tokens/');
    expect(steps[2]!.text()).toContain('Authorization');
    expect(steps[2]!.text()).toContain('Bearer <your token>');
  });

  it('gives the curl snippet its own multiline copy field built from the endpoint', async () => {
    const wrapper = await mountSection();

    const snippet = wrapper.findAll('.af-copy')[1]!;
    expect(snippet.classes()).toContain('copy--multiline');
    expect(snippet.find('code').text()).toBe(
      'export MCP_TOKEN="<your token>"\n' +
        'curl -H "Authorization: Bearer $MCP_TOKEN" \\\n' +
        '     https://mcp.example.org/mcp/',
    );
  });

  it('links the curl note to the tokens page', async () => {
    const wrapper = await mountSection();

    const link = wrapper.findAll('a').filter((a) => a.attributes('href') === '/tokens/');
    expect(link).toHaveLength(2);
  });
});
