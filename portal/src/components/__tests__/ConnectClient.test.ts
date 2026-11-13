/**
 * Component tests for ConnectClient.vue — the Overview page's "connect a
 * client" section: three numbered step boxes (copy the endpoint, add it to a
 * client, sign in), and a collapsed disclosure holding the personal access
 * token route (request header and curl snippet) for clients that cannot open
 * a browser.
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

  it('lays out three numbered step boxes with a title each', async () => {
    const wrapper = await mountSection();

    const steps = wrapper.findAll('ol > li');
    expect(steps).toHaveLength(3);
    expect(steps.map((s) => s.get('h3').text())).toEqual([
      'Copy the server URL',
      'Add it to your client',
      'Sign in when asked',
    ]);
    expect(steps.map((s) => s.get('.cc__num').text())).toEqual(['1', '2', '3']);
    expect(steps.every((s) => s.classes().includes('af-box'))).toBe(true);
  });

  it('puts the endpoint copy field inside the first step', async () => {
    const wrapper = await mountSection();

    const first = wrapper.findAll('ol > li')[0]!;
    expect(first.find('.af-copy').exists()).toBe(true);
    expect(wrapper.findAll('ol > li .af-copy')).toHaveLength(1);
  });

  it('tells the user where to add the connector and that sign-in happens in a browser', async () => {
    const wrapper = await mountSection();

    const steps = wrapper.findAll('ol > li');
    expect(steps[1]!.text()).toContain('Settings → Connectors → Add custom connector');
    expect(steps[1]!.text()).toContain('No header or token needed');
    expect(steps[2]!.text()).toContain('opens a browser window');
  });

  it('drops the per-client sub-headings', async () => {
    const wrapper = await mountSection();

    const headings = wrapper.findAll('h3').map((h) => h.text());
    expect(headings).not.toContain('curl');
    expect(headings.some((h) => h.startsWith('Claude'))).toBe(false);
  });

  it('keeps the token route in one collapsed disclosure', async () => {
    const wrapper = await mountSection();

    const toggle = wrapper.get('button.disclosure__toggle');
    expect(toggle.text()).toBe('No browser? Use a personal access token');
    expect(toggle.attributes('aria-expanded')).toBe('false');
    expect(wrapper.find('.disclosure__body').exists()).toBe(false);

    await toggle.trigger('click');

    const body = wrapper.get('.disclosure__body');
    expect(body.get('a').attributes('href')).toBe('/tokens/');
    expect(body.text()).toContain('Authorization');
    expect(body.text()).toContain('Bearer <your token>');
  });

  it('gives the curl snippet its own multiline copy field built from the endpoint', async () => {
    const wrapper = await mountSection();
    await wrapper.get('button.disclosure__toggle').trigger('click');

    const snippet = wrapper.get('.disclosure__body .af-copy');
    expect(snippet.classes()).toContain('copy--multiline');
    expect(snippet.find('code').text()).toBe(
      'export MCP_TOKEN="<your token>"\n' +
        'curl -H "Authorization: Bearer $MCP_TOKEN" \\\n' +
        '     https://mcp.example.org/mcp/',
    );
  });
});
