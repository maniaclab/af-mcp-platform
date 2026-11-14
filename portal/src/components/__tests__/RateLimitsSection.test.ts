/**
 * Component tests for RateLimitsSection.vue — the Entitlements page's "Rate
 * limits" section: each configured rule in plain language, the caller's tools
 * it covers, and their usage of its window.
 */
import { flushPromises, mount } from '@vue/test-utils';
import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../lib/api', () => ({
  fetchRateLimits: vi.fn(),
  fetchCatalog: vi.fn(),
  fetchServerTools: vi.fn(),
  SessionExpiredError: class SessionExpiredError extends Error {},
  AccessDeniedError: class AccessDeniedError extends Error {},
}));

import {
  fetchCatalog,
  fetchRateLimits,
  fetchServerTools,
  type CatalogServer,
  type CatalogTool,
  type RateLimitsResponse,
} from '../../lib/api';
import RateLimitsSection from '../RateLimitsSection.vue';

const RULES: RateLimitsResponse = {
  usage_available: true,
  rate_limits: [
    {
      action_type: 'state_change',
      tool: null,
      limit: 60,
      window_seconds: 300,
      used: 12,
      resets_in_seconds: 180,
    },
    {
      action_type: null,
      tool: 'condor_submit_*',
      limit: 30,
      window_seconds: 300,
      used: 30,
      resets_in_seconds: 45,
    },
    {
      action_type: null,
      tool: 'servicex_submit_query',
      limit: 10,
      window_seconds: 300,
      used: 0,
      resets_in_seconds: null,
    },
  ],
};

function server(name: string, status: CatalogServer['status'] = 'available'): CatalogServer {
  return { name, display_name: name, status } as CatalogServer;
}

function tool(name: string, action_type: CatalogTool['action_type']): CatalogTool {
  return { name, description: '', action_type, permission: '__none__' };
}

const TOOLS: Record<string, CatalogTool[]> = {
  condor_service: [
    tool('condor_submit_job', 'state_change'),
    tool('condor_submit_dag', 'state_change'),
    tool('condor_query_jobs', 'read'),
  ],
  rucio_service: [tool('rucio_list_dids', 'read')],
};

function stubFetches(rules: RateLimitsResponse = RULES, servers: CatalogServer[] = []) {
  vi.mocked(fetchRateLimits).mockResolvedValue(rules);
  vi.mocked(fetchCatalog).mockResolvedValue({
    servers: servers.length
      ? servers
      : [
          server('condor_service'),
          server('rucio_service'),
          server('jhub_service', 'link_required'),
        ],
  });
  vi.mocked(fetchServerTools).mockImplementation(async (name: string) => ({
    name,
    display_name: name,
    description: '',
    status: 'ok',
    status_detail: '',
    tools: TOOLS[name] ?? [],
  }));
}

async function mountSection() {
  const wrapper = mount(RateLimitsSection);
  await flushPromises();
  return wrapper;
}

beforeEach(() => {
  vi.resetAllMocks();
});

describe('RateLimitsSection', () => {
  it('describes each rule in plain language', async () => {
    stubFetches();
    const text = (await mountSection()).text();

    expect(text).toContain('State-changing methods');
    expect(text).toContain('60 calls per 5 minutes');
    expect(text).toContain('Methods matching');
    expect(text).toContain('condor_submit_*');
    expect(text).toContain('30 calls per 5 minutes');
    expect(text).toContain('10 calls per 5 minutes');
  });

  it("shows the caller's usage and when the window resets", async () => {
    stubFetches();
    const wrapper = await mountSection();

    const rows = wrapper.findAll('tbody tr');
    expect(rows[0].text()).toContain('12 of 60 used, resets in 3 min');
    expect(rows[1].text()).toContain('Limit reached, resets in 45 sec');
    expect(rows[2].text()).toContain('0 of 10 used');
  });

  it("lists the caller's tools each rule covers, from the services they can list", async () => {
    stubFetches();
    const wrapper = await mountSection();

    const rows = wrapper.findAll('tbody tr');
    expect(rows[0].text()).toContain('condor_submit_dag');
    expect(rows[0].text()).toContain('condor_submit_job');
    expect(rows[0].text()).not.toContain('rucio_list_dids');
    expect(rows[1].text()).toContain('condor_submit_dag');
    expect(rows[2].text()).toContain('No tool of yours matches');
    // A service that needs linking is not asked for its tools.
    expect(fetchServerTools).not.toHaveBeenCalledWith('jhub_service');
  });

  it('says which services could not be listed rather than implying completeness', async () => {
    stubFetches();
    const wrapper = await mountSection();

    expect(wrapper.find('[data-testid="rl-unlisted"]').text()).toContain('jhub_service');
  });

  it('keeps the rules when a service listing fails', async () => {
    stubFetches();
    vi.mocked(fetchServerTools).mockImplementation(async (name: string) => {
      if (name === 'rucio_service') throw new Error('boom');
      return {
        name,
        display_name: name,
        description: '',
        status: 'ok',
        status_detail: '',
        tools: TOOLS[name] ?? [],
      };
    });
    const wrapper = await mountSection();

    expect(wrapper.findAll('tbody tr')).toHaveLength(3);
    expect(wrapper.find('[data-testid="rl-unlisted"]').text()).toContain('rucio_service');
  });

  it('shows the empty state, and asks for no tools, when no limits are configured', async () => {
    stubFetches({ rate_limits: [], usage_available: true });
    const wrapper = await mountSection();

    expect(wrapper.text()).toContain('No rate limits are configured.');
    expect(wrapper.find('table').exists()).toBe(false);
    expect(fetchCatalog).not.toHaveBeenCalled();
  });

  it('marks usage unavailable and says why when the broker could not read it', async () => {
    stubFetches({
      usage_available: false,
      rate_limits: RULES.rate_limits.map((r) => ({ ...r, used: null, resets_in_seconds: null })),
    });
    const wrapper = await mountSection();

    expect(wrapper.findAll('tbody tr')[0].text()).toContain('Usage unavailable');
    expect(wrapper.find('[data-testid="rl-usage-note"]').text()).toContain('could not be read');
  });

  it('renders a failed load as an alert', async () => {
    vi.mocked(fetchRateLimits).mockRejectedValue(new Error('boom'));
    const wrapper = await mountSection();

    expect(wrapper.find('[role="alert"]').text()).toContain('boom');
  });
});
