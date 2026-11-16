/**
 * Component tests for RateLimitsSection.vue — the Entitlements page's "Rate
 * limits" section: each configured rule in plain language, the caller's tools
 * it covers, and their usage of its window.
 */
import { flushPromises, mount } from '@vue/test-utils';
import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../lib/api', () => ({
  fetchRateLimits: vi.fn(),
  SessionExpiredError: class SessionExpiredError extends Error {},
  AccessDeniedError: class AccessDeniedError extends Error {},
}));

import { fetchRateLimits, type RateLimitsResponse } from '../../lib/api';
import RateLimitsSection from '../RateLimitsSection.vue';

const RULES: RateLimitsResponse = {
  usage_available: true,
  unlisted_services: ['jhub_service'],
  rate_limits: [
    {
      action_type: 'state_change',
      tool: null,
      limit: 60,
      window_seconds: 300,
      used: 12,
      resets_in_seconds: 180,
      tools: ['condor_submit_dag', 'condor_submit_job'],
    },
    {
      action_type: null,
      tool: 'condor_submit_*',
      limit: 30,
      window_seconds: 300,
      used: 30,
      resets_in_seconds: 45,
      tools: ['condor_submit_dag', 'condor_submit_job'],
    },
    {
      action_type: null,
      tool: 'servicex_submit_query',
      limit: 10,
      window_seconds: 300,
      used: 0,
      resets_in_seconds: null,
      tools: [],
    },
  ],
};

function stubFetches(rules: RateLimitsResponse = RULES) {
  vi.mocked(fetchRateLimits).mockResolvedValue(rules);
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

  it("lists the caller's tools each rule covers, as the broker reports them", async () => {
    stubFetches();
    const wrapper = await mountSection();

    const rows = wrapper.findAll('tbody tr');
    expect(rows[0].text()).toContain('condor_submit_dag');
    expect(rows[0].text()).toContain('condor_submit_job');
    expect(rows[0].text()).not.toContain('rucio_list_dids');
    expect(rows[1].text()).toContain('condor_submit_dag');
    expect(rows[2].text()).toContain('No tool of yours matches');
  });

  it('says which services the broker could not list rather than implying completeness', async () => {
    stubFetches();
    const wrapper = await mountSection();

    expect(wrapper.find('[data-testid="rl-unlisted"]').text()).toContain('jhub_service');
  });

  it('omits the unlisted-services note when every service was listed', async () => {
    stubFetches({ ...RULES, unlisted_services: [] });
    const wrapper = await mountSection();

    expect(wrapper.find('[data-testid="rl-unlisted"]').exists()).toBe(false);
  });

  it('shows the empty state when no limits are configured', async () => {
    stubFetches({ rate_limits: [], usage_available: true, unlisted_services: [] });
    const wrapper = await mountSection();

    expect(wrapper.text()).toContain('No rate limits are configured.');
    expect(wrapper.find('table').exists()).toBe(false);
  });

  it('marks usage unavailable and says why when the broker could not read it', async () => {
    stubFetches({
      usage_available: false,
      unlisted_services: [],
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
