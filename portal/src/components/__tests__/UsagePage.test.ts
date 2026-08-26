/**
 * Component tests for UsagePage.vue — the full /usage page.
 *
 * The page renders GET /v1/usage's whole payload: window totals, the
 * per-service table, and the per-day activity bars, with a window
 * selector (7/30/90 days) that refetches on change. Everything shown is
 * an ESTIMATE (tokenized tool-result text priced at one model's input
 * rate, not provider-reported spend) so the page must label it as such,
 * and it must degrade gracefully on an empty window and on a failed
 * fetch.
 */
import { flushPromises, mount } from '@vue/test-utils';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { UsageResponse } from '../../lib/api';

vi.mock('../../lib/api', () => ({
  fetchUsage: vi.fn(),
  SessionExpiredError: class SessionExpiredError extends Error {},
  AccessDeniedError: class AccessDeniedError extends Error {},
}));

import { fetchUsage } from '../../lib/api';
import UsagePage from '../UsagePage.vue';

const USAGE: UsageResponse = {
  subject: 'user-123',
  window_days: 30,
  cost_model: 'claude-sonnet-4-20250514',
  totals: {
    calls: 42,
    errors: 3,
    duration_ms: 1234.5,
    result_bytes: 98765,
    result_tokens_est: 15000,
    estimated_cost_usd: 0.045,
  },
  by_service: [
    {
      service: 'rucio',
      calls: 30,
      errors: 2,
      result_bytes: 65536,
      result_tokens_est: 11000,
      estimated_cost_usd: 0.033,
    },
    {
      service: 'ami',
      calls: 12,
      errors: 1,
      result_bytes: 33229,
      result_tokens_est: 4000,
      estimated_cost_usd: 0.012,
    },
  ],
  by_day: [
    { date: '2026-08-24', calls: 30, result_tokens_est: 11000 },
    { date: '2026-08-25', calls: 12, result_tokens_est: 4000 },
  ],
};

const EMPTY: UsageResponse = {
  subject: 'user-123',
  window_days: 30,
  cost_model: 'claude-sonnet-4-20250514',
  totals: {
    calls: 0,
    errors: 0,
    duration_ms: 0,
    result_bytes: 0,
    result_tokens_est: 0,
    estimated_cost_usd: 0,
  },
  by_service: [],
  by_day: [],
};

beforeEach(() => {
  vi.restoreAllMocks();
});

describe('UsagePage', () => {
  it('renders window totals with the estimate labeling and model name', async () => {
    vi.mocked(fetchUsage).mockResolvedValue(USAGE);
    const wrapper = mount(UsagePage);
    await flushPromises();

    const text = wrapper.text();
    expect(text).toContain('42');
    expect(text).toContain('15,000');
    expect(text).toContain('$0.045');
    expect(text).toContain('claude-sonnet-4-20250514');
    // Everything shown is an estimate and must say so — same caveat
    // wording as the overview's UsageCard.
    expect(text.toLowerCase()).toContain('estimated');
    expect(text).toContain('this is not your provider bill');
  });

  it('renders one per-service row per service with its aggregates', async () => {
    vi.mocked(fetchUsage).mockResolvedValue(USAGE);
    const wrapper = mount(UsagePage);
    await flushPromises();

    const rows = wrapper.findAll('tbody tr');
    expect(rows).toHaveLength(2);
    expect(rows[0].text()).toContain('rucio');
    expect(rows[0].text()).toContain('30');
    expect(rows[1].text()).toContain('ami');
    expect(rows[1].text()).toContain('4,000');
  });

  it('renders per-day activity bars for the days with calls', async () => {
    vi.mocked(fetchUsage).mockResolvedValue(USAGE);
    const wrapper = mount(UsagePage);
    await flushPromises();

    const bars = wrapper.findAll('[data-testid="usage-day-bar"]');
    // One bar per calendar day in the 30-day window, zero-height for the
    // days without calls.
    expect(bars).toHaveLength(30);
    expect(bars.some((b) => Number(b.attributes('data-calls')) === 30)).toBe(true);
  });

  it('refetches when the window selector changes', async () => {
    vi.mocked(fetchUsage).mockResolvedValue(USAGE);
    const wrapper = mount(UsagePage);
    await flushPromises();
    expect(fetchUsage).toHaveBeenCalledWith(30);

    const ninety = wrapper.findAll('button').find((b) => b.text() === '90d');
    expect(ninety).toBeDefined();
    await ninety!.trigger('click');
    await flushPromises();

    expect(fetchUsage).toHaveBeenCalledWith(90);
  });

  it('renders a friendly empty state when the window has no calls', async () => {
    vi.mocked(fetchUsage).mockResolvedValue(EMPTY);
    const wrapper = mount(UsagePage);
    await flushPromises();

    expect(wrapper.text()).toContain('No tool calls');
    // A zeroed cost figure would be noise under an explicit empty state.
    expect(wrapper.text()).not.toContain('$0');
  });

  it('renders an error state when the fetch fails', async () => {
    vi.mocked(fetchUsage).mockRejectedValue(new Error('boom'));
    const wrapper = mount(UsagePage);
    await flushPromises();

    expect(wrapper.find('[role="alert"]').exists()).toBe(true);
    expect(wrapper.text()).toContain('boom');
  });
});
