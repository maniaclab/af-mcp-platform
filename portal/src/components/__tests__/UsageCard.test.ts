/**
 * Component tests for UsageCard.vue — the overview page's usage summary.
 *
 * The card surfaces GET /v1/usage's window totals (calls, estimated
 * tokens, estimated cost priced at the reference model). Everything it
 * shows is an ESTIMATE (tokenized tool-result text priced at one model's
 * input rate, not provider-reported spend), so the card must label it as
 * such, and it must degrade gracefully both when the window is empty and
 * when the fetch fails outright.
 */
import { flushPromises, mount } from '@vue/test-utils';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { UsageResponse } from '../../lib/api';

vi.mock('../../lib/api', () => ({
  fetchUsage: vi.fn(),
}));

import { fetchUsage } from '../../lib/api';
import UsageCard from '../UsageCard.vue';

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
      calls: 42,
      errors: 3,
      result_bytes: 98765,
      result_tokens_est: 15000,
      estimated_cost_usd: 0.045,
    },
  ],
  by_day: [{ date: '2026-08-25', calls: 42, result_tokens_est: 15000 }],
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

describe('UsageCard', () => {
  it('shows window calls, estimated tokens, and estimated cost with the model name', async () => {
    vi.mocked(fetchUsage).mockResolvedValue(USAGE);
    const wrapper = mount(UsageCard);
    await flushPromises();

    const text = wrapper.text();
    expect(text).toContain('42');
    expect(text).toContain('15,000');
    expect(text).toContain('$0.045');
    expect(text).toContain('claude-sonnet-4-20250514');
    // Everything shown is an estimate and must say so.
    expect(text.toLowerCase()).toContain('estimated');
  });

  it('renders a friendly no-usage state when the window is empty', async () => {
    vi.mocked(fetchUsage).mockResolvedValue(EMPTY);
    const wrapper = mount(UsageCard);
    await flushPromises();

    expect(wrapper.text()).toContain('No tool calls');
    // The zeroed cost line would be noise under an explicit empty state.
    expect(wrapper.text()).not.toContain('$0');
  });

  it('degrades to the plain explanation when the fetch fails', async () => {
    vi.mocked(fetchUsage).mockRejectedValue(new Error('boom'));
    const wrapper = mount(UsageCard);
    await flushPromises();

    // Same graceful degradation as DashboardCards: the card still renders
    // its explanation, just without a live status line.
    expect(wrapper.find('.uc__card').exists()).toBe(true);
    expect(wrapper.text()).not.toContain('Loading…');
  });
});
