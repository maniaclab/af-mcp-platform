/**
 * Component tests for OverviewSummary.vue — the Overview page's banner,
 * status list and usage stats.
 *
 * The usage figures come from GET /v1/usage's window totals (calls,
 * estimated tokens, estimated cost priced at the reference model).
 * Everything the usage stats show is an ESTIMATE (tokenized tool-result text
 * priced at one model's input rate, not provider-reported spend), so the
 * component must label it as such, and it must degrade gracefully both when
 * the window is empty and when a fetch fails outright.
 */
import { flushPromises, mount } from '@vue/test-utils';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { DashboardSummary, UsageResponse } from '../../lib/api';

vi.mock('../../lib/api', () => ({
  fetchUsage: vi.fn(),
  fetchDashboardSummary: vi.fn(),
}));

import { fetchDashboardSummary, fetchUsage } from '../../lib/api';
import OverviewSummary from '../OverviewSummary.vue';

const SUMMARY: DashboardSummary = {
  linkedCount: 3,
  serverCount: 8,
  activeTokenCount: 2,
  reachableCount: 8,
  needsLinkCount: 0,
  unavailableCount: 0,
  misconfiguredCount: 0,
  proxyAutoRenews: false,
  soonestExpiringToken: null,
  proxyStatus: { cached: true, voms_attributes: [], remaining_seconds: 48 * 3600 },
};

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
  vi.mocked(fetchDashboardSummary).mockResolvedValue(SUMMARY);
  vi.mocked(fetchUsage).mockResolvedValue(USAGE);
});

async function mountSummary() {
  const wrapper = mount(OverviewSummary);
  await flushPromises();
  return wrapper;
}

describe('OverviewSummary usage', () => {
  it('shows window calls, estimated tokens, and estimated cost with the model name', async () => {
    const wrapper = await mountSummary();

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
    const wrapper = await mountSummary();

    expect(wrapper.text()).toContain('No tool calls');
    // The zeroed cost line would be noise under an explicit empty state.
    expect(wrapper.text()).not.toContain('$0');
  });

  it('degrades to a status-unavailable row when the usage fetch fails', async () => {
    vi.mocked(fetchUsage).mockRejectedValue(new Error('boom'));
    const wrapper = await mountSummary();

    // The row still renders its explanation and link, just without live
    // numbers, and the other rows are unaffected.
    const usageRow = wrapper.findAll('.ov__row').find((r) => r.text().includes('Usage'));
    expect(usageRow?.text()).toContain('Status unavailable');
    expect(usageRow?.find('a').attributes('href')).toBe('/usage/');
    expect(wrapper.text()).not.toContain('Loading…');
    expect(wrapper.text()).toContain('8 of 8 available');
  });
});

describe('OverviewSummary status list', () => {
  it('has one row per area, each with a status word and a link to its page', async () => {
    const wrapper = await mountSummary();

    const rows = wrapper.findAll('.ov__row');
    expect(rows.map((r) => r.find('a').attributes('href'))).toEqual([
      '/catalog/',
      '/identities/',
      '/tokens/',
      '/usage/',
    ]);
    for (const row of rows) {
      expect(row.find('.af-mark').attributes('aria-hidden')).toBe('true');
      expect(row.find('svg').attributes('aria-hidden')).toBe('true');
    }
    expect(rows[0]!.text()).toContain('8 of 8 available');
    expect(rows[0]!.find('.af-mark').classes()).toContain('ok');
    expect(rows[1]!.text()).toContain('3 linked');
    expect(rows[1]!.text()).toContain('grid certificate active');
    expect(rows[2]!.text()).toContain('2 active');
    expect(rows[3]!.text()).toContain('42 calls in 30 days');
  });

  it('shows the grid certificate as not linked when no proxy is cached', async () => {
    vi.mocked(fetchDashboardSummary).mockResolvedValue({
      ...SUMMARY,
      proxyStatus: { cached: false, voms_attributes: [] },
    });
    const wrapper = await mountSummary();

    const identities = wrapper.findAll('.ov__row')[1]!;
    expect(identities.text()).toContain('grid certificate not linked');
    expect(identities.find('.af-mark').classes()).toContain('ok');
  });

  it('marks an expired grid proxy as a problem in the identities row', async () => {
    vi.mocked(fetchDashboardSummary).mockResolvedValue({
      ...SUMMARY,
      proxyStatus: { cached: true, voms_attributes: [], remaining_seconds: 0 },
    });
    const wrapper = await mountSummary();

    const identities = wrapper.findAll('.ov__row')[1]!;
    expect(identities.text()).toContain('grid certificate expired');
    expect(identities.find('.af-mark').classes()).toContain('bad');
  });

  it('warns in the identities row when a proxy that cannot renew has under an hour left', async () => {
    vi.mocked(fetchDashboardSummary).mockResolvedValue({
      ...SUMMARY,
      proxyStatus: { cached: true, voms_attributes: [], remaining_seconds: 1800 },
    });
    const wrapper = await mountSummary();

    const identities = wrapper.findAll('.ov__row')[1]!;
    expect(identities.text()).toContain('grid certificate expiring');
    expect(identities.find('.af-mark').classes()).toContain('warn');
  });

  it('keeps an auto-renewing proxy under an hour from expiry as active', async () => {
    vi.mocked(fetchDashboardSummary).mockResolvedValue({
      ...SUMMARY,
      proxyAutoRenews: true,
      proxyStatus: { cached: true, voms_attributes: [], remaining_seconds: 1800 },
    });
    const wrapper = await mountSummary();

    const identities = wrapper.findAll('.ov__row')[1]!;
    expect(identities.text()).toContain('grid certificate active');
    expect(identities.find('.af-mark').classes()).toContain('ok');
  });

  it('shows a loading state until the fetches settle', () => {
    vi.mocked(fetchDashboardSummary).mockReturnValue(new Promise(() => {}));
    vi.mocked(fetchUsage).mockReturnValue(new Promise(() => {}));
    const wrapper = mount(OverviewSummary);

    expect(wrapper.findAll('.ov__row')).toHaveLength(4);
    expect(wrapper.text()).toContain('Loading…');
  });

  it('shows status unavailable rather than zeros when the summary fetch fails', async () => {
    vi.mocked(fetchDashboardSummary).mockRejectedValue(new Error('boom'));
    const wrapper = await mountSummary();

    const text = wrapper.findAll('.ov__row')[0]!.text();
    expect(text).toContain('Status unavailable');
    expect(text).not.toContain('0 of 0');
  });
});

describe('OverviewSummary services and tokens rows', () => {
  it('keeps the ok mark when some services are only not linked', async () => {
    vi.mocked(fetchDashboardSummary).mockResolvedValue({
      ...SUMMARY,
      reachableCount: 6,
      needsLinkCount: 2,
    });
    const wrapper = await mountSummary();

    const row = wrapper.findAll('.ov__row')[0]!;
    expect(row.text()).toContain('6 of 8 available · 2 not linked');
    expect(row.find('.af-mark').classes()).toContain('ok');
  });

  it('marks an unavailable service as a warning and names it apart from not linked', async () => {
    vi.mocked(fetchDashboardSummary).mockResolvedValue({
      ...SUMMARY,
      reachableCount: 6,
      needsLinkCount: 1,
      unavailableCount: 1,
    });
    const wrapper = await mountSummary();

    const row = wrapper.findAll('.ov__row')[0]!;
    expect(row.find('.af-mark').classes()).toContain('warn');
    expect(row.text()).toContain('6 of 8 available · 1 unavailable · 1 not linked');
  });

  it('marks a misconfigured service as a problem and keeps it apart from unavailable', async () => {
    vi.mocked(fetchDashboardSummary).mockResolvedValue({
      ...SUMMARY,
      reachableCount: 5,
      misconfiguredCount: 1,
      unavailableCount: 2,
    });
    const wrapper = await mountSummary();

    const row = wrapper.findAll('.ov__row')[0]!;
    expect(row.find('.af-mark').classes()).toContain('bad');
    expect(row.text()).toContain('5 of 8 available · 1 misconfigured · 2 unavailable');
  });

  it('shows the identities row as off, not a warning, when nothing is linked', async () => {
    vi.mocked(fetchDashboardSummary).mockResolvedValue({
      ...SUMMARY,
      linkedCount: 0,
      proxyStatus: { cached: false, voms_attributes: [] },
    });
    const wrapper = await mountSummary();
    const mark = wrapper.findAll('.ov__row')[1]!.find('.af-mark');
    expect(mark.classes()).toContain('off');
  });

  it('says when a token expires soon, as a warning', async () => {
    const soon = new Date(Date.now() + 3 * 24 * 3600 * 1000).toISOString();
    vi.mocked(fetchDashboardSummary).mockResolvedValue({
      ...SUMMARY,
      soonestExpiringToken: { name: 'ci', expires_at: soon },
    });
    const wrapper = await mountSummary();

    const row = wrapper.findAll('.ov__row')[2]!;
    expect(row.text()).toContain('2 active · soonest expires in 3 days');
    expect(row.find('.af-mark').classes()).toContain('warn');
  });
});

describe('OverviewSummary banner', () => {
  it('renders nothing when nothing is wrong', async () => {
    const wrapper = await mountSummary();
    expect(wrapper.find('.af-banner').exists()).toBe(false);
  });

  it('renders the single most urgent problem with its fix', async () => {
    vi.mocked(fetchDashboardSummary).mockResolvedValue({
      ...SUMMARY,
      proxyStatus: { cached: true, voms_attributes: [], remaining_seconds: 0 },
    });
    const wrapper = await mountSummary();

    const banners = wrapper.findAll('.af-banner');
    expect(banners).toHaveLength(1);
    expect(banners[0]!.classes()).toContain('bad');
    expect(banners[0]!.attributes('role')).toBe('alert');
    expect(banners[0]!.text()).toContain('Your grid proxy has expired');
    const action = banners[0]!.find('a.af-btn');
    expect(action.text()).toBe('Renew proxy');
    expect(action.attributes('href')).toBe('/identities/');
  });
});
