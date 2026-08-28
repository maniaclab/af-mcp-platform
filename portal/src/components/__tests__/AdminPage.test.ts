/**
 * Component tests for AdminPage.vue — the /admin page body.
 *
 * Admins get a dropdown of subjects with recorded usage (GET
 * /v1/usage/subjects), labeled by unixname (falling back to email, then the
 * bare subject) since that's what's most recognizable to an operator.
 * Selecting one fetches that subject's usage (GET /v1/usage?subject=...)
 * and renders it via UsagePage.vue's existing rendering — this test only
 * pins the dropdown-to-fetch wiring, not the usage rendering itself (see
 * UsagePage.test.ts for that).
 */
import { flushPromises, mount } from '@vue/test-utils';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { UsageResponse, UsageSubjectsResponse } from '../../lib/api';

vi.mock('../../lib/api', () => ({
  fetchUsage: vi.fn(),
  fetchUsageSubjects: vi.fn(),
  SessionExpiredError: class SessionExpiredError extends Error {},
  AccessDeniedError: class AccessDeniedError extends Error {},
}));

import { fetchUsage, fetchUsageSubjects } from '../../lib/api';
import AdminPage from '../AdminPage.vue';

const SUBJECTS: UsageSubjectsResponse = {
  subjects: [
    { subject: 'sub-1', unixname: 'jdoe', email: 'jdoe@example.org' },
    { subject: 'sub-2', unixname: null, email: 'nouser@example.org' },
    { subject: 'sub-3', unixname: null, email: '' },
  ],
};

const USAGE: UsageResponse = {
  subject: 'sub-1',
  window_days: 30,
  cost_model: 'claude-sonnet-4-20250514',
  totals: {
    calls: 7,
    errors: 0,
    duration_ms: 12.3,
    result_bytes: 4096,
    result_tokens_est: 900,
    estimated_cost_usd: 0.003,
  },
  by_service: [],
  by_day: [],
};

beforeEach(() => {
  vi.restoreAllMocks();
});

describe('AdminPage', () => {
  it('renders a dropdown of subjects, labeled by unixname/email/subject fallback', async () => {
    vi.mocked(fetchUsageSubjects).mockResolvedValue(SUBJECTS);
    const wrapper = mount(AdminPage);
    await flushPromises();

    const options = wrapper.findAll('option[value]:not([value=""])');
    expect(options).toHaveLength(3);
    expect(options[0].text()).toBe('jdoe');
    expect(options[1].text()).toBe('nouser@example.org');
    expect(options[2].text()).toBe('sub-3');
  });

  it("fetches and renders the selected subject's usage via UsagePage", async () => {
    vi.mocked(fetchUsageSubjects).mockResolvedValue(SUBJECTS);
    vi.mocked(fetchUsage).mockResolvedValue(USAGE);
    const wrapper = mount(AdminPage);
    await flushPromises();

    expect(fetchUsage).not.toHaveBeenCalled();

    await wrapper.find('select').setValue('sub-1');
    await flushPromises();

    expect(fetchUsage).toHaveBeenCalledWith(30, 'sub-1');
    expect(wrapper.text()).toContain('900');
    expect(wrapper.text()).toContain('$0.003');
  });

  it('renders the empty-state placeholder and no dropdown when no subject has recorded usage', async () => {
    vi.mocked(fetchUsageSubjects).mockResolvedValue({ subjects: [] });
    const wrapper = mount(AdminPage);
    await flushPromises();

    expect(wrapper.text()).toContain('No subjects with recorded usage yet');
    expect(wrapper.find('select').exists()).toBe(false);
  });

  it('renders an error state when fetchUsageSubjects fails', async () => {
    vi.mocked(fetchUsageSubjects).mockRejectedValue(new Error('boom'));
    const wrapper = mount(AdminPage);
    await flushPromises();

    expect(wrapper.find('[role="alert"]').exists()).toBe(true);
    expect(wrapper.text()).toContain('Could not load subjects');
    expect(wrapper.text()).toContain('boom');
  });

  it('renders the second selection when its usage resolves after a later selection was already made', async () => {
    // Regression test for the :key-based remount contract in AdminPage.vue's
    // template: switching subjects destroys the old UsagePage instance
    // rather than reusing it, so a late-resolving fetch from the FIRST
    // selection must not clobber the SECOND selection's rendered totals.
    vi.mocked(fetchUsageSubjects).mockResolvedValue(SUBJECTS);

    let resolveFirst!: (value: UsageResponse) => void;
    let resolveSecond!: (value: UsageResponse) => void;
    const firstPromise = new Promise<UsageResponse>((resolve) => {
      resolveFirst = resolve;
    });
    const secondPromise = new Promise<UsageResponse>((resolve) => {
      resolveSecond = resolve;
    });
    vi.mocked(fetchUsage).mockImplementation((_days, subject) => {
      if (subject === 'sub-1') return firstPromise;
      if (subject === 'sub-2') return secondPromise;
      throw new Error(`unexpected subject: ${String(subject)}`);
    });

    const wrapper = mount(AdminPage);
    await flushPromises();

    await wrapper.find('select').setValue('sub-1');
    await flushPromises();
    await wrapper.find('select').setValue('sub-2');
    await flushPromises();

    // Resolve out of order: the orphaned first selection's fetch settles
    // after the second selection's fetch has already been kicked off.
    resolveSecond({
      ...USAGE,
      subject: 'sub-2',
      totals: { ...USAGE.totals, estimated_cost_usd: 0.099 },
    });
    await flushPromises();
    resolveFirst({
      ...USAGE,
      subject: 'sub-1',
      totals: { ...USAGE.totals, estimated_cost_usd: 0.001 },
    });
    await flushPromises();

    expect(fetchUsage).toHaveBeenCalledWith(30, 'sub-1');
    expect(fetchUsage).toHaveBeenCalledWith(30, 'sub-2');
    expect(wrapper.text()).toContain('$0.099');
    expect(wrapper.text()).not.toContain('$0.001');
  });
});
