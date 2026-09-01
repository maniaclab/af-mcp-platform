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
import type { MaintenanceStatus, UsageResponse, UsageSubjectsResponse } from '../../lib/api';

vi.mock('../../lib/api', () => ({
  fetchUsage: vi.fn(),
  fetchUsageSubjects: vi.fn(),
  fetchMaintenanceStatus: vi.fn(),
  setMaintenanceStatus: vi.fn(),
  SessionExpiredError: class SessionExpiredError extends Error {},
  AccessDeniedError: class AccessDeniedError extends Error {},
  APIError: class APIError extends Error {
    constructor(
      public readonly status: number,
      public readonly statusText: string,
      public readonly body: string,
    ) {
      super(`${status} ${statusText}: ${body}`);
      this.name = 'APIError';
    }
  },
}));

import {
  fetchMaintenanceStatus,
  fetchUsage,
  fetchUsageSubjects,
  setMaintenanceStatus,
} from '../../lib/api';
import AdminPage from '../AdminPage.vue';

const DISABLED: MaintenanceStatus = {
  enabled: false,
  reason: null,
  enabled_by: null,
  enabled_at: null,
  enabled_by_unixname: null,
  enabled_by_email: '',
};

const ENABLED: MaintenanceStatus = {
  enabled: true,
  reason: 'Scheduled Postgres upgrade',
  enabled_by: 'sub-admin',
  enabled_at: 1756450000,
  enabled_by_unixname: 'gstark',
  enabled_by_email: 'gstark@example.org',
};

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

describe('AdminPage maintenance mode', () => {
  beforeEach(() => {
    // These tests don't exercise the usage dropdown -- keep it a harmless
    // empty state so its own assertions can't bleed into these.
    vi.mocked(fetchUsageSubjects).mockResolvedValue({ subjects: [] });
  });

  it('shows the current maintenance status when disabled', async () => {
    vi.mocked(fetchMaintenanceStatus).mockResolvedValue(DISABLED);
    const wrapper = mount(AdminPage);
    await flushPromises();

    expect(wrapper.text()).toContain('Disabled');
  });

  it('shows reason/enabled_by when enabled', async () => {
    vi.mocked(fetchMaintenanceStatus).mockResolvedValue(ENABLED);
    const wrapper = mount(AdminPage);
    await flushPromises();

    expect(wrapper.text()).toContain('Enabled');
    expect(wrapper.text()).toContain('Scheduled Postgres upgrade');
    expect(wrapper.text()).toContain('gstark');
  });

  it('falls back to the bare enabled_by subject when the principal cache could not resolve it', async () => {
    vi.mocked(fetchMaintenanceStatus).mockResolvedValue({
      ...ENABLED,
      enabled_by_unixname: null,
      enabled_by_email: '',
    });
    const wrapper = mount(AdminPage);
    await flushPromises();

    expect(wrapper.text()).toContain('sub-admin');
  });

  it('enabling calls setMaintenanceStatus with the reason input and updates the displayed status', async () => {
    vi.mocked(fetchMaintenanceStatus).mockResolvedValue(DISABLED);
    vi.mocked(setMaintenanceStatus).mockResolvedValue(ENABLED);
    const wrapper = mount(AdminPage);
    await flushPromises();

    await wrapper.find('[data-af-maintenance-reason]').setValue('Scheduled Postgres upgrade');
    await wrapper.find('[data-af-maintenance-enable]').trigger('click');
    await flushPromises();

    expect(setMaintenanceStatus).toHaveBeenCalledWith(true, 'Scheduled Postgres upgrade');
    expect(wrapper.text()).toContain('Enabled');
    expect(wrapper.text()).toContain('gstark');
  });

  it('disabling calls setMaintenanceStatus(false) and updates the displayed status', async () => {
    vi.mocked(fetchMaintenanceStatus).mockResolvedValue(ENABLED);
    vi.mocked(setMaintenanceStatus).mockResolvedValue(DISABLED);
    const wrapper = mount(AdminPage);
    await flushPromises();

    await wrapper.find('[data-af-maintenance-disable]').trigger('click');
    await flushPromises();

    expect(setMaintenanceStatus).toHaveBeenCalledWith(false);
    expect(wrapper.text()).toContain('Disabled');
  });

  it('surfaces a 403 from the POST as an access-denied-style message', async () => {
    vi.mocked(fetchMaintenanceStatus).mockResolvedValue(DISABLED);
    const { APIError } = await import('../../lib/api');
    vi.mocked(setMaintenanceStatus).mockRejectedValue(new APIError(403, 'Forbidden', '{}'));
    const wrapper = mount(AdminPage);
    await flushPromises();

    await wrapper.find('[data-af-maintenance-enable]').trigger('click');
    await flushPromises();

    expect(wrapper.find('[role="alert"]').exists()).toBe(true);
    expect(wrapper.text().toLowerCase()).toContain('access');
  });

  it('surfaces a 409 from the POST as a retry-prompting message', async () => {
    vi.mocked(fetchMaintenanceStatus).mockResolvedValue(DISABLED);
    const { APIError } = await import('../../lib/api');
    vi.mocked(setMaintenanceStatus).mockRejectedValue(new APIError(409, 'Conflict', '{}'));
    const wrapper = mount(AdminPage);
    await flushPromises();

    await wrapper.find('[data-af-maintenance-enable]').trigger('click');
    await flushPromises();

    expect(wrapper.find('[role="alert"]').exists()).toBe(true);
    expect(wrapper.text().toLowerCase()).toContain('retry');
  });

  it('shows a generic error when fetchMaintenanceStatus fails', async () => {
    vi.mocked(fetchMaintenanceStatus).mockRejectedValue(new Error('network down'));
    const wrapper = mount(AdminPage);
    await flushPromises();

    expect(wrapper.text()).toContain('network down');
  });

  it("prefers the broker's actual detail text over the canned 403/409 messages", async () => {
    vi.mocked(fetchMaintenanceStatus).mockResolvedValue(DISABLED);
    const { APIError } = await import('../../lib/api');
    vi.mocked(setMaintenanceStatus).mockRejectedValue(
      new APIError(409, 'Conflict', JSON.stringify({ detail: 'a very specific broker detail' })),
    );
    const wrapper = mount(AdminPage);
    await flushPromises();

    await wrapper.find('[data-af-maintenance-enable]').trigger('click');
    await flushPromises();

    expect(wrapper.text()).toContain('a very specific broker detail');
  });

  it('shows the same dedicated Reload UI as the Usage section when the toggle POST session expires', async () => {
    vi.mocked(fetchMaintenanceStatus).mockResolvedValue(DISABLED);
    const { SessionExpiredError } = await import('../../lib/api');
    vi.mocked(setMaintenanceStatus).mockRejectedValue(new SessionExpiredError());
    const wrapper = mount(AdminPage);
    await flushPromises();

    await wrapper.find('[data-af-maintenance-enable]').trigger('click');
    await flushPromises();

    expect(wrapper.text()).toContain('Session expired');
    expect(wrapper.find('.ap__reload').exists()).toBe(true);
  });
});
