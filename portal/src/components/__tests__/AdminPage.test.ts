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
import type { VueWrapper } from '@vue/test-utils';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type {
  AnnotationMismatch,
  AnnotationMismatchesReport,
  CredmonStatus,
  LintServiceStatus,
  MaintenanceStatus,
  ToolMappingDrift,
  ToolMappingDriftReport,
  UsageResponse,
  UsageSubjectsResponse,
} from '../../lib/api';

// The usage view draws a chart; jsdom has no canvas.
vi.mock('chart.js', () => ({
  Chart: class {
    static register = vi.fn();
  },
  BarController: {},
  BarElement: {},
  CategoryScale: {},
  LinearScale: {},
  Tooltip: {},
}));
vi.mock('basecoat-css/chart', () => ({}));

vi.mock('../../lib/api', () => ({
  fetchUsage: vi.fn(),
  fetchCatalog: vi.fn(async () => ({ servers: [] })),
  fetchUsageSubjects: vi.fn(),
  fetchMaintenanceStatus: vi.fn(),
  setMaintenanceStatus: vi.fn(),
  fetchAnnotationMismatches: vi.fn(),
  fetchToolMappingDrift: vi.fn(),
  fetchCredmonStatus: vi.fn(),
  runCredmonSync: vi.fn(),
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
  AccessDeniedError,
  fetchAnnotationMismatches,
  fetchCredmonStatus,
  fetchMaintenanceStatus,
  fetchToolMappingDrift,
  fetchUsage,
  fetchUsageSubjects,
  runCredmonSync,
  SessionExpiredError,
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

const CREDMON_DISABLED: CredmonStatus = {
  enabled: false,
  kinds: [],
  service_prefix: '',
  interval_seconds: null,
  last_run: null,
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

const OBSERVED_AT = 1_700_000_000;
const RETENTION_SECONDS = 86_400;

/** Every configured service observed at OBSERVED_AT, unless *observed* is false (none observed). */
function lintServices(observed = true): LintServiceStatus[] {
  return ['ami', 'rucio'].map((service) => ({
    service,
    last_observed: observed ? OBSERVED_AT : null,
  }));
}

function mismatchReport(
  mismatches: AnnotationMismatch[],
  services: LintServiceStatus[] = lintServices(),
): AnnotationMismatchesReport {
  return { retention_seconds: RETENTION_SECONDS, services, mismatches };
}

function driftReport(
  drift: ToolMappingDrift[],
  services: LintServiceStatus[] = lintServices(),
): ToolMappingDriftReport {
  return { retention_seconds: RETENTION_SECONDS, services, drift };
}

beforeEach(() => {
  vi.restoreAllMocks();
  vi.clearAllMocks();
  (window as unknown as { basecoat: unknown }).basecoat = { chart: vi.fn() };
  window.matchMedia = vi.fn().mockReturnValue({ matches: false }) as typeof window.matchMedia;
  // Every test mounts the full AdminPage, which always fetches annotation
  // mismatches on mount regardless of which section a given test is
  // exercising -- default to the empty-and-harmless case so tests focused
  // on the usage/maintenance sections don't have to know about this one.
  vi.mocked(fetchAnnotationMismatches).mockResolvedValue(mismatchReport([]));
  vi.mocked(fetchToolMappingDrift).mockResolvedValue(driftReport([]));
  vi.mocked(fetchCredmonStatus).mockResolvedValue(CREDMON_DISABLED);
});

/** Click Enable, then the dialog's confirm button (enabling affects every user). */
async function enableAndConfirm(wrapper: VueWrapper): Promise<void> {
  await wrapper.get('[data-af-maintenance-enable]').trigger('click');
  await wrapper.get('dialog .btn.af-danger').trigger('click');
  await flushPromises();
}

function reloadButton(wrapper: VueWrapper) {
  return wrapper.findAll('button').find((b) => b.text() === 'Reload') ?? wrapper.find('.none');
}

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

    expect(wrapper.get('[data-af-maintenance-status]').text()).toBe('Off');
  });

  it('shows reason/enabled_by when enabled', async () => {
    vi.mocked(fetchMaintenanceStatus).mockResolvedValue(ENABLED);
    const wrapper = mount(AdminPage);
    await flushPromises();

    expect(wrapper.get('[data-af-maintenance-status]').text()).toContain('On');
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
    await enableAndConfirm(wrapper);

    expect(setMaintenanceStatus).toHaveBeenCalledWith(true, 'Scheduled Postgres upgrade');
    expect(wrapper.get('[data-af-maintenance-status]').text()).toContain('On');
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
    expect(wrapper.get('[data-af-maintenance-status]').text()).toBe('Off');
  });

  it('surfaces a 403 from the POST as an access-denied-style message', async () => {
    vi.mocked(fetchMaintenanceStatus).mockResolvedValue(DISABLED);
    const { APIError } = await import('../../lib/api');
    vi.mocked(setMaintenanceStatus).mockRejectedValue(new APIError(403, 'Forbidden', '{}'));
    const wrapper = mount(AdminPage);
    await flushPromises();

    await enableAndConfirm(wrapper);

    expect(wrapper.find('[role="alert"]').exists()).toBe(true);
    expect(wrapper.text().toLowerCase()).toContain('access');
  });

  it('surfaces a 409 from the POST as a retry-prompting message', async () => {
    vi.mocked(fetchMaintenanceStatus).mockResolvedValue(DISABLED);
    const { APIError } = await import('../../lib/api');
    vi.mocked(setMaintenanceStatus).mockRejectedValue(new APIError(409, 'Conflict', '{}'));
    const wrapper = mount(AdminPage);
    await flushPromises();

    await enableAndConfirm(wrapper);

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

    await enableAndConfirm(wrapper);

    expect(wrapper.text()).toContain('a very specific broker detail');
  });

  it('shows the same dedicated Reload UI as the Usage section when the toggle POST session expires', async () => {
    vi.mocked(fetchMaintenanceStatus).mockResolvedValue(DISABLED);
    const { SessionExpiredError } = await import('../../lib/api');
    vi.mocked(setMaintenanceStatus).mockRejectedValue(new SessionExpiredError());
    const wrapper = mount(AdminPage);
    await flushPromises();

    await enableAndConfirm(wrapper);

    expect(wrapper.text()).toContain('Session expired');
    expect(reloadButton(wrapper).exists()).toBe(true);
  });
});

describe('AdminPage annotation mismatches', () => {
  const MISMATCH: AnnotationMismatch = {
    service: 'rucio',
    tool: 'rucio_list_dids',
    declared_read_only_hint: false,
    resolved_action_type: 'read',
    resolved_via: 'default',
    permission: 'read_data',
  };

  beforeEach(() => {
    // These tests don't exercise the usage/maintenance sections -- keep
    // them harmless empty states so their own assertions can't bleed in.
    vi.mocked(fetchUsageSubjects).mockResolvedValue({ subjects: [] });
    vi.mocked(fetchMaintenanceStatus).mockResolvedValue(DISABLED);
  });

  it('shows the empty-state placeholder when there are no mismatches', async () => {
    vi.mocked(fetchAnnotationMismatches).mockResolvedValue(mismatchReport([]));
    const wrapper = mount(AdminPage);
    await flushPromises();

    expect(wrapper.text()).toContain('No mismatches');
  });

  it('renders a row per mismatch with the declared/resolved/permission columns', async () => {
    vi.mocked(fetchAnnotationMismatches).mockResolvedValue(mismatchReport([MISMATCH]));
    const wrapper = mount(AdminPage);
    await flushPromises();

    const text = wrapper.text();
    expect(text).toContain('rucio');
    expect(text).toContain('rucio_list_dids');
    expect(text).toContain('readOnlyHint=false');
    expect(text).toContain('Read data');
    expect(wrapper.find('td[title="read_data"]').exists()).toBe(true);
  });

  it.each([
    ['target_action_types', 'target_action_types glob override'],
    ['permission', 'permission Read data'],
    ['default', 'default fallback'],
  ])('describes how %s was resolved', async (via, label) => {
    vi.mocked(fetchAnnotationMismatches).mockResolvedValue(
      mismatchReport([{ ...MISMATCH, resolved_via: via }]),
    );
    const wrapper = mount(AdminPage);
    await flushPromises();

    expect(wrapper.text()).toContain(label);
  });

  it('labels the columns by what they hold and explains the table', async () => {
    vi.mocked(fetchAnnotationMismatches).mockResolvedValue(mismatchReport([MISMATCH]));
    const wrapper = mount(AdminPage);
    await flushPromises();

    const text = wrapper.text();
    expect(text).toContain('Backend readOnlyHint');
    expect(text).toContain('Broker action_type');
    expect(text).toContain('Visibility only');
  });

  it('renders an error state when fetchAnnotationMismatches fails', async () => {
    vi.mocked(fetchAnnotationMismatches).mockRejectedValue(new Error('boom'));
    const wrapper = mount(AdminPage);
    await flushPromises();

    expect(wrapper.text()).toContain('Could not load annotation mismatches');
  });

  it('surfaces a 403 as an access-not-yet-granted message', async () => {
    vi.mocked(fetchAnnotationMismatches).mockRejectedValue(
      new AccessDeniedError('admin group required', 'corr-1'),
    );
    const wrapper = mount(AdminPage);
    await flushPromises();

    expect(wrapper.text()).toContain('Access not yet granted');
    expect(wrapper.text()).toContain('admin group required');
  });

  it('shows the dedicated Reload UI on a session-expired fetch', async () => {
    vi.mocked(fetchAnnotationMismatches).mockRejectedValue(new SessionExpiredError());
    const wrapper = mount(AdminPage);
    await flushPromises();

    expect(wrapper.text()).toContain('Session expired');
    expect(reloadButton(wrapper).exists()).toBe(true);
  });
});

describe('AdminPage tool mapping drift', () => {
  const DRIFT: ToolMappingDrift = {
    service: 'condor_service',
    prefix: 'condor',
    advertised: 2,
    routable: 2,
    unmapped: ['condor_submit_job'],
    stale: ['condor_old_tool'],
    unroutable: [],
  };
  // An apply_namespace: false backend that renamed every tool away from the
  // configured prefix: nothing routes, every mapped key is stale.
  const RENAMED: ToolMappingDrift = {
    service: 'atlas_search_service',
    prefix: 'atlas_opensearch',
    advertised: 2,
    routable: 0,
    unmapped: [],
    stale: ['atlas_opensearch_query', 'atlas_opensearch_search'],
    unroutable: ['aos_query', 'aos_search'],
  };

  beforeEach(() => {
    vi.mocked(fetchUsageSubjects).mockResolvedValue({ subjects: [] });
    vi.mocked(fetchMaintenanceStatus).mockResolvedValue(DISABLED);
  });

  it('shows the empty-state placeholder when nothing has drifted', async () => {
    const wrapper = mount(AdminPage);
    await flushPromises();

    expect(wrapper.text()).toContain('No tool mapping drift');
  });

  it('renders unmapped and stale tools per service', async () => {
    vi.mocked(fetchToolMappingDrift).mockResolvedValue(driftReport([DRIFT]));
    const wrapper = mount(AdminPage);
    await flushPromises();

    const text = wrapper.text();
    expect(text).toContain('condor_service');
    expect(text).toContain('condor_submit_job');
    expect(text).toContain('condor_old_tool');
  });

  it('renders unroutable tools with the expected prefix and routable count', async () => {
    vi.mocked(fetchToolMappingDrift).mockResolvedValue(driftReport([RENAMED]));
    const wrapper = mount(AdminPage);
    await flushPromises();

    const text = wrapper.text();
    expect(text).toContain('Unroutable (prefix mismatch)');
    expect(text).toContain('atlas_search_service');
    expect(text).toContain('Expected atlas_opensearch_*');
    expect(wrapper.findAll('[data-af-drift-unroutable] li').map((li) => li.text())).toEqual([
      'aos_query',
      'aos_search',
    ]);
    expect(text).toContain('0 / 2');
  });

  it('lists every tool name of a drift column as its own item, never joined', async () => {
    vi.mocked(fetchToolMappingDrift).mockResolvedValue(
      driftReport([
        {
          ...DRIFT,
          unmapped: ['condor_create_output_download_url', 'condor_doc_guide'],
          stale: ['condor_condor_doc_search'],
        },
      ]),
    );
    const wrapper = mount(AdminPage);
    await flushPromises();

    const items = (selector: string) => wrapper.findAll(`${selector} li`).map((li) => li.text());
    expect(items('[data-af-drift-unmapped]')).toEqual([
      'condor_create_output_download_url',
      'condor_doc_guide',
    ]);
    expect(items('[data-af-drift-stale]')).toEqual(['condor_condor_doc_search']);
  });

  it('collapses a long drift list behind a count', async () => {
    const many = Array.from({ length: 10 }, (_, i) => `condor_tool_${i}`);
    vi.mocked(fetchToolMappingDrift).mockResolvedValue(driftReport([{ ...DRIFT, unmapped: many }]));
    const wrapper = mount(AdminPage);
    await flushPromises();

    expect(wrapper.findAll('[data-af-drift-unmapped] li')).toHaveLength(3);
    expect(wrapper.get('[data-af-drift-unmapped] button').text()).toBe('7 more');
  });

  it('renders an error state when fetchToolMappingDrift fails', async () => {
    vi.mocked(fetchToolMappingDrift).mockRejectedValue(new Error('boom'));
    const wrapper = mount(AdminPage);
    await flushPromises();

    expect(wrapper.text()).toContain('Could not load tool mapping drift');
  });
});

describe('AdminPage maintenance confirmation', () => {
  beforeEach(() => {
    vi.mocked(fetchUsageSubjects).mockResolvedValue({ subjects: [] });
    vi.mocked(fetchMaintenanceStatus).mockResolvedValue(DISABLED);
  });

  it('asks before enabling and does not call the API until confirmed', async () => {
    vi.mocked(setMaintenanceStatus).mockResolvedValue(ENABLED);
    const wrapper = mount(AdminPage);
    await flushPromises();

    await wrapper.get('[data-af-maintenance-reason]').setValue('Postgres upgrade');
    await wrapper.get('[data-af-maintenance-enable]').trigger('click');

    expect(setMaintenanceStatus).not.toHaveBeenCalled();
    const dialog = wrapper.get('dialog');
    expect(dialog.text()).toContain('Enable maintenance mode?');
    expect(dialog.text()).toContain('"Postgres upgrade"');

    await dialog.get('.btn.af-danger').trigger('click');
    await flushPromises();
    expect(setMaintenanceStatus).toHaveBeenCalledWith(true, 'Postgres upgrade');
  });

  it('cancelling the dialog leaves maintenance off', async () => {
    const wrapper = mount(AdminPage);
    await flushPromises();

    await wrapper.get('[data-af-maintenance-enable]').trigger('click');
    await wrapper.get('dialog .btn[data-variant="ghost"]').trigger('click');

    expect(setMaintenanceStatus).not.toHaveBeenCalled();
  });

  it('disables without asking', async () => {
    vi.mocked(fetchMaintenanceStatus).mockResolvedValue(ENABLED);
    vi.mocked(setMaintenanceStatus).mockResolvedValue(DISABLED);
    const wrapper = mount(AdminPage);
    await flushPromises();

    expect(wrapper.find('[data-af-maintenance-enable]').exists()).toBe(false);
    await wrapper.get('[data-af-maintenance-disable]').trigger('click');
    await flushPromises();
    expect(setMaintenanceStatus).toHaveBeenCalledWith(false);
  });
});

describe('AdminPage banner', () => {
  const MISMATCH: AnnotationMismatch = {
    service: 'rucio',
    tool: 'rucio_list_dids',
    declared_read_only_hint: false,
    resolved_action_type: 'read',
    resolved_via: 'default',
    permission: 'read_data',
  };

  beforeEach(() => {
    vi.mocked(fetchUsageSubjects).mockResolvedValue({ subjects: [] });
    vi.mocked(fetchMaintenanceStatus).mockResolvedValue(DISABLED);
  });

  it('is absent when nothing is wrong', async () => {
    const wrapper = mount(AdminPage);
    await flushPromises();
    expect(wrapper.find('[data-af-admin-banner]').exists()).toBe(false);
  });

  // The shell's maintenance bar (Base.astro) already tells every visitor, so
  // the page keeps the details in its Maintenance mode section instead of a
  // second banner.
  it('has no banner when only maintenance is on; the section carries the details', async () => {
    vi.mocked(fetchMaintenanceStatus).mockResolvedValue(ENABLED);
    const wrapper = mount(AdminPage);
    await flushPromises();

    expect(wrapper.find('[data-af-admin-banner]').exists()).toBe(false);
    const section = wrapper.get('#ap-maintenance');
    expect(section.text()).toContain('Scheduled Postgres upgrade');
    expect(section.text()).toContain('Everyone outside the admin group is refused');
  });

  it('is a warning with the count when mismatches or drift are found', async () => {
    vi.mocked(fetchAnnotationMismatches).mockResolvedValue(mismatchReport([MISMATCH]));
    const wrapper = mount(AdminPage);
    await flushPromises();

    const banner = wrapper.get('[data-af-admin-banner]');
    expect(banner.classes()).toContain('warn');
    expect(banner.attributes('role')).toBe('alert');
    expect(banner.text()).toContain('1 tool configuration issue found');
    expect(banner.text()).toContain('1 annotation mismatch');
  });

  it('shows only the warning when maintenance is on and issues exist', async () => {
    vi.mocked(fetchMaintenanceStatus).mockResolvedValue(ENABLED);
    vi.mocked(fetchAnnotationMismatches).mockResolvedValue(mismatchReport([MISMATCH]));
    const wrapper = mount(AdminPage);
    await flushPromises();

    expect(wrapper.findAll('[data-af-admin-banner]')).toHaveLength(1);
    expect(wrapper.get('[data-af-admin-banner]').classes()).toContain('warn');
    expect(wrapper.get('[data-af-maintenance-status]').text()).toContain('On');
  });
});

describe('AdminPage credmon', () => {
  const RUN = {
    outcome: 'partial',
    trigger: 'timer',
    holder: 'broker-0',
    started_at: 1756450000,
    finished_at: Math.floor(Date.now() / 1000) - 60,
    last_success_at: Math.floor(Date.now() / 1000) - 60,
    stored: { krb5: 3 },
    not_linked: {},
    skipped_no_posix: {},
    failed: { krb5: 1 },
    errors: ['example-user: refused'],
    errors_truncated: 2,
  };
  const ENABLED_CREDMON: CredmonStatus = {
    enabled: true,
    kinds: ['krb5'],
    service_prefix: 'condor_credd_',
    interval_seconds: 300,
    last_run: RUN as CredmonStatus['last_run'],
  };

  beforeEach(() => {
    vi.mocked(fetchUsageSubjects).mockResolvedValue({ subjects: [] });
    vi.mocked(fetchMaintenanceStatus).mockResolvedValue(DISABLED);
  });

  it('says it is not enabled when the broker has credmon off', async () => {
    const wrapper = mount(AdminPage);
    await flushPromises();
    expect(wrapper.text()).toContain('Not enabled on this broker');
  });

  it('shows the health as a status mark with its word, and the per-kind counts', async () => {
    vi.mocked(fetchCredmonStatus).mockResolvedValue(ENABLED_CREDMON);
    const wrapper = mount(AdminPage);
    await flushPromises();

    const health = wrapper.get('[data-af-credmon-health]');
    expect(health.find('.af-mark.warn').exists()).toBe(true);
    expect(health.text()).toBe('Needs attention');
    expect(wrapper.text()).toContain('condor_credd_krb5');
  });

  it('lists the last run errors, with the truncated count, in a disclosure', async () => {
    vi.mocked(fetchCredmonStatus).mockResolvedValue(ENABLED_CREDMON);
    const wrapper = mount(AdminPage);
    await flushPromises();

    const toggle = wrapper
      .findAll('button')
      .find((b) => b.text().startsWith('Errors from the last run'));
    expect(toggle?.text()).toContain('(3)');
    expect(wrapper.text()).toContain('example-user: refused');
    expect(wrapper.text()).toContain('+2 more not shown.');
  });

  it('runs a sync, reloads the status and disables the button meanwhile', async () => {
    vi.mocked(fetchCredmonStatus).mockResolvedValue(ENABLED_CREDMON);
    let finish!: (run: NonNullable<CredmonStatus['last_run']>) => void;
    vi.mocked(runCredmonSync).mockReturnValue(
      new Promise((resolve) => {
        finish = resolve;
      }),
    );
    const wrapper = mount(AdminPage);
    await flushPromises();

    await wrapper.get('[data-af-credmon-sync]').trigger('click');
    expect(wrapper.get('[data-af-credmon-sync]').attributes('disabled')).toBeDefined();
    expect(wrapper.get('[data-af-credmon-sync]').text()).toBe('Syncing…');

    finish(RUN as NonNullable<CredmonStatus['last_run']>);
    await flushPromises();
    expect(fetchCredmonStatus).toHaveBeenCalledTimes(2);
    expect(wrapper.get('[data-af-credmon-sync]').text()).toBe('Run sync now');
  });

  it('surfaces a failed sync in an alert', async () => {
    vi.mocked(fetchCredmonStatus).mockResolvedValue(ENABLED_CREDMON);
    vi.mocked(runCredmonSync).mockRejectedValue(new Error('credd unreachable'));
    const wrapper = mount(AdminPage);
    await flushPromises();

    await wrapper.get('[data-af-credmon-sync]').trigger('click');
    await flushPromises();
    expect(wrapper.get('[role="alert"]').text()).toContain('credd unreachable');
  });
});

describe('AdminPage lint observation status (issue #332)', () => {
  const MISMATCH: AnnotationMismatch = {
    service: 'rucio',
    tool: 'rucio_list_dids',
    declared_read_only_hint: false,
    resolved_action_type: 'read',
    resolved_via: 'default',
    permission: 'read_data',
  };

  beforeEach(() => {
    vi.mocked(fetchUsageSubjects).mockResolvedValue({ subjects: [] });
    vi.mocked(fetchMaintenanceStatus).mockResolvedValue(DISABLED);
  });

  it('says "not yet observed since" rather than "clean" when nothing was observed', async () => {
    vi.mocked(fetchAnnotationMismatches).mockResolvedValue(mismatchReport([], lintServices(false)));
    vi.mocked(fetchToolMappingDrift).mockResolvedValue(driftReport([], lintServices(false)));
    const wrapper = mount(AdminPage);
    await flushPromises();

    expect(wrapper.find('#ap-mismatches').text()).toContain('Not yet observed since');
    expect(wrapper.find('#ap-mismatches').text()).not.toContain('No mismatches.');
    expect(wrapper.find('#ap-drift').text()).toContain('Not yet observed since');
    expect(wrapper.find('#ap-drift').text()).not.toContain('No tool mapping drift.');
  });

  it('reads "No mismatches." only once every service has been observed', async () => {
    vi.mocked(fetchAnnotationMismatches).mockResolvedValue(mismatchReport([]));
    const wrapper = mount(AdminPage);
    await flushPromises();

    const section = wrapper.find('#ap-mismatches').text();
    expect(section).toContain('No mismatches.');
    expect(section).not.toContain('Not yet observed');
  });

  it('qualifies an empty table when only some services were observed', async () => {
    vi.mocked(fetchAnnotationMismatches).mockResolvedValue(
      mismatchReport(
        [],
        [
          { service: 'ami', last_observed: null },
          { service: 'rucio', last_observed: OBSERVED_AT },
        ],
      ),
    );
    const wrapper = mount(AdminPage);
    await flushPromises();

    const section = wrapper.find('#ap-mismatches').text();
    expect(section).toContain('No mismatches among the observed services');
    expect(section).not.toContain('No mismatches.');
  });

  it('lists when each service was last observed, or that it was not', async () => {
    vi.mocked(fetchAnnotationMismatches).mockResolvedValue(
      mismatchReport(
        [MISMATCH],
        [
          { service: 'ami', last_observed: null },
          { service: 'rucio', last_observed: OBSERVED_AT },
        ],
      ),
    );
    const wrapper = mount(AdminPage);
    await flushPromises();

    const rows = wrapper.findAll('#ap-mismatches [data-af-observed] li').map((li) => li.text());
    expect(rows).toHaveLength(2);
    expect(rows[0]).toMatch(/^ami\b.*not yet observed since/i);
    expect(rows[1]).toMatch(/^rucio\b.*observed/i);
    expect(rows[1]).not.toMatch(/not yet observed/i);
    expect(wrapper.find('#ap-mismatches').text()).toContain('rucio_list_dids');
  });

  it('shows the same observation list in the drift section', async () => {
    vi.mocked(fetchToolMappingDrift).mockResolvedValue(driftReport([], lintServices(false)));
    const wrapper = mount(AdminPage);
    await flushPromises();

    expect(wrapper.findAll('#ap-drift [data-af-observed] li')).toHaveLength(2);
  });
});
