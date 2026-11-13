/**
 * Component tests for EntitlementsPage.vue — the permission x group matrix.
 *
 * Every cell is a mark whose accessible name must tell apart the three
 * states (granted read, granted state-changing, not granted), because the
 * shape and colour of the mark alone cannot be relied on. The summary
 * sentence reflects /v1/permissions, and a failed fetch surfaces as an alert.
 */
import { flushPromises, mount } from '@vue/test-utils';
import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../lib/api', () => ({
  fetchEntitlements: vi.fn(),
  fetchPermissions: vi.fn(),
  SessionExpiredError: class SessionExpiredError extends Error {},
  AccessDeniedError: class AccessDeniedError extends Error {},
}));

import {
  fetchEntitlements,
  fetchPermissions,
  type EntitlementsResponse,
  type PermissionsResponse,
} from '../../lib/api';
import EntitlementsPage from '../EntitlementsPage.vue';

// The broker's catalog order is deliberately not "reads first": the page must
// sort by kind itself, keeping broker order within each kind.
const ENTITLEMENTS: EntitlementsResponse = {
  group_permissions: {
    'example-users': ['read_data', 'submit_jobs', 'example_exec_jobs'],
    'example-guests': ['read_data'],
  },
  permissions: [
    { name: 'submit_jobs', action_type: 'state_change', description: 'Submit compute jobs' },
    { name: 'read_data', action_type: 'read', description: 'Read datasets from data stores' },
    { name: 'example_exec_jobs', action_type: 'state_change', description: null },
    { name: 'example_peek', action_type: 'read', description: null },
  ],
};

const PERMISSIONS: PermissionsResponse = {
  subject: 'example-subject',
  groups: ['example-users', 'unrelated-group'],
  grants: [
    { permission: 'read_data', targets: ['rucio'], action_types: ['read'] },
    { permission: 'submit_jobs', targets: ['condor'], action_types: ['state_change'] },
  ],
};

async function mountPage(permissions = PERMISSIONS) {
  vi.mocked(fetchEntitlements).mockResolvedValue(ENTITLEMENTS);
  vi.mocked(fetchPermissions).mockResolvedValue(permissions);
  const wrapper = mount(EntitlementsPage);
  await flushPromises();
  return wrapper;
}

beforeEach(() => {
  vi.restoreAllMocks();
});

describe('EntitlementsPage', () => {
  it('gives granted-read, granted-state-changing and not-granted cells distinct names', async () => {
    const wrapper = await mountPage();

    const read = wrapper.find('[aria-label="example-users grants Read data (read)"]');
    const write = wrapper.find('[aria-label="example-users grants Submit jobs (state-changing)"]');
    const none = wrapper.find('[aria-label="example-guests does not grant Submit jobs"]');
    expect(read.exists()).toBe(true);
    expect(write.exists()).toBe(true);
    expect(none.exists()).toBe(true);
  });

  it('names the You column cells by what the caller holds', async () => {
    const wrapper = await mountPage({ ...PERMISSIONS, grants: [PERMISSIONS.grants[0]] });

    expect(wrapper.find('[aria-label="You hold Read data (read)"]').exists()).toBe(true);
    expect(wrapper.find('[aria-label="You do not hold Submit jobs"]').exists()).toBe(true);
  });

  it('keeps the matrix a real table with scoped headers', async () => {
    const wrapper = await mountPage();

    const colHeads = wrapper.findAll('thead th[scope="col"]');
    // Permission, You, then one per group.
    expect(colHeads).toHaveLength(4);
    // Only permissions some group (or the caller) holds get a row.
    expect(wrapper.findAll('tbody th[scope="row"]')).toHaveLength(3);
  });

  it('lists only the recognized groups in the summary', async () => {
    const wrapper = await mountPage();

    const summary = wrapper.find('[data-testid="ep-summary"]');
    expect(summary.text()).toContain('example-users');
    expect(summary.text()).not.toContain('unrelated-group');
  });

  it('says so when none of the caller groups are recognized', async () => {
    const wrapper = await mountPage({ ...PERMISSIONS, groups: ['unrelated-group'] });

    expect(wrapper.find('[data-testid="ep-summary"]').text()).toContain(
      'None of your groups are recognized',
    );
  });

  it('renders the failure as an alert', async () => {
    vi.mocked(fetchEntitlements).mockRejectedValue(new Error('boom'));
    vi.mocked(fetchPermissions).mockResolvedValue(PERMISSIONS);
    const wrapper = mount(EntitlementsPage);
    await flushPromises();

    const alert = wrapper.find('[role="alert"]');
    expect(alert.exists()).toBe(true);
    expect(alert.text()).toContain('boom');
  });

  it('shows an empty state when the policy declares no permissions', async () => {
    vi.mocked(fetchEntitlements).mockResolvedValue({
      group_permissions: {},
      permissions: ENTITLEMENTS.permissions,
    });
    vi.mocked(fetchPermissions).mockResolvedValue({ ...PERMISSIONS, grants: [] });
    const wrapper = mount(EntitlementsPage);
    await flushPromises();

    expect(wrapper.find('.empty').text()).toContain('No permissions are declared');
    expect(wrapper.find('table').exists()).toBe(false);
  });

  it('shows a permission the portal has never heard of by the kind the broker sent', async () => {
    const wrapper = await mountPage();

    expect(
      wrapper
        .find('[aria-label="example-users grants Example exec jobs (state-changing)"]')
        .exists(),
    ).toBe(true);
    expect(
      wrapper.find('[aria-label="example-guests does not grant Example exec jobs"]').exists(),
    ).toBe(true);
  });

  it('lists reads first, then state-changing, each in broker order', async () => {
    const wrapper = await mountPage();

    const rows = wrapper.findAll('tbody th[scope="row"] .ep__perm-name').map((c) => c.text());
    expect(rows).toEqual(['Read data', 'Submit jobs', 'Example exec jobs']);
  });

  it('puts the heavier rule above the first state-changing row only', async () => {
    const wrapper = await mountPage();

    const rows = wrapper.findAll('tbody tr');
    expect(rows.map((r) => r.classes('ep__divider'))).toEqual([false, true, false]);
  });

  it('gives the broker description to a described permission', async () => {
    const wrapper = await mountPage();

    const row = wrapper.findAll('tbody tr')[0];
    expect(row.get('[role="tooltip"]').text()).toContain('Read datasets from data stores');
  });

  it('shows the label in plain text and the raw identifier in the info tooltip', async () => {
    const wrapper = await mountPage();

    const row = wrapper.findAll('tbody tr')[0];
    expect(row.get('.ep__perm-name').text()).toBe('Read data');
    const tip = row.get('[role="tooltip"]');
    expect(tip.get('code').text()).toBe('read_data');
    expect(tip.text()).toBe('read_data Read datasets from data stores');
  });

  it('gives a permission without a description the site-defined info text', async () => {
    const wrapper = await mountPage();

    const row = wrapper.findAll('tbody tr')[2];
    expect(row.find('button[aria-label="About Example exec jobs"]').exists()).toBe(true);
    expect(row.get('[role="tooltip"]').text()).toBe('example_exec_jobs Site-defined permission');
  });

  it('shows the error state, not a table, when the broker sends no permission catalog', async () => {
    vi.mocked(fetchEntitlements).mockResolvedValue({
      group_permissions: ENTITLEMENTS.group_permissions,
    } as never);
    vi.mocked(fetchPermissions).mockResolvedValue(PERMISSIONS);
    const wrapper = mount(EntitlementsPage);
    await flushPromises();

    const alert = wrapper.find('[role="alert"]');
    expect(alert.text()).toContain('permission catalog');
    expect(wrapper.find('table').exists()).toBe(false);
  });
});
