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

import { fetchEntitlements, fetchPermissions, type PermissionsResponse } from '../../lib/api';
import EntitlementsPage from '../EntitlementsPage.vue';

const ENTITLEMENTS = {
  group_permissions: {
    'example-users': ['read_data', 'submit_jobs'],
    'example-guests': ['read_data'],
  },
};

const PERMISSIONS: PermissionsResponse = {
  subject: 'example-subject',
  groups: ['example-users', 'unrelated-group'],
  grants: [
    { permission: 'read_data', targets: ['rucio'], action_types: ['read'] },
    { permission: 'submit_jobs', targets: ['condor'], action_types: ['read', 'state_change'] },
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

    const read = wrapper.find('[aria-label="example-users grants read_data (read)"]');
    const write = wrapper.find('[aria-label="example-users grants submit_jobs (state-changing)"]');
    const none = wrapper.find('[aria-label="example-guests does not grant submit_jobs"]');
    expect(read.exists()).toBe(true);
    expect(write.exists()).toBe(true);
    expect(none.exists()).toBe(true);
  });

  it('names the You column cells by what the caller holds', async () => {
    const wrapper = await mountPage({ ...PERMISSIONS, grants: [PERMISSIONS.grants[0]] });

    expect(wrapper.find('[aria-label="You hold read_data (read)"]').exists()).toBe(true);
    expect(wrapper.find('[aria-label="You do not hold submit_jobs"]').exists()).toBe(true);
  });

  it('keeps the matrix a real table with scoped headers', async () => {
    const wrapper = await mountPage();

    const colHeads = wrapper.findAll('thead th[scope="col"]');
    // Permission, You, then one per group.
    expect(colHeads).toHaveLength(4);
    expect(wrapper.findAll('tbody th[scope="row"]')).toHaveLength(2);
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
    vi.mocked(fetchEntitlements).mockResolvedValue({ group_permissions: {} });
    vi.mocked(fetchPermissions).mockResolvedValue({ ...PERMISSIONS, grants: [] });
    const wrapper = mount(EntitlementsPage);
    await flushPromises();

    expect(wrapper.find('.empty').text()).toContain('No permissions are declared');
    expect(wrapper.find('table').exists()).toBe(false);
  });
});
