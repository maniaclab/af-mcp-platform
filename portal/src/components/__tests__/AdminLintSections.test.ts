/**
 * Component contract tests for AdminMismatchesSection.vue and
 * AdminDriftSection.vue: once loaded, each emits `count` with its number of
 * findings, which the admin page's banner adds up.
 */
import { flushPromises, mount } from '@vue/test-utils';
import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../lib/api', () => ({
  fetchAnnotationMismatches: vi.fn(),
  fetchToolMappingDrift: vi.fn(),
  SessionExpiredError: class SessionExpiredError extends Error {},
  AccessDeniedError: class AccessDeniedError extends Error {},
}));

import { fetchAnnotationMismatches, fetchToolMappingDrift } from '../../lib/api';
import AdminDriftSection from '../AdminDriftSection.vue';
import AdminMismatchesSection from '../AdminMismatchesSection.vue';

beforeEach(() => {
  vi.resetAllMocks();
});

describe('AdminMismatchesSection', () => {
  it('emits the mismatch count once loaded', async () => {
    vi.mocked(fetchAnnotationMismatches).mockResolvedValue({
      retention_seconds: 3600,
      services: [],
      mismatches: [
        {
          service: 'rucio',
          tool: 'rucio_a',
          declared_read_only_hint: true,
          resolved_action_type: 'state_change',
          resolved_via: 'default',
          permission: 'read_data',
        },
        {
          service: 'rucio',
          tool: 'rucio_b',
          declared_read_only_hint: false,
          resolved_action_type: 'read',
          resolved_via: 'default',
          permission: 'read_data',
        },
      ],
    });

    const wrapper = mount(AdminMismatchesSection);
    await flushPromises();

    expect(wrapper.emitted('count')).toEqual([[2]]);
  });

  it('emits nothing when the load fails', async () => {
    vi.mocked(fetchAnnotationMismatches).mockRejectedValue(new Error('boom'));

    const wrapper = mount(AdminMismatchesSection);
    await flushPromises();

    expect(wrapper.emitted('count')).toBeUndefined();
    expect(wrapper.get('[role="alert"]').text()).toContain('boom');
  });
});

describe('AdminDriftSection', () => {
  it('emits the drifting service count once loaded', async () => {
    vi.mocked(fetchToolMappingDrift).mockResolvedValue({
      retention_seconds: 3600,
      services: [],
      drift: [
        {
          service: 'ami',
          prefix: 'ami',
          advertised: 3,
          routable: 3,
          unmapped: ['ami_new'],
          stale: [],
          unroutable: [],
        },
      ],
    });

    const wrapper = mount(AdminDriftSection);
    await flushPromises();

    expect(wrapper.emitted('count')).toEqual([[1]]);
  });

  it('emits nothing when the load fails', async () => {
    vi.mocked(fetchToolMappingDrift).mockRejectedValue(new Error('boom'));

    const wrapper = mount(AdminDriftSection);
    await flushPromises();

    expect(wrapper.emitted('count')).toBeUndefined();
  });
});
