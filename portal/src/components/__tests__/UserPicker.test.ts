/**
 * Component tests for UserPicker.vue — the admin typeahead that finds a platform
 * user by name, username or email.
 *
 * The picker never loads a user list: it sends what was typed (debounced) to
 * GET /v1/admin/users and renders the few rows that come back. The API layer is
 * mocked; these tests pin the debounce, the states, the keyboard contract and
 * what is emitted on selection.
 */
import { flushPromises, mount } from '@vue/test-utils';
import type { VueWrapper } from '@vue/test-utils';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { AdminUser, AdminUserSearchResponse } from '../../lib/api';

vi.mock('../../lib/api', () => ({
  searchAdminUsers: vi.fn(),
}));

import { searchAdminUsers } from '../../lib/api';
import UserPicker from '../UserPicker.vue';

const DEBOUNCE_MS = 250;

function user(n: number, overrides: Partial<AdminUser> = {}): AdminUser {
  return {
    subject: `sub-${n}`,
    username: `user${n}`,
    email: `user${n}@example.org`,
    display_name: `User Number${n}`,
    last_seen: '2026-01-01T00:00:00Z',
    pat_count: 0,
    ...overrides,
  };
}

function response(
  users: AdminUser[],
  extra: Partial<AdminUserSearchResponse> = {},
): AdminUserSearchResponse {
  return { users, more: false, partial: false, ...extra };
}

async function type(wrapper: VueWrapper, text: string): Promise<void> {
  const input = wrapper.get('input[role="combobox"]');
  await input.setValue(text);
}

async function settle(): Promise<void> {
  await vi.advanceTimersByTimeAsync(DEBOUNCE_MS);
  await flushPromises();
}

beforeEach(() => {
  vi.useFakeTimers();
  vi.mocked(searchAdminUsers).mockReset();
});

afterEach(() => {
  vi.useRealTimers();
});

describe('UserPicker', () => {
  it('asks the user to type, and fetches nothing, until they do', async () => {
    const wrapper = mount(UserPicker, { props: { label: 'User', modelValue: null } });
    await wrapper.get('input').trigger('focus');
    await settle();

    expect(wrapper.text()).toContain('Type to search');
    expect(searchAdminUsers).not.toHaveBeenCalled();
  });

  it('debounces typing into a single search for the final text', async () => {
    vi.mocked(searchAdminUsers).mockResolvedValue(response([user(1)]));
    const wrapper = mount(UserPicker, { props: { label: 'User', modelValue: null } });

    await type(wrapper, 'a');
    await vi.advanceTimersByTimeAsync(DEBOUNCE_MS - 50);
    await type(wrapper, 'ad');
    await vi.advanceTimersByTimeAsync(DEBOUNCE_MS - 50);
    expect(searchAdminUsers).not.toHaveBeenCalled();
    await settle();

    expect(searchAdminUsers).toHaveBeenCalledTimes(1);
    expect(vi.mocked(searchAdminUsers).mock.calls[0][0]).toBe('ad');
  });

  it('shows name, username and email for each match', async () => {
    vi.mocked(searchAdminUsers).mockResolvedValue(response([user(1), user(2)]));
    const wrapper = mount(UserPicker, { props: { label: 'User', modelValue: null } });

    await type(wrapper, 'user');
    await settle();

    const options = wrapper.findAll('[role="option"]');
    expect(options).toHaveLength(2);
    expect(options[0].text()).toContain('User Number1');
    expect(options[0].text()).toContain('user1');
    expect(options[0].text()).toContain('user1@example.org');
  });

  it('says so when the search is truncated', async () => {
    vi.mocked(searchAdminUsers).mockResolvedValue(response([user(1), user(2)], { more: true }));
    const wrapper = mount(UserPicker, { props: { label: 'User', modelValue: null } });

    await type(wrapper, 'user');
    await settle();

    expect(wrapper.text()).toContain('2+ matches, refine your search');
  });

  it('says so when nobody matches', async () => {
    vi.mocked(searchAdminUsers).mockResolvedValue(response([]));
    const wrapper = mount(UserPicker, { props: { label: 'User', modelValue: null } });

    await type(wrapper, 'zzz');
    await settle();

    expect(wrapper.text()).toContain('No users found');
    expect(wrapper.findAll('[role="option"]')).toHaveLength(0);
  });

  it('warns that results may be incomplete while the directory warms up', async () => {
    vi.mocked(searchAdminUsers).mockResolvedValue(response([], { partial: true }));
    const wrapper = mount(UserPicker, { props: { label: 'User', modelValue: null } });

    await type(wrapper, 'zzz');
    await settle();

    expect(wrapper.text()).toContain('still loading');
  });

  it('shows the failure and keeps working', async () => {
    vi.mocked(searchAdminUsers).mockRejectedValueOnce(new Error('boom'));
    vi.mocked(searchAdminUsers).mockResolvedValueOnce(response([user(1)]));
    const wrapper = mount(UserPicker, { props: { label: 'User', modelValue: null } });

    await type(wrapper, 'user');
    await settle();
    expect(wrapper.text()).toContain('boom');

    await type(wrapper, 'user1');
    await settle();
    expect(wrapper.text()).not.toContain('boom');
    expect(wrapper.findAll('[role="option"]')).toHaveLength(1);
  });

  it('ignores a slow response to an earlier search', async () => {
    let resolveFirst!: (r: AdminUserSearchResponse) => void;
    vi.mocked(searchAdminUsers)
      .mockImplementationOnce(
        () =>
          new Promise<AdminUserSearchResponse>((resolve) => {
            resolveFirst = resolve;
          }),
      )
      .mockResolvedValueOnce(response([user(2)]));
    const wrapper = mount(UserPicker, { props: { label: 'User', modelValue: null } });

    await type(wrapper, 'user');
    await settle();
    await type(wrapper, 'user2');
    await settle();
    resolveFirst(response([user(1)]));
    await flushPromises();

    const options = wrapper.findAll('[role="option"]');
    expect(options).toHaveLength(1);
    expect(options[0].text()).toContain('user2');
  });

  it('selects with the keyboard and emits the user', async () => {
    vi.mocked(searchAdminUsers).mockResolvedValue(response([user(1), user(2)]));
    const wrapper = mount(UserPicker, { props: { label: 'User', modelValue: null } });
    await type(wrapper, 'user');
    await settle();
    const input = wrapper.get('input[role="combobox"]');

    await input.trigger('keydown', { key: 'ArrowDown' });
    await input.trigger('keydown', { key: 'ArrowDown' });
    const active = wrapper.get('[role="option"].active');
    expect(input.attributes('aria-activedescendant')).toBe(active.attributes('id'));
    await input.trigger('keydown', { key: 'Enter' });

    expect(wrapper.emitted('update:modelValue')).toEqual([[user(2)]]);
    expect(wrapper.find('[role="listbox"]').exists()).toBe(true);
    expect(input.attributes('aria-expanded')).toBe('false');
  });

  it('selects with a click', async () => {
    vi.mocked(searchAdminUsers).mockResolvedValue(response([user(1), user(2)]));
    const wrapper = mount(UserPicker, { props: { label: 'User', modelValue: null } });
    await type(wrapper, 'user');
    await settle();

    await wrapper.findAll('[role="option"]')[0].trigger('click');

    expect(wrapper.emitted('update:modelValue')).toEqual([[user(1)]]);
  });

  it('closes on Escape without selecting', async () => {
    vi.mocked(searchAdminUsers).mockResolvedValue(response([user(1)]));
    const wrapper = mount(UserPicker, { props: { label: 'User', modelValue: null } });
    await type(wrapper, 'user');
    await settle();
    const input = wrapper.get('input[role="combobox"]');

    await input.trigger('keydown', { key: 'Escape' });

    expect(input.attributes('aria-expanded')).toBe('false');
    expect(wrapper.emitted('update:modelValue')).toBeUndefined();
  });

  it('shows the selected user in the input', async () => {
    const wrapper = mount(UserPicker, { props: { label: 'User', modelValue: user(3) } });

    expect((wrapper.get('input').element as HTMLInputElement).value).toBe('User Number3 · user3');
  });

  it('labels the input for assistive technology', () => {
    const wrapper = mount(UserPicker, { props: { label: 'Find a user', modelValue: null } });

    const input = wrapper.get('input[role="combobox"]');
    expect(wrapper.get('label').text()).toBe('Find a user');
    expect(wrapper.get('label').attributes('for')).toBe(input.attributes('id'));
  });
});
