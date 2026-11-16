/**
 * Component tests for AdminUserTokensSection.vue — the Admin page's "User tokens"
 * panel: pick a user with the typeahead, see their tokens in the same table the
 * Tokens page uses, and revoke one or all of them behind a confirmation.
 *
 * The API layer is mocked; the UserPicker's own behaviour is covered in
 * UserPicker.test.ts, so these tests only drive it far enough to pick a user.
 */
import { flushPromises, mount } from '@vue/test-utils';
import type { VueWrapper } from '@vue/test-utils';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { AdminUser, TokenSummary } from '../../lib/api';

vi.mock('../../lib/api', () => ({
  searchAdminUsers: vi.fn(),
  listUserTokens: vi.fn(),
  revokeUserToken: vi.fn(),
  revokeAllUserTokens: vi.fn(),
  SessionExpiredError: class SessionExpiredError extends Error {},
  AccessDeniedError: class AccessDeniedError extends Error {},
}));

import {
  listUserTokens,
  revokeAllUserTokens,
  revokeUserToken,
  searchAdminUsers,
} from '../../lib/api';
import AdminUserTokensSection from '../AdminUserTokensSection.vue';

const DAY_MS = 86_400_000;
const iso = (offsetDays: number) => new Date(Date.now() + offsetDays * DAY_MS).toISOString();

const ADA: AdminUser = {
  subject: 'sub-ada',
  username: 'ada',
  email: 'ada@example.org',
  display_name: 'Ada Lovelace',
  last_seen: iso(-1),
  pat_count: 2,
};

function token(overrides: Partial<TokenSummary>): TokenSummary {
  return {
    lookup_id: 'LOOKUP0001',
    name: 'laptop',
    note: null,
    created_at: iso(-10),
    expires_at: iso(60),
    revoked_at: null,
    last_used_at: null,
    permission_grant: null,
    ...overrides,
  };
}

function stubDialogApi() {
  HTMLDialogElement.prototype.showModal = vi.fn(function (this: HTMLDialogElement) {
    this.setAttribute('open', '');
  });
  HTMLDialogElement.prototype.close = vi.fn(function (this: HTMLDialogElement) {
    this.removeAttribute('open');
    this.dispatchEvent(new Event('close'));
  });
}

function unstubDialogApi() {
  // @ts-expect-error -- deleting a test-only stub
  delete HTMLDialogElement.prototype.showModal;
  // @ts-expect-error -- deleting a test-only stub
  delete HTMLDialogElement.prototype.close;
}

/** Mount, pick Ada through the typeahead, and wait for her tokens to load. */
async function mountWithAda(tokens: TokenSummary[]): Promise<VueWrapper> {
  vi.mocked(searchAdminUsers).mockResolvedValue({ users: [ADA], more: false, partial: false });
  vi.mocked(listUserTokens).mockResolvedValue(tokens);
  const wrapper = mount(AdminUserTokensSection, { attachTo: document.body });
  await wrapper.get('input[role="combobox"]').setValue('ada');
  await vi.advanceTimersByTimeAsync(250);
  await flushPromises();
  await wrapper.get('[role="option"]').trigger('click');
  await flushPromises();
  return wrapper;
}

async function confirm(wrapper: VueWrapper): Promise<void> {
  await wrapper.get('dialog[open] .btn.af-danger').trigger('click');
  await flushPromises();
}

beforeEach(() => {
  vi.useFakeTimers();
  stubDialogApi();
  vi.mocked(listUserTokens).mockReset();
  vi.mocked(revokeUserToken).mockReset();
  vi.mocked(revokeAllUserTokens).mockReset();
});

afterEach(() => {
  vi.useRealTimers();
  unstubDialogApi();
  document.body.innerHTML = '';
});

describe('AdminUserTokensSection', () => {
  it('asks for a user first and fetches no tokens', () => {
    const wrapper = mount(AdminUserTokensSection);

    expect(wrapper.find('input[role="combobox"]').exists()).toBe(true);
    expect(wrapper.find('table').exists()).toBe(false);
    expect(listUserTokens).not.toHaveBeenCalled();
  });

  it("lists the selected user's tokens in the shared token table, without Delete", async () => {
    const wrapper = await mountWithAda([
      token({ lookup_id: 'A', name: 'laptop' }),
      token({ lookup_id: 'B', name: 'old', revoked_at: iso(-2) }),
    ]);

    expect(listUserTokens).toHaveBeenCalledWith('sub-ada');
    const names = wrapper.findAll('tbody tr').map((r) => r.find('.tp__name span').text());
    expect(names).toEqual(['laptop', 'old']);
    expect(wrapper.find('button[aria-label="Revoke laptop"]').exists()).toBe(true);
    expect(wrapper.find('button[aria-label="Delete old"]').exists()).toBe(false);
  });

  it('says so when the user has no tokens', async () => {
    const wrapper = await mountWithAda([]);

    expect(wrapper.text()).toContain('has no tokens');
    expect(wrapper.find('table').exists()).toBe(false);
  });

  it('revokes one token only after confirmation, then refreshes the list', async () => {
    const wrapper = await mountWithAda([token({ lookup_id: 'A', name: 'laptop' })]);
    vi.mocked(revokeUserToken).mockResolvedValue(undefined);
    vi.mocked(listUserTokens).mockResolvedValue([
      token({ lookup_id: 'A', name: 'laptop', revoked_at: iso(0) }),
    ]);

    await wrapper.get('button[aria-label="Revoke laptop"]').trigger('click');
    expect(revokeUserToken).not.toHaveBeenCalled();
    expect(wrapper.get('dialog[open]').text()).toContain('laptop');
    await confirm(wrapper);

    expect(revokeUserToken).toHaveBeenCalledWith('A');
    expect(listUserTokens).toHaveBeenCalledTimes(2);
    expect(wrapper.find('button[aria-label="Revoke laptop"]').exists()).toBe(false);
    expect(wrapper.get('[data-af-revoke-result]').text()).toContain('Revoked "laptop"');
  });

  it('shows a failed revoke and leaves the list alone', async () => {
    const wrapper = await mountWithAda([token({ lookup_id: 'A', name: 'laptop' })]);
    vi.mocked(revokeUserToken).mockRejectedValue(new Error('boom'));

    await wrapper.get('button[aria-label="Revoke laptop"]').trigger('click');
    await confirm(wrapper);

    expect(wrapper.get('[role="alert"]').text()).toContain('boom');
    expect(listUserTokens).toHaveBeenCalledTimes(1);
    expect(wrapper.find('button[aria-label="Revoke laptop"]').exists()).toBe(true);
  });

  it('revokes all active tokens only after confirmation, then refreshes the list', async () => {
    const wrapper = await mountWithAda([
      token({ lookup_id: 'A', name: 'one' }),
      token({ lookup_id: 'B', name: 'two' }),
      token({ lookup_id: 'C', name: 'dead', revoked_at: iso(-2) }),
    ]);
    vi.mocked(revokeAllUserTokens).mockResolvedValue(['A', 'B']);
    vi.mocked(listUserTokens).mockResolvedValue([
      token({ lookup_id: 'A', name: 'one', revoked_at: iso(0) }),
      token({ lookup_id: 'B', name: 'two', revoked_at: iso(0) }),
      token({ lookup_id: 'C', name: 'dead', revoked_at: iso(-2) }),
    ]);

    const revokeAll = wrapper.get('[data-af-revoke-all]');
    expect(revokeAll.text()).toContain('2');
    await revokeAll.trigger('click');
    expect(revokeAllUserTokens).not.toHaveBeenCalled();
    expect(wrapper.get('dialog[open]').text()).toContain('Ada Lovelace');
    await confirm(wrapper);

    expect(revokeAllUserTokens).toHaveBeenCalledWith('sub-ada');
    expect(listUserTokens).toHaveBeenCalledTimes(2);
    expect(wrapper.find('[data-af-revoke-all]').exists()).toBe(false);
    expect(wrapper.get('[data-af-revoke-result]').text()).toContain('Revoked 2 tokens');
  });

  it('offers no Revoke all when nothing is active', async () => {
    const wrapper = await mountWithAda([token({ name: 'dead', revoked_at: iso(-2) })]);

    expect(wrapper.find('[data-af-revoke-all]').exists()).toBe(false);
  });

  it('shows a failed revoke-all', async () => {
    const wrapper = await mountWithAda([token({ lookup_id: 'A', name: 'one' })]);
    vi.mocked(revokeAllUserTokens).mockRejectedValue(new Error('vault down'));

    await wrapper.get('[data-af-revoke-all]').trigger('click');
    await confirm(wrapper);

    expect(wrapper.get('[role="alert"]').text()).toContain('vault down');
  });

  it('shows a failure to load the tokens', async () => {
    vi.mocked(searchAdminUsers).mockResolvedValue({ users: [ADA], more: false, partial: false });
    vi.mocked(listUserTokens).mockRejectedValue(new Error('nope'));
    const wrapper = mount(AdminUserTokensSection, { attachTo: document.body });
    await wrapper.get('input[role="combobox"]').setValue('ada');
    await vi.advanceTimersByTimeAsync(250);
    await flushPromises();
    await wrapper.get('[role="option"]').trigger('click');
    await flushPromises();

    expect(wrapper.text()).toContain('nope');
  });
});
