/**
 * Component tests for TokensPage.vue — the /tokens page.
 *
 * The list shows each token's status as a status word, a warning banner names
 * a token that expires within 7 days, an empty list explains what tokens are
 * for, revoking asks for confirmation before it calls the API, and a revoked
 * or expired row can be deleted singly or all at once (after confirmation).
 */
import { flushPromises, mount } from '@vue/test-utils';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { TokenSummary } from '../../lib/api';

vi.mock('../../lib/api', () => ({
  listTokens: vi.fn(),
  revokeToken: vi.fn(),
  deleteTokenRecord: vi.fn(),
  clearInactiveTokens: vi.fn(),
  mintToken: vi.fn(),
  fetchPermissions: vi.fn(),
  SessionExpiredError: class SessionExpiredError extends Error {},
  AccessDeniedError: class AccessDeniedError extends Error {},
}));
vi.mock('../../lib/auth', () => ({
  getBrokerOrigin: vi.fn(async () => 'https://broker.example.org'),
}));

import {
  clearInactiveTokens,
  deleteTokenRecord,
  fetchPermissions,
  listTokens,
  mintToken,
  revokeToken,
} from '../../lib/api';
import TokensPage from '../TokensPage.vue';

const DAY_MS = 86_400_000;

function iso(offsetDays: number): string {
  return new Date(Date.now() + offsetDays * DAY_MS).toISOString();
}

function token(overrides: Partial<TokenSummary>): TokenSummary {
  return {
    lookup_id: 'LOOKUP0001',
    name: 'example-token',
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

async function mountPage(tokens: TokenSummary[]) {
  vi.mocked(listTokens).mockResolvedValue(tokens);
  const wrapper = mount(TokensPage, { attachTo: document.body });
  await flushPromises();
  return wrapper;
}

beforeEach(() => {
  vi.resetAllMocks();
  vi.mocked(fetchPermissions).mockResolvedValue({ grants: [] } as never);
  stubDialogApi();
});

afterEach(() => {
  unstubDialogApi();
  document.body.innerHTML = '';
});

describe('TokensPage', () => {
  it('shows the page title and a New token button in the header', async () => {
    const wrapper = await mountPage([token({})]);

    expect(wrapper.find('h1').text()).toBe('Tokens');
    expect(wrapper.find('.af-page-head .btn:not([data-variant])').text()).toContain('New token');
  });

  it('renders one row per token with its status as a word', async () => {
    const wrapper = await mountPage([
      token({ lookup_id: 'A', name: 'active-one', expires_at: iso(60) }),
      token({ lookup_id: 'B', name: 'soon-one', expires_at: iso(3) }),
      token({ lookup_id: 'C', name: 'revoked-one', revoked_at: iso(-1) }),
      token({ lookup_id: 'D', name: 'expired-one', expires_at: iso(-2) }),
    ]);

    const rows = wrapper.findAll('tbody tr');
    expect(rows).toHaveLength(4);
    const byName = (name: string) => rows.find((r) => r.text().includes(name))!;
    expect(byName('active-one').find('.af-st').text()).toBe('Active');
    expect(byName('soon-one').find('.af-st').text()).toMatch(/^Expires in \d+ days?$/);
    expect(byName('revoked-one').find('.af-st').text()).toBe('Revoked');
    expect(byName('expired-one').find('.af-st').text()).toBe('Expired');
  });

  it('offers Revoke on active tokens and Delete on revoked and expired ones', async () => {
    const wrapper = await mountPage([
      token({ lookup_id: 'A', name: 'active-one' }),
      token({ lookup_id: 'C', name: 'revoked-one', revoked_at: iso(-1) }),
      token({ lookup_id: 'D', name: 'expired-one', expires_at: iso(-2) }),
    ]);

    const rows = wrapper.findAll('tbody tr');
    const row = (name: string) => rows.find((r) => r.text().includes(name))!;
    expect(row('active-one').find('button.af-danger').exists()).toBe(true);
    expect(row('active-one').find('button[aria-label^="Delete"]').exists()).toBe(false);
    for (const name of ['revoked-one', 'expired-one']) {
      expect(row(name).find('button.af-danger').exists()).toBe(false);
      expect(row(name).find(`button[aria-label="Delete ${name}"]`).exists()).toBe(true);
    }
  });

  describe('expiring-soon banner', () => {
    it('names the token that expires within 7 days', async () => {
      const wrapper = await mountPage([
        token({ lookup_id: 'A', name: 'active-one', expires_at: iso(60) }),
        token({ lookup_id: 'B', name: 'soon-one', expires_at: iso(3) }),
      ]);

      const banner = wrapper.find('.af-banner.warn');
      expect(banner.exists()).toBe(true);
      expect(banner.attributes('role')).toBe('alert');
      expect(banner.text()).toContain('soon-one');
    });

    it('is absent when no active token expires within 7 days', async () => {
      const wrapper = await mountPage([
        token({ lookup_id: 'A', expires_at: iso(60) }),
        token({ lookup_id: 'B', expires_at: null }),
        // Already revoked or expired tokens are not "about to expire".
        token({ lookup_id: 'C', expires_at: iso(2), revoked_at: iso(-1) }),
        token({ lookup_id: 'D', expires_at: iso(-3) }),
      ]);

      expect(wrapper.find('.af-banner').exists()).toBe(false);
    });
  });

  it('shows an empty state that carries the New token button', async () => {
    const wrapper = await mountPage([]);

    const empty = wrapper.find('.empty');
    expect(empty.exists()).toBe(true);
    expect(empty.text()).toContain('No tokens yet');
    expect(empty.find('.btn:not([data-variant])').text()).toContain('New token');
    // The page header does not repeat the primary button.
    expect(wrapper.find('.af-page-head .btn').exists()).toBe(false);
  });

  it('shows an alert when the list fails to load', async () => {
    vi.mocked(listTokens).mockRejectedValue(new Error('boom'));
    const wrapper = mount(TokensPage, { attachTo: document.body });
    await flushPromises();

    expect(wrapper.find('[role="alert"]').text()).toContain('boom');
  });

  describe('revoke', () => {
    it('asks for confirmation before calling the API', async () => {
      vi.mocked(revokeToken).mockResolvedValue(undefined);
      const wrapper = await mountPage([token({ lookup_id: 'A', name: 'active-one' })]);

      await wrapper.find('tbody button.af-danger').trigger('click');
      await flushPromises();

      expect(revokeToken).not.toHaveBeenCalled();
      const dialog = wrapper.find('dialog.dialog[open]');
      expect(dialog.exists()).toBe(true);
      expect(dialog.text()).toContain('active-one');

      await dialog.find('footer .btn.af-danger').trigger('click');
      await flushPromises();

      expect(revokeToken).toHaveBeenCalledExactlyOnceWith('A');
      expect(wrapper.find('tbody tr .af-st').text()).toBe('Revoked');
    });

    it('does not call the API when the confirmation is cancelled', async () => {
      const wrapper = await mountPage([token({ lookup_id: 'A', name: 'active-one' })]);

      await wrapper.find('tbody button.af-danger').trigger('click');
      await flushPromises();
      await wrapper.find('dialog.dialog[open] footer .btn[data-variant="ghost"]').trigger('click');
      await flushPromises();

      expect(revokeToken).not.toHaveBeenCalled();
    });

    it('shows the failure when the API rejects', async () => {
      vi.mocked(revokeToken).mockRejectedValue(new Error('nope'));
      const wrapper = await mountPage([token({ lookup_id: 'A', name: 'active-one' })]);

      await wrapper.find('tbody button.af-danger').trigger('click');
      await flushPromises();
      await wrapper.find('dialog.dialog[open] footer .btn.af-danger').trigger('click');
      await flushPromises();

      expect(wrapper.find('[role="alert"]').text()).toContain('nope');
    });
  });

  describe('delete', () => {
    it('deletes a revoked row and removes it from the list', async () => {
      vi.mocked(deleteTokenRecord).mockResolvedValue(undefined);
      const wrapper = await mountPage([
        token({ lookup_id: 'A', name: 'active-one' }),
        token({ lookup_id: 'C', name: 'revoked-one', revoked_at: iso(-1) }),
      ]);

      await wrapper.find('button[aria-label="Delete revoked-one"]').trigger('click');
      await flushPromises();

      expect(deleteTokenRecord).toHaveBeenCalledExactlyOnceWith('C');
      const rows = wrapper.findAll('tbody tr');
      expect(rows).toHaveLength(1);
      expect(rows[0].text()).toContain('active-one');
    });

    it('shows the failure and keeps the row when the API rejects', async () => {
      vi.mocked(deleteTokenRecord).mockRejectedValue(new Error('still active'));
      const wrapper = await mountPage([
        token({ lookup_id: 'C', name: 'revoked-one', revoked_at: iso(-1) }),
      ]);

      await wrapper.find('button[aria-label="Delete revoked-one"]').trigger('click');
      await flushPromises();

      expect(wrapper.find('[role="alert"]').text()).toContain('still active');
      expect(wrapper.findAll('tbody tr')).toHaveLength(1);
    });
  });

  describe('clear revoked and expired', () => {
    const clearButton = (wrapper: Awaited<ReturnType<typeof mountPage>>) =>
      wrapper.find('button.tp__clear');

    it('is absent when every token is active', async () => {
      const wrapper = await mountPage([token({ lookup_id: 'A' })]);

      expect(clearButton(wrapper).exists()).toBe(false);
    });

    it('counts the revoked and expired tokens it would delete', async () => {
      const wrapper = await mountPage([
        token({ lookup_id: 'A', name: 'active-one' }),
        token({ lookup_id: 'C', name: 'revoked-one', revoked_at: iso(-1) }),
        token({ lookup_id: 'D', name: 'expired-one', expires_at: iso(-2) }),
      ]);

      expect(clearButton(wrapper).text()).toContain('Clear revoked and expired (2)');
    });

    it('asks for confirmation, then deletes only the revoked and expired rows', async () => {
      vi.mocked(clearInactiveTokens).mockResolvedValue(2);
      const wrapper = await mountPage([
        token({ lookup_id: 'A', name: 'active-one' }),
        token({ lookup_id: 'C', name: 'revoked-one', revoked_at: iso(-1) }),
        token({ lookup_id: 'D', name: 'expired-one', expires_at: iso(-2) }),
      ]);

      await clearButton(wrapper).trigger('click');
      await flushPromises();
      expect(clearInactiveTokens).not.toHaveBeenCalled();
      const dialog = wrapper.find('dialog.dialog[open]');
      expect(dialog.text()).toContain('2');

      await dialog.find('footer .btn.af-danger').trigger('click');
      await flushPromises();

      expect(clearInactiveTokens).toHaveBeenCalledOnce();
      const rows = wrapper.findAll('tbody tr');
      expect(rows).toHaveLength(1);
      expect(rows[0].text()).toContain('active-one');
      expect(clearButton(wrapper).exists()).toBe(false);
    });

    it('does not call the API when the confirmation is cancelled', async () => {
      const wrapper = await mountPage([
        token({ lookup_id: 'C', name: 'revoked-one', revoked_at: iso(-1) }),
      ]);

      await clearButton(wrapper).trigger('click');
      await flushPromises();
      await wrapper.find('dialog.dialog[open] footer .btn[data-variant="ghost"]').trigger('click');
      await flushPromises();

      expect(clearInactiveTokens).not.toHaveBeenCalled();
      expect(wrapper.findAll('tbody tr')).toHaveLength(1);
    });

    it('shows the failure when the API rejects', async () => {
      vi.mocked(clearInactiveTokens).mockRejectedValue(new Error('vault down'));
      const wrapper = await mountPage([
        token({ lookup_id: 'C', name: 'revoked-one', revoked_at: iso(-1) }),
      ]);

      await clearButton(wrapper).trigger('click');
      await flushPromises();
      await wrapper.find('dialog.dialog[open] footer .btn.af-danger').trigger('click');
      await flushPromises();

      expect(wrapper.find('[role="alert"]').text()).toContain('vault down');
    });
  });

  describe('new token dialog', () => {
    it('mints a token and shows its value once in a copy field', async () => {
      vi.mocked(mintToken).mockResolvedValue({
        token: 'mcp_pat_SECRET',
        lookup_id: 'NEW1',
        name: 'my-client',
        note: null,
        expires_at: iso(90),
        permission_grant: null,
      } as never);
      const wrapper = await mountPage([token({})]);

      await wrapper.find('.af-page-head .btn:not([data-variant])').trigger('click');
      await flushPromises();
      expect(wrapper.find('dialog[open] #tp-name').exists()).toBe(true);

      await wrapper.find('dialog[open] form').trigger('submit');
      await flushPromises();

      const dialog = wrapper.find('dialog[open]');
      expect(dialog.find('.af-note.warn').text()).toContain('only time');
      expect(dialog.findAll('.af-copy').length).toBeGreaterThanOrEqual(1);
      expect(dialog.text()).toContain('mcp_pat_SECRET');
    });
  });
});

describe('TokensPage permission picker', () => {
  const GRANTS = [
    { permission: 'use_notebooks', targets: ['jhub'], action_types: ['read', 'state_change'] },
    { permission: 'read_data', targets: ['rucio'], action_types: ['read'] },
    { permission: 'manage_jobs', targets: ['condor'], action_types: ['state_change'] },
    { permission: 'read_search', targets: ['aos'], action_types: ['read'] },
    // A site-defined permission no portal list has ever named.
    { permission: 'example_exec_jobs', targets: ['exec'], action_types: ['state_change'] },
  ];

  async function openPicker() {
    vi.mocked(fetchPermissions).mockResolvedValue({ grants: GRANTS } as never);
    const wrapper = await mountPage([token({})]);
    await wrapper.find('.af-page-head .btn:not([data-variant])').trigger('click');
    await flushPromises();
    await wrapper.get('dialog[open] #tp-restrict').setValue(true);
    return wrapper;
  }

  it('groups the permissions into read and state-changing fieldsets', async () => {
    const wrapper = await openPicker();

    const groups = wrapper.findAll('dialog[open] fieldset.tp__perms');
    expect(groups.map((g) => g.get('legend').text())).toEqual(['Read', 'State-changing']);
    const names = (g: (typeof groups)[number]) => g.findAll('label').map((l) => l.text());
    expect(names(groups[0])).toEqual(['read_data', 'read_search']);
    // Only the grant's own action types decide; a grant reporting both is state-changing.
    expect(names(groups[1])).toEqual(['example_exec_jobs', 'manage_jobs', 'use_notebooks']);
  });

  it('omits a group that has no permissions', async () => {
    vi.mocked(fetchPermissions).mockResolvedValue({ grants: [GRANTS[1]] } as never);
    const wrapper = await mountPage([token({})]);
    await wrapper.find('.af-page-head .btn:not([data-variant])').trigger('click');
    await flushPromises();
    await wrapper.get('dialog[open] #tp-restrict').setValue(true);

    const groups = wrapper.findAll('dialog[open] fieldset.tp__perms');
    expect(groups).toHaveLength(1);
    expect(groups[0].get('legend').text()).toBe('Read');
  });

  it('mints with the permissions ticked across both groups', async () => {
    vi.mocked(mintToken).mockResolvedValue({
      token: 'mcp_pat_SECRET',
      lookup_id: 'NEW1',
      name: 'x',
      note: null,
      expires_at: iso(90),
      permission_grant: ['manage_jobs', 'read_data'],
    } as never);
    const wrapper = await openPicker();

    await wrapper.get('#tp-perm-read_data').setValue(true);
    await wrapper.get('#tp-perm-manage_jobs').setValue(true);
    await wrapper.get('dialog[open] form').trigger('submit');
    await flushPromises();

    expect(vi.mocked(mintToken).mock.calls[0][4]).toEqual(['read_data', 'manage_jobs']);
  });
});

describe('TokensPage table layout', () => {
  it('has only the columns that fit a 900px content width, with the action last', async () => {
    const wrapper = await mountPage([token({})]);

    const headers = wrapper.findAll('thead th').map((th) => th.text());
    expect(headers).toEqual(['Name', 'Status', 'Scope', 'Expires', 'Last used', 'Actions']);
  });

  it('keeps the token id, its copy button and the created time under the name', async () => {
    const wrapper = await mountPage([
      token({ lookup_id: 'LOOKUP0001-FULL-VALUE', name: 'active-one', created_at: iso(-10) }),
    ]);

    const nameCell = wrapper.get('tbody tr td');
    expect(nameCell.text()).toContain('active-one');
    const meta = nameCell.get('.tp__meta');
    expect(meta.text()).toContain('LOOKUP00…');
    expect(meta.text()).toContain('Created 10 days ago');
    expect(meta.find('button[aria-label="Copy token ID LOOKUP0001-FULL-VALUE"]').exists()).toBe(
      true,
    );
  });

  it('pins the action column so it stays visible when the table scrolls', async () => {
    const wrapper = await mountPage([token({})]);

    expect(wrapper.get('thead th.af-act').classes()).toContain('af-sticky');
    expect(wrapper.get('tbody td.af-act').classes()).toContain('af-sticky');
  });

  it('lists every permission of a scoped token in the scope cell', async () => {
    const wrapper = await mountPage([token({ permission_grant: ['read_data', 'submit_jobs'] })]);

    expect(wrapper.get('tbody td.tp__scope').text()).toBe('read_data, submit_jobs');
  });
});

describe('TokensPage token id', () => {
  it('can be copied in full with a button, since the cell shows only the start', async () => {
    const writeText = vi.fn(async () => {});
    Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true });
    const wrapper = await mountPage([token({ lookup_id: 'LOOKUP0001-FULL-VALUE' })]);

    const button = wrapper.get('button[aria-label="Copy token ID LOOKUP0001-FULL-VALUE"]');
    await button.trigger('click');
    await flushPromises();

    expect(writeText).toHaveBeenCalledWith('LOOKUP0001-FULL-VALUE');
  });
});
