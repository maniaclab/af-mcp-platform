/**
 * Component tests for TokensPage.vue — the /tokens page.
 *
 * The list shows each token's status as a status word, a warning banner names
 * a token that expires within 7 days, an empty list explains what tokens are
 * for, and revoking asks for confirmation before it calls the API.
 */
import { flushPromises, mount } from '@vue/test-utils';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { TokenSummary } from '../../lib/api';

vi.mock('../../lib/api', () => ({
  listTokens: vi.fn(),
  revokeToken: vi.fn(),
  mintToken: vi.fn(),
  fetchPermissions: vi.fn(),
  SessionExpiredError: class SessionExpiredError extends Error {},
  AccessDeniedError: class AccessDeniedError extends Error {},
}));
vi.mock('../../lib/auth', () => ({
  getBrokerOrigin: vi.fn(async () => 'https://broker.example.org'),
}));

import { fetchPermissions, listTokens, mintToken, revokeToken } from '../../lib/api';
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
    expect(wrapper.find('.af-page-head .af-btn.primary').text()).toContain('New token');
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

  it('only offers Revoke on active tokens', async () => {
    const wrapper = await mountPage([
      token({ lookup_id: 'A', name: 'active-one' }),
      token({ lookup_id: 'C', name: 'revoked-one', revoked_at: iso(-1) }),
    ]);

    const rows = wrapper.findAll('tbody tr');
    const revokeIn = (name: string) =>
      rows.find((r) => r.text().includes(name))!.find('button.danger');
    expect(revokeIn('active-one').attributes('disabled')).toBeUndefined();
    expect(revokeIn('revoked-one').attributes('disabled')).toBeDefined();
  });

  describe('expiring-soon banner', () => {
    it('names the token that expires within 7 days', async () => {
      const wrapper = await mountPage([
        token({ lookup_id: 'A', name: 'active-one', expires_at: iso(60) }),
        token({ lookup_id: 'B', name: 'soon-one', expires_at: iso(3) }),
      ]);

      const banner = wrapper.find('.af-banner.warn');
      expect(banner.exists()).toBe(true);
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

    const empty = wrapper.find('.af-empty');
    expect(empty.exists()).toBe(true);
    expect(empty.text()).toContain('No tokens yet');
    expect(empty.find('.af-btn.primary').text()).toContain('New token');
    // The page header does not repeat the primary button.
    expect(wrapper.find('.af-page-head .af-btn').exists()).toBe(false);
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

      await wrapper.find('tbody button.danger').trigger('click');
      await flushPromises();

      expect(revokeToken).not.toHaveBeenCalled();
      const dialog = wrapper.find('dialog.af-dialog[open]');
      expect(dialog.exists()).toBe(true);
      expect(dialog.text()).toContain('active-one');

      await dialog.find('footer .af-btn.danger').trigger('click');
      await flushPromises();

      expect(revokeToken).toHaveBeenCalledExactlyOnceWith('A');
      expect(wrapper.find('tbody tr .af-st').text()).toBe('Revoked');
    });

    it('does not call the API when the confirmation is cancelled', async () => {
      const wrapper = await mountPage([token({ lookup_id: 'A', name: 'active-one' })]);

      await wrapper.find('tbody button.danger').trigger('click');
      await flushPromises();
      await wrapper.find('dialog.af-dialog[open] footer .af-btn.quiet').trigger('click');
      await flushPromises();

      expect(revokeToken).not.toHaveBeenCalled();
    });

    it('shows the failure when the API rejects', async () => {
      vi.mocked(revokeToken).mockRejectedValue(new Error('nope'));
      const wrapper = await mountPage([token({ lookup_id: 'A', name: 'active-one' })]);

      await wrapper.find('tbody button.danger').trigger('click');
      await flushPromises();
      await wrapper.find('dialog.af-dialog[open] footer .af-btn.danger').trigger('click');
      await flushPromises();

      expect(wrapper.find('[role="alert"]').text()).toContain('nope');
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

      await wrapper.find('.af-page-head .af-btn.primary').trigger('click');
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
