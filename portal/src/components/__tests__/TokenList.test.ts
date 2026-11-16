/**
 * Component contract tests for TokenList.vue — the token table. It is
 * presentational: rows come in as a prop, and Revoke / Delete leave as
 * `revoke` / `delete` events. TokensPage.test.ts covers the same table
 * through the page.
 */
import { mount } from '@vue/test-utils';
import { describe, expect, it, vi } from 'vitest';
import type { TokenSummary } from '../../lib/api';

vi.mock('../../lib/clipboard', () => ({ copyText: vi.fn(async () => true) }));

import { copyText } from '../../lib/clipboard';
import TokenList from '../TokenList.vue';

const DAY_MS = 86_400_000;
const iso = (offsetDays: number) => new Date(Date.now() + offsetDays * DAY_MS).toISOString();

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

const mountList = (tokens: TokenSummary[], props: Record<string, unknown> = {}) =>
  mount(TokenList, {
    props: { tokens, revokingLookupId: null, deletingLookupId: null, ...props },
  });

describe('TokenList', () => {
  it('renders the tokens in the order given', () => {
    const wrapper = mountList([
      token({ lookup_id: 'B', name: 'second' }),
      token({ lookup_id: 'A', name: 'first' }),
    ]);

    const names = wrapper.findAll('tbody tr').map((r) => r.find('.tp__name span').text());
    expect(names).toEqual(['second', 'first']);
  });

  it('emits revoke with the lookup id and name from an active row', async () => {
    const wrapper = mountList([token({ lookup_id: 'A', name: 'active-one' })]);

    await wrapper.get('button[aria-label="Revoke active-one"]').trigger('click');

    expect(wrapper.emitted('revoke')).toEqual([['A', 'active-one']]);
  });

  it('emits delete with the lookup id from a revoked row', async () => {
    const wrapper = mountList([
      token({ lookup_id: 'C', name: 'revoked-one', revoked_at: iso(-1) }),
    ]);

    await wrapper.get('button[aria-label="Delete revoked-one"]').trigger('click');

    expect(wrapper.emitted('delete')).toEqual([['C']]);
  });

  it('disables and relabels only the row whose revoke is in flight', () => {
    const wrapper = mountList(
      [token({ lookup_id: 'A', name: 'one' }), token({ lookup_id: 'B', name: 'two' })],
      { revokingLookupId: 'A' },
    );

    const one = wrapper.get('button[aria-label="Revoke one"]');
    const two = wrapper.get('button[aria-label="Revoke two"]');
    expect(one.attributes('disabled')).toBeDefined();
    expect(one.text()).toBe('Revoking…');
    expect(two.attributes('disabled')).toBeUndefined();
    expect(two.text()).toBe('Revoke');
  });

  it('disables and relabels only the row whose delete is in flight', () => {
    const wrapper = mountList(
      [
        token({ lookup_id: 'C', name: 'one', revoked_at: iso(-1) }),
        token({ lookup_id: 'D', name: 'two', revoked_at: iso(-1) }),
      ],
      { deletingLookupId: 'C' },
    );

    expect(wrapper.get('button[aria-label="Delete one"]').text()).toBe('Deleting…');
    expect(wrapper.get('button[aria-label="Delete two"]').attributes('disabled')).toBeUndefined();
  });

  it('copies the full token id', async () => {
    const wrapper = mountList([token({ lookup_id: 'LOOKUP-FULL-ID' })]);

    await wrapper.get('button[aria-label="Copy token ID LOOKUP-FULL-ID"]').trigger('click');

    expect(copyText).toHaveBeenCalledWith('LOOKUP-FULL-ID');
  });
});
