/**
 * Component tests for IdentitiesPage.vue's stable per-provider anchor ids.
 *
 * Part of the elicitation/link-identity design's stage 1: the broker's
 * af_link_identity tool (and the shared not-linked ToolError both
 * _bearer_factory/_x509_factory raise) build a portal deep link of the
 * form `{portal_url}/identities#identity-card-{alias}` -- this only works
 * if the rendered page actually has an element with that id for every
 * provider, regardless of which card component (IdentityLink vs.
 * X509IdentityCard) renders it.
 */
import { enableAutoUnmount, flushPromises, mount } from '@vue/test-utils';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { IdentitiesResponse, IdentityProvider } from '../../lib/api';

vi.mock('../../lib/api', () => ({
  fetchIdentities: vi.fn(),
  fetchCatalog: vi.fn(),
  clearIdentitiesCache: vi.fn(),
  SessionExpiredError: class SessionExpiredError extends Error {},
  AccessDeniedError: class AccessDeniedError extends Error {},
}));

import { fetchCatalog, fetchIdentities } from '../../lib/api';
import IdentitiesPage from '../IdentitiesPage.vue';

const IDENTITIES: IdentitiesResponse = {
  subject: 'user-123',
  email: 'user@example.org',
  unixname: 'auser',
  uid: 1000,
  gid: 1000,
  groups: [],
  is_admin: false,
  providers: [
    {
      id: 'atlas-iam',
      type: 'keycloak-brokered',
      display_name: 'ATLAS IAM',
      enables: 'Rucio/PanDA access',
      linked: true,
      link_url: null,
      link_mechanism: 'redirect',
    },
    {
      id: 'x509',
      type: 'x509',
      display_name: 'Grid certificate (x509)',
      enables: 'VOMS proxy minting',
      linked: false,
      link_url: null,
      link_mechanism: 'passphrase',
    },
    {
      id: 'krb5',
      type: 'krb5-token',
      display_name: 'CERN Kerberos ticket',
      enables: 'AFS/CVMFS access',
      linked: false,
      link_url: null,
      link_mechanism: 'credential',
    },
    {
      id: 'servicex',
      type: 'servicex-token',
      display_name: 'ServiceX',
      enables: 'On-demand data delivery via servicex-mcp',
      linked: false,
      link_url: null,
      link_mechanism: 'servicex-token',
      external_login_url: 'https://servicex.example.org/api-token',
    },
  ],
};

// A mounted page listens for hashchange on window; unmounting keeps one test's
// page from reacting to the next test's hash.
enableAutoUnmount(afterEach);

beforeEach(() => {
  vi.restoreAllMocks();
  window.sessionStorage.clear();
  vi.mocked(fetchIdentities).mockResolvedValue(IDENTITIES);
  vi.mocked(fetchCatalog).mockResolvedValue({ servers: [] });
});

describe('IdentitiesPage provider card anchors', () => {
  it('renders a stable identity-card-{id} anchor for a redirect-mechanism provider', async () => {
    const wrapper = mount(IdentitiesPage);
    await flushPromises();

    const anchor = wrapper.find('#identity-card-atlas-iam');
    expect(anchor.exists()).toBe(true);
    // IdentityLink.vue's root .il element must be inside the anchor -- the
    // portal deep link needs an actual scrollable target, not just a
    // same-named sibling.
    expect(anchor.find('.il').exists()).toBe(true);
  });

  it('renders a stable identity-card-{id} anchor for the passphrase-mechanism (x509) provider', async () => {
    const wrapper = mount(IdentitiesPage);
    await flushPromises();

    const anchor = wrapper.find('#identity-card-x509');
    expect(anchor.exists()).toBe(true);
    expect(anchor.find('.xc').exists()).toBe(true);
  });

  it('renders Krb5IdentityCard for a credential-mechanism provider', async () => {
    const wrapper = mount(IdentitiesPage);
    await flushPromises();

    const anchor = wrapper.find('#identity-card-krb5');
    expect(anchor.exists()).toBe(true);
    expect(anchor.find('.kc').exists()).toBe(true);
    expect(anchor.find('.il').exists()).toBe(false);
    expect(anchor.find('.xc').exists()).toBe(false);
  });

  it('renders ServiceXIdentityCard for a servicex-token-mechanism provider, passing external_login_url through', async () => {
    const wrapper = mount(IdentitiesPage);
    await flushPromises();

    const anchor = wrapper.find('#identity-card-servicex');
    expect(anchor.exists()).toBe(true);
    expect(anchor.find('.sc').exists()).toBe(true);
    expect(anchor.find('.il').exists()).toBe(false);
    expect(anchor.find('.xc').exists()).toBe(false);
    expect(anchor.find('.kc').exists()).toBe(false);
    const link = anchor.find('a.sc__btn--external');
    expect(link.attributes('href')).toBe('https://servicex.example.org/api-token');
  });
});

describe('IdentitiesPage banner', () => {
  const linkedProvider = (over: Partial<IdentityProvider> = {}): IdentityProvider => ({
    id: 'atlas-iam',
    type: 'keycloak-brokered',
    display_name: 'ATLAS IAM',
    enables: 'Rucio/PanDA access',
    linked: true,
    link_url: null,
    link_mechanism: 'redirect',
    ...over,
  });
  const x509 = (over: Partial<IdentityProvider> = {}): IdentityProvider => ({
    id: 'x509',
    type: 'x509',
    display_name: 'Grid certificate',
    enables: 'VOMS proxy minting',
    linked: true,
    link_url: null,
    link_mechanism: 'passphrase',
    x509_link_mode: 'auto-renew',
    proxy_expires_at: new Date(Date.now() + 9 * 3600_000).toISOString(),
    ...over,
  });

  async function mountWith(providers: IdentityProvider[]) {
    vi.mocked(fetchIdentities).mockResolvedValue({ ...IDENTITIES, providers });
    const wrapper = mount(IdentitiesPage);
    await flushPromises();
    return wrapper;
  }

  it('shows no banner when every account is linked and the proxy is valid', async () => {
    const wrapper = await mountWith([linkedProvider(), x509()]);
    expect(wrapper.find('.af-banner').exists()).toBe(false);
  });

  it('shows a problem banner with a link to the certificate when an until-expiry proxy has expired', async () => {
    const wrapper = await mountWith([
      linkedProvider(),
      x509({
        linked: false,
        x509_link_mode: 'until-expiry',
        proxy_expires_at: new Date(Date.now() - 3 * 3600_000).toISOString(),
      }),
    ]);
    const banner = wrapper.find('.af-banner.bad');
    expect(banner.attributes('role')).toBe('alert');
    expect(banner.text()).toContain('Your grid proxy has expired');
    expect(banner.find('a.btn').attributes('href')).toBe('#identity-card-x509');
  });

  it('shows a warning banner when an until-expiry proxy is about to expire', async () => {
    const wrapper = await mountWith([
      x509({
        x509_link_mode: 'until-expiry',
        proxy_expires_at: new Date(Date.now() + 30 * 60_000).toISOString(),
      }),
    ]);
    const banner = wrapper.find('.af-banner.warn');
    expect(banner.attributes('role')).toBe('alert');
    expect(banner.text()).toContain('Your grid proxy expires soon');
    expect(banner.find('a.btn').attributes('href')).toBe('#identity-card-x509');
  });

  it('does not warn about a proxy that cannot renew while it has over an hour left', async () => {
    const wrapper = await mountWith([
      x509({
        x509_link_mode: 'until-expiry',
        proxy_expires_at: new Date(Date.now() + 90 * 60_000).toISOString(),
      }),
    ]);
    expect(wrapper.find('.af-banner').exists()).toBe(false);
  });

  it('does not warn about an auto-renewing proxy that is near expiry', async () => {
    const wrapper = await mountWith([
      x509({ proxy_expires_at: new Date(Date.now() + 10 * 60_000).toISOString() }),
    ]);
    expect(wrapper.find('.af-banner').exists()).toBe(false);
  });

  it('raises no banner for an unlinked account', async () => {
    const wrapper = await mountWith([linkedProvider({ linked: false })]);
    expect(wrapper.find('.af-banner').exists()).toBe(false);
  });

  it('raises no banner for several unlinked accounts, and marks each as not linked', async () => {
    const wrapper = await mountWith([
      linkedProvider({ linked: false }),
      linkedProvider({ id: 'other', display_name: 'Other', linked: false }),
    ]);
    expect(wrapper.find('.af-banner').exists()).toBe(false);
    expect(wrapper.findAll('.af-mark.off').length).toBeGreaterThanOrEqual(2);
    expect(wrapper.find('.af-mark.warn').exists()).toBe(false);
    expect(wrapper.find('.af-mark.bad').exists()).toBe(false);
  });

  it('raises no banner for an account that needs access, which the card reports itself', async () => {
    const wrapper = await mountWith([
      linkedProvider({ linked: false, link_permission_denied: true }),
    ]);
    expect(wrapper.find('.af-banner').exists()).toBe(false);
    expect(wrapper.text()).toContain('Access required');
  });

  const rejectedProvider = (over: Partial<IdentityProvider> = {}) =>
    linkedProvider({
      id: 'rucio-oauth',
      type: 'oauth21-direct',
      display_name: 'Rucio (ATLAS)',
      linked: false,
      rejected: true,
      link_url: '/v1/oauth/authorize/rucio-oauth',
      ...over,
    });

  it('shows a warning banner with a re-link action for a rejected credential', async () => {
    const wrapper = await mountWith([linkedProvider(), rejectedProvider()]);
    const banner = wrapper.find('.af-banner.warn');
    expect(banner.attributes('role')).toBe('alert');
    expect(banner.text()).toContain('Rucio (ATLAS) rejected the linked credential');
    expect(banner.text()).toContain('Re-link it to restore the services that use it.');
    const action = banner.find('a.btn');
    expect(action.text()).toBe('Reconnect Rucio (ATLAS) account');
    expect(action.attributes('href')).toBe('#identity-card-rucio-oauth');
    expect(wrapper.find('#identity-card-rucio-oauth .il__status--rejected').exists()).toBe(true);
  });

  it('counts several rejected credentials without naming one action', async () => {
    const wrapper = await mountWith([
      rejectedProvider(),
      rejectedProvider({ id: 'other-oauth', display_name: 'Other' }),
    ]);
    const banner = wrapper.find('.af-banner.warn');
    expect(banner.text()).toContain('2 linked credentials were rejected');
    expect(banner.find('a.btn').exists()).toBe(false);
  });

  it('ranks a rejected credential below an expired proxy and above an expiring one', async () => {
    const expired = x509({
      linked: false,
      x509_link_mode: 'until-expiry',
      proxy_expires_at: new Date(Date.now() - 3600_000).toISOString(),
    });
    const expiring = x509({
      x509_link_mode: 'until-expiry',
      proxy_expires_at: new Date(Date.now() + 30 * 60_000).toISOString(),
    });

    const withExpired = await mountWith([rejectedProvider(), expired]);
    expect(withExpired.findAll('.af-banner')).toHaveLength(1);
    expect(withExpired.find('.af-banner.bad').text()).toContain('Your grid proxy has expired');

    const withExpiring = await mountWith([rejectedProvider(), expiring]);
    expect(withExpiring.findAll('.af-banner')).toHaveLength(1);
    expect(withExpiring.find('.af-banner.warn').text()).toContain('rejected the linked credential');
  });

  it('treats a response without the rejected field as not rejected', async () => {
    const wrapper = await mountWith([rejectedProvider({ rejected: undefined })]);
    expect(wrapper.find('.af-banner').exists()).toBe(false);
    expect(wrapper.find('.il__status--rejected').exists()).toBe(false);
    expect(wrapper.text()).toContain('Not linked');
  });

  it('shows the most urgent problem only: an expired proxy beats an unlinked account', async () => {
    const wrapper = await mountWith([
      linkedProvider({ linked: false }),
      x509({
        linked: false,
        x509_link_mode: 'until-expiry',
        proxy_expires_at: new Date(Date.now() - 3600_000).toISOString(),
      }),
    ]);
    expect(wrapper.findAll('.af-banner')).toHaveLength(1);
    expect(wrapper.find('.af-banner.bad').exists()).toBe(true);
  });
});

describe('IdentitiesPage deep-link highlight', () => {
  const TARGET_CLASS = 'ip__card-anchor--target';

  beforeEach(() => {
    window.location.hash = '';
    Element.prototype.scrollIntoView = vi.fn();
  });

  async function mountAt(hash: string) {
    window.location.hash = hash;
    const host = document.createElement('div');
    document.body.appendChild(host);
    const wrapper = mount(IdentitiesPage, { attachTo: host });
    await flushPromises();
    return wrapper;
  }

  const marked = (wrapper: ReturnType<typeof mount>) =>
    wrapper.findAll(`.${TARGET_CLASS}`).map((w) => w.attributes('id'));

  it('marks only the targeted row, exposes aria-current, scrolls to it and focuses its heading', async () => {
    const wrapper = await mountAt('#identity-card-krb5');
    expect(marked(wrapper)).toEqual(['identity-card-krb5']);
    const row = wrapper.find('#identity-card-krb5');
    expect(row.attributes('aria-current')).toBe('true');
    expect(wrapper.findAll('[aria-current="true"]')).toHaveLength(1);
    expect(Element.prototype.scrollIntoView).toHaveBeenCalledTimes(1);
    expect(document.activeElement).toBe(row.find('h3').element);
  });

  it('highlights nothing and leaves focus alone with no hash', async () => {
    const wrapper = await mountAt('');
    expect(marked(wrapper)).toEqual([]);
    expect(wrapper.find('[aria-current]').exists()).toBe(false);
    expect(Element.prototype.scrollIntoView).not.toHaveBeenCalled();
    expect(document.activeElement).toBe(document.body);
  });

  it('highlights nothing and leaves focus alone for an unknown id', async () => {
    const wrapper = await mountAt('#identity-card-nope');
    expect(marked(wrapper)).toEqual([]);
    expect(Element.prototype.scrollIntoView).not.toHaveBeenCalled();
    expect(document.activeElement).toBe(document.body);
  });

  it('highlights once the rows render when the hash arrived before the data', async () => {
    let resolve!: (v: IdentitiesResponse) => void;
    vi.mocked(fetchIdentities).mockReturnValue(new Promise((r) => (resolve = r)));
    window.location.hash = '#identity-card-x509';
    const host = document.createElement('div');
    document.body.appendChild(host);
    const wrapper = mount(IdentitiesPage, { attachTo: host });
    await flushPromises();
    expect(marked(wrapper)).toEqual([]);
    resolve(IDENTITIES);
    await flushPromises();
    expect(marked(wrapper)).toEqual(['identity-card-x509']);
    expect(Element.prototype.scrollIntoView).toHaveBeenCalledTimes(1);
  });

  it('moves the highlight when the hash changes', async () => {
    const wrapper = await mountAt('#identity-card-krb5');
    window.location.hash = '#identity-card-servicex';
    window.dispatchEvent(new HashChangeEvent('hashchange'));
    await flushPromises();
    expect(marked(wrapper)).toEqual(['identity-card-servicex']);
    expect(wrapper.find('#identity-card-krb5').attributes('aria-current')).toBeUndefined();
    expect(document.activeElement).toBe(wrapper.find('#identity-card-servicex h3').element);
  });
});
