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
import { flushPromises, mount } from '@vue/test-utils';
import { beforeEach, describe, expect, it, vi } from 'vitest';
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
    expect(banner.text()).toContain('Your grid proxy has expired');
    expect(banner.find('a.af-btn').attributes('href')).toBe('#identity-card-x509');
  });

  it('shows a warning banner when an until-expiry proxy is about to expire', async () => {
    const wrapper = await mountWith([
      x509({
        x509_link_mode: 'until-expiry',
        proxy_expires_at: new Date(Date.now() + 3600_000).toISOString(),
      }),
    ]);
    const banner = wrapper.find('.af-banner.warn');
    expect(banner.text()).toContain('Your grid proxy expires soon');
    expect(banner.find('a.af-btn').attributes('href')).toBe('#identity-card-x509');
  });

  it('does not warn about an auto-renewing proxy that is near expiry', async () => {
    const wrapper = await mountWith([
      x509({ proxy_expires_at: new Date(Date.now() + 3600_000).toISOString() }),
    ]);
    expect(wrapper.find('.af-banner').exists()).toBe(false);
  });

  it('names the one unlinked account and its link target', async () => {
    const wrapper = await mountWith([linkedProvider({ linked: false })]);
    const banner = wrapper.find('.af-banner.warn');
    expect(banner.text()).toContain('ATLAS IAM is not linked');
    expect(banner.find('a.af-btn').attributes('href')).toBe('#identity-card-atlas-iam');
  });

  it('counts several unlinked accounts without offering a single target', async () => {
    const wrapper = await mountWith([
      linkedProvider({ linked: false }),
      linkedProvider({ id: 'other', display_name: 'Other', linked: false }),
    ]);
    const banner = wrapper.find('.af-banner.warn');
    expect(banner.text()).toContain('2 accounts are not linked');
    expect(banner.find('a.af-btn').exists()).toBe(false);
  });

  it('reports an account that needs access instead of offering to link it', async () => {
    const wrapper = await mountWith([
      linkedProvider({ linked: false, link_permission_denied: true }),
    ]);
    const banner = wrapper.find('.af-banner.warn');
    expect(banner.text()).toContain('ATLAS IAM needs access');
    expect(banner.find('a.af-btn').exists()).toBe(false);
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
