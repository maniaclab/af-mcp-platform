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
import type { IdentitiesResponse } from '../../lib/api';

vi.mock('../../lib/api', () => ({
  fetchIdentities: vi.fn(),
  fetchCatalog: vi.fn(),
  clearIdentitiesCache: vi.fn(),
  SessionExpiredError: class SessionExpiredError extends Error {},
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
});
