/**
 * Component tests for CatalogPage.vue — the Services page body: the
 * blocked-services banner, the type filter and search, and both empty states.
 */
import { flushPromises, mount } from '@vue/test-utils';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { CatalogServer } from '../../lib/api';

vi.mock('../../lib/api', () => ({
  fetchCatalog: vi.fn(),
  fetchIdentities: vi.fn(),
  fetchServerTools: vi.fn(),
  SessionExpiredError: class SessionExpiredError extends Error {},
  AccessDeniedError: class AccessDeniedError extends Error {},
}));

import { fetchCatalog, fetchIdentities } from '../../lib/api';
import CatalogPage from '../CatalogPage.vue';

function server(overrides: Partial<CatalogServer> = {}): CatalogServer {
  return {
    name: 'rucio',
    display_name: 'Rucio',
    description: 'Data management',
    permission: 'read_data',
    auth_type: 'bearer',
    action_type: 'read',
    credential_provider: 'atlas-oidc',
    status: 'available',
    status_detail: 'Available.',
    correlation_id: null,
    builtin: false,
    ...overrides,
  };
}

const BLOCKED = {
  status: 'link_required' as const,
  status_detail: 'Link your ATLAS IAM account to use this service.',
};

async function mountPage(servers: CatalogServer[]) {
  vi.mocked(fetchCatalog).mockResolvedValueOnce({ servers });
  vi.mocked(fetchIdentities).mockResolvedValueOnce({
    providers: [{ id: 'atlas-oidc', display_name: 'ATLAS IAM', linked: false }],
  } as never);
  const wrapper = mount(CatalogPage);
  await flushPromises();
  return wrapper;
}

beforeEach(() => {
  vi.resetAllMocks();
});

describe('services banner', () => {
  it('is absent when every service is available', async () => {
    const wrapper = await mountPage([server(), server({ name: 'ami', display_name: 'AMI' })]);
    expect(wrapper.find('.af-banner').exists()).toBe(false);
  });

  it('raises no banner for services that need a linked account', async () => {
    const wrapper = await mountPage([
      server(),
      server({ name: 'panda', display_name: 'PanDA', ...BLOCKED }),
      server({ name: 'ami', display_name: 'AMI', ...BLOCKED }),
    ]);
    expect(wrapper.find('.af-banner').exists()).toBe(false);
  });

  it('reports a failing service as a problem, ahead of services needing a link', async () => {
    const wrapper = await mountPage([
      server({ name: 'panda', ...BLOCKED }),
      server({
        name: 'ami',
        status: 'misconfigured',
        status_detail: 'Contact an administrator.',
      }),
    ]);
    const banner = wrapper.find('.af-banner');
    expect(banner.classes()).toContain('bad');
    expect(banner.text()).toContain('1 service is misconfigured');
    expect(banner.find('a.btn').exists()).toBe(false);
  });
});

describe('service order', () => {
  it('lists failing services first, then available, then not linked, alphabetically within each', async () => {
    const wrapper = await mountPage([
      server({ name: 'zz-ok', display_name: 'Zeta', status: 'available' }),
      server({ name: 'aa-link', display_name: 'Alpha', ...BLOCKED }),
      server({ name: 'mm-ok', display_name: 'Mu', status: 'available' }),
      server({ name: 'bb-down', display_name: 'Beta', status: 'unavailable' }),
    ]);
    const names = wrapper.findAll('.bc__name').map((n) => n.text());
    expect(names).toEqual(['Beta', 'Mu', 'Zeta', 'Alpha']);
  });
});

describe('filter and search', () => {
  const servers = [
    server({ name: 'rucio', display_name: 'Rucio', action_type: 'read' }),
    server({ name: 'condor', display_name: 'HTCondor', action_type: 'state_change' }),
  ];

  async function filterTo(wrapper: Awaited<ReturnType<typeof mountPage>>, label: string) {
    const button = wrapper.findAll('.button-group button').find((b) => b.text() === label);
    expect(button).toBeDefined();
    await button!.trigger('click');
  }

  it('lists every service by default', async () => {
    const wrapper = await mountPage(servers);
    expect(wrapper.text()).toContain('Rucio');
    expect(wrapper.text()).toContain('HTCondor');
    expect(wrapper.text()).toContain('2 services');
  });

  it('narrows to write-capable services', async () => {
    const wrapper = await mountPage(servers);
    await filterTo(wrapper, 'Write ops');
    expect(wrapper.text()).not.toContain('Rucio');
    expect(wrapper.text()).toContain('HTCondor');
  });

  it('narrows by search text', async () => {
    const wrapper = await mountPage(servers);
    await wrapper.find('input[type="search"]').setValue('condor');
    expect(wrapper.text()).not.toContain('Rucio');
    expect(wrapper.text()).toContain('HTCondor');
  });
});

describe('empty states', () => {
  it('points at the Identities page when there are no services at all', async () => {
    const wrapper = await mountPage([]);
    const empty = wrapper.find('.empty');
    expect(empty.exists()).toBe(true);
    expect(empty.text()).toContain('No services available');
    expect(empty.find('a').attributes('href')).toBe('/identities/');
  });

  it('says nothing matches when the filter hides every service', async () => {
    const wrapper = await mountPage([server()]);
    await wrapper.find('input[type="search"]').setValue('zzz');
    const empty = wrapper.find('.empty');
    expect(empty.text()).toContain('No matches');
    expect(empty.text()).toContain('zzz');
  });
});

describe('load errors', () => {
  it('shows the failure with a pointer to the Identities page', async () => {
    vi.mocked(fetchCatalog).mockRejectedValueOnce(new Error('boom'));
    vi.mocked(fetchIdentities).mockResolvedValueOnce({ providers: [] } as never);
    const wrapper = mount(CatalogPage);
    await flushPromises();
    const alert = wrapper.find('[role="alert"]');
    expect(alert.text()).toContain('boom');
    expect(alert.find('a').attributes('href')).toBe('/identities/');
  });
});
