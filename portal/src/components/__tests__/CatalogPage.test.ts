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
    link_state: null,
    builtin: false,
    ...overrides,
  };
}

const BLOCKED = {
  status: 'link_required' as const,
  link_state: 'not_linked' as const,
  status_detail: 'Link your ATLAS IAM account to use this service.',
};

const REJECTED = {
  status: 'link_required' as const,
  link_state: 'rejected' as const,
  status_detail: 'Your linked credential was rejected. Re-link your identity.',
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

  it('hints, without a banner, when services need a linked account', async () => {
    const wrapper = await mountPage([
      server(),
      server({ name: 'panda', display_name: 'PanDA', ...BLOCKED }),
      server({ name: 'ami', display_name: 'AMI', ...BLOCKED }),
    ]);
    expect(wrapper.find('.af-banner').exists()).toBe(false);
    const hint = wrapper.get('.af-note.info');
    expect(hint.attributes('role')).toBe('status');
    expect(hint.text()).toContain('2 services are not linked');
    // Both need the same account, so the hint names the one action.
    const action = hint.get('a.btn');
    expect(action.text()).toBe('Link ATLAS IAM account');
    expect(action.attributes('href')).toBe('/identities/#identity-card-atlas-oidc');
  });

  it('offers no action when the unlinked services need different accounts', async () => {
    const wrapper = await mountPage([
      server({ name: 'panda', ...BLOCKED }),
      server({ name: 'condor', credential_provider: 'x509', ...BLOCKED }),
    ]);
    expect(wrapper.get('.af-note.info').find('a.btn').exists()).toBe(false);
  });

  it('does not hint for a service that needs no credential', async () => {
    const wrapper = await mountPage([
      server({ name: 'af', credential_provider: null, auth_type: 'none', builtin: true }),
    ]);
    expect(wrapper.find('.af-note').exists()).toBe(false);
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
    expect(banner.attributes('role')).toBe('alert');
    expect(wrapper.find('.af-note').exists()).toBe(false);
    expect(banner.text()).toContain('1 service is misconfigured');
    expect(banner.find('a.btn').exists()).toBe(false);
  });
});

describe('rejected credential', () => {
  it('raises a warning banner, not a hint, naming the service and the re-link action', async () => {
    const wrapper = await mountPage([
      server(),
      server({ name: 'panda', display_name: 'PanDA', ...REJECTED }),
    ]);
    const banner = wrapper.get('.af-banner');
    expect(banner.classes()).toContain('warn');
    expect(banner.attributes('role')).toBe('alert');
    expect(banner.text()).toContain('PanDA rejected your ATLAS IAM account');
    const action = banner.get('a.btn');
    expect(action.text()).toBe('Reconnect ATLAS IAM account');
    expect(action.attributes('href')).toBe('/identities/#identity-card-atlas-oidc');
    expect(wrapper.find('.af-note').exists()).toBe(false);
  });

  it('shows the row with the warning mark at full ink, never as not linked', async () => {
    const wrapper = await mountPage([
      server({ name: 'panda', display_name: 'PanDA', ...REJECTED }),
    ]);
    const card = wrapper.get('.bc');
    expect(card.classes()).not.toContain('bc--off');
    expect(card.get('.bc__status-line').text()).toContain('Credential rejected');
    expect(card.get('.bc__status-line .af-mark').classes()).toContain('warn');
    expect(card.text()).not.toContain('Not linked');
  });

  it('puts a failing service ahead of it, and it ahead of the not-linked hint', async () => {
    const down = await mountPage([
      server({ name: 'panda', display_name: 'PanDA', ...REJECTED }),
      server({ name: 'ami', display_name: 'AMI', status: 'unavailable' }),
    ]);
    expect(down.get('.af-banner').text()).toContain('1 service is unavailable');
    const both = await mountPage([
      server({ name: 'ami', display_name: 'AMI', ...BLOCKED }),
      server({ name: 'panda', display_name: 'PanDA', ...REJECTED }),
    ]);
    expect(both.get('.af-banner').text()).toContain('PanDA rejected your ATLAS IAM account');
    expect(both.find('.af-note.info').exists()).toBe(false);
  });

  it('lists it after failing services and before available ones', async () => {
    const wrapper = await mountPage([
      server({ name: 'ok', display_name: 'Ok', status: 'available' }),
      server({ name: 'rej', display_name: 'Rej', ...REJECTED }),
      server({ name: 'down', display_name: 'Down', status: 'unavailable' }),
      server({ name: 'nl', display_name: 'Nl', ...BLOCKED }),
    ]);
    expect(wrapper.findAll('.bc__name').map((n) => n.text())).toEqual(['Down', 'Rej', 'Ok', 'Nl']);
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
