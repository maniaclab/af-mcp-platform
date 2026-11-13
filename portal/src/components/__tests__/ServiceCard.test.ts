/**
 * Component tests for ServiceCard.vue's fetch-on-expand Tools accordion.
 *
 * The staleness contract is the same one X509IdentityCard.test.ts pins down
 * (PR #185's toggle sequence-number guard): a fetch may only apply its
 * result while the expand that initiated it is still the current, open one
 * — a response landing after a collapse (or after a newer expand) is
 * discarded, so slow responses can never rewrite the accordion one fetch
 * behind the clicks.
 */
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { CatalogServer, ServerToolsResponse } from '../../lib/api';

vi.mock('../../lib/api', () => ({
  fetchServerTools: vi.fn(),
}));

import { fetchServerTools } from '../../lib/api';
import ServiceCard from '../ServiceCard.vue';

/** A promise whose resolution the test controls — stands in for a slow HTTP response. */
function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((r) => {
    resolve = r;
  });
  return { promise, resolve };
}

const SERVER: CatalogServer = {
  name: 'rucio',
  display_name: 'Rucio',
  description: 'ATLAS distributed data management',
  permission: 'read_data',
  auth_type: 'bearer',
  action_type: 'read',
  credential_provider: 'atlas-oidc',
  status: 'available',
  status_detail: 'Available.',
  correlation_id: null,
  link_state: null,
  builtin: false,
};

/** The broker's own af-mcp entry as /v1/catalog reports it (issue #240). */
const BUILTIN_SERVER: CatalogServer = {
  name: 'af-mcp',
  display_name: 'AF Gateway',
  description: "The gateway's own identity, catalog, and usage methods.",
  permission: '__none__',
  auth_type: 'none',
  action_type: 'read',
  credential_provider: null,
  status: 'available',
  status_detail: 'Available.',
  correlation_id: null,
  link_state: null,
  builtin: true,
};

function listing(overrides: Partial<ServerToolsResponse> = {}): ServerToolsResponse {
  return {
    name: 'rucio',
    display_name: 'Rucio',
    description: 'ATLAS distributed data management',
    status: 'ok',
    status_detail: 'Methods listed.',
    tools: [
      {
        name: 'rucio_list_dids',
        description: 'List DIDs.',
        action_type: 'read',
        permission: 'read_data',
      },
      {
        name: 'rucio_add_rule',
        description: 'Add a replication rule.',
        action_type: 'state_change',
        permission: 'manage_data',
      },
    ],
    ...overrides,
  };
}

function mountCard(): VueWrapper {
  return mount(ServiceCard, {
    props: {
      server: SERVER,
      poweredBy: {
        kind: 'identity' as const,
        label: 'ATLAS IAM',
        linked: true,
        linkHref: '/identities/#identity-card-atlas-oidc',
        linkLabel: 'Link ATLAS IAM account',
        relinkLabel: 'Reconnect ATLAS IAM account',
        noun: 'ATLAS IAM account',
      },
    },
  });
}

function mountBuiltinCard(): VueWrapper {
  return mount(ServiceCard, {
    props: {
      server: BUILTIN_SERVER,
      // What CatalogPage's resolvePoweredBy produces for a null
      // credential_provider -- the builtin card never renders it.
      poweredBy: {
        kind: 'none' as const,
        label: 'No credential required',
        linked: null,
        linkHref: null,
        linkLabel: null,
        relinkLabel: null,
        noun: null,
      },
    },
  });
}

function toolsToggle(wrapper: VueWrapper) {
  const button = wrapper.find('button.disclosure__toggle');
  expect(button.exists()).toBe(true);
  return button;
}

/** The toggle row's tool-count chip text, or null when no chip is rendered. */
function countChip(wrapper: VueWrapper): string | null {
  const chip = wrapper.find('.bc__tools-count');
  return chip.exists() ? chip.text() : null;
}

beforeEach(() => {
  vi.restoreAllMocks();
});

describe('Tools accordion', () => {
  it('fetches on expand (never on mount) and renders the tool table', async () => {
    const d1 = deferred<ServerToolsResponse>();
    vi.mocked(fetchServerTools).mockReturnValueOnce(d1.promise);
    const wrapper = mountCard();
    expect(fetchServerTools).not.toHaveBeenCalled();

    await toolsToggle(wrapper).trigger('click'); // expand
    expect(fetchServerTools).toHaveBeenCalledWith('rucio');
    d1.resolve(listing());
    await flushPromises();

    expect(wrapper.text()).toContain('rucio_list_dids');
    expect(wrapper.text()).toContain('rucio_add_rule');
    expect(countChip(wrapper)).toBe('2 methods');
  });

  it('shows the loading state in the header badge and nothing in the body', async () => {
    const d1 = deferred<ServerToolsResponse>();
    vi.mocked(fetchServerTools).mockReturnValueOnce(d1.promise);
    const wrapper = mountCard();

    await toolsToggle(wrapper).trigger('click');

    const chip = wrapper.find('button.disclosure__toggle .bc__tools-count');
    expect(chip.text()).toBe('Loading…');
    expect(chip.attributes('role')).toBe('status');
    expect(chip.attributes('aria-live')).toBe('polite');
    expect(wrapper.find('.bc__tools-body').text()).toBe('');

    d1.resolve(listing());
    await flushPromises();

    expect(countChip(wrapper)).toBe('2 methods');
    expect(wrapper.text()).not.toContain('Loading');
  });

  it('discards a response that lands after the accordion collapsed', async () => {
    const d1 = deferred<ServerToolsResponse>();
    vi.mocked(fetchServerTools).mockReturnValueOnce(d1.promise);
    const wrapper = mountCard();
    const toggle = toolsToggle(wrapper);

    await toggle.trigger('click'); // expand — fetch in flight
    await toggle.trigger('click'); // collapse before it lands
    d1.resolve(listing());
    await flushPromises();

    // The stale result must not populate the chip after collapse.
    expect(countChip(wrapper)).toBeNull();
    expect(wrapper.text()).not.toContain('rucio_list_dids');
  });

  it('discards a superseded response when the accordion is re-expanded', async () => {
    const d1 = deferred<ServerToolsResponse>();
    const d2 = deferred<ServerToolsResponse>();
    vi.mocked(fetchServerTools).mockReturnValueOnce(d1.promise).mockReturnValueOnce(d2.promise);
    const wrapper = mountCard();
    const toggle = toolsToggle(wrapper);

    await toggle.trigger('click'); // expand — fetch #1 in flight
    await toggle.trigger('click'); // collapse
    await toggle.trigger('click'); // re-expand — fetch #2 in flight
    d2.resolve(
      listing({
        tools: [
          { name: 'rucio_whoami', description: '', action_type: 'read', permission: '__none__' },
        ],
      }),
    );
    await flushPromises();
    d1.resolve(listing()); // the abandoned fetch (2 tools) lands LAST
    await flushPromises();

    // Fetch #2 belongs to the current open period and must win.
    expect(countChip(wrapper)).toBe('1 method');
    expect(wrapper.text()).toContain('rucio_whoami');
    expect(wrapper.text()).not.toContain('rucio_list_dids');
  });

  it('explains a not_linked listing and links to the Identities page', async () => {
    vi.mocked(fetchServerTools).mockResolvedValueOnce(
      listing({
        status: 'not_linked',
        status_detail: "Link your identity to see this service's methods.",
        tools: [],
      }),
    );
    const wrapper = mountCard();

    await toolsToggle(wrapper).trigger('click');
    await flushPromises();

    expect(wrapper.text()).toContain("Link your identity to see this service's methods.");
    const cta = wrapper.find('.bc__tools-cta');
    expect(cta.exists()).toBe(true);
    expect(cta.attributes('href')).toBe('/identities/');
    expect(countChip(wrapper)).toBeNull(); // no count chip for a blocked listing
  });

  it('says so when an ok listing carries zero tools', async () => {
    vi.mocked(fetchServerTools).mockResolvedValueOnce(listing({ tools: [] }));
    const wrapper = mountCard();

    await toolsToggle(wrapper).trigger('click');
    await flushPromises();

    expect(wrapper.text()).toContain('This service currently registers no methods.');
  });

  it('surfaces a fetch failure as an error note, not a silent empty section', async () => {
    vi.mocked(fetchServerTools).mockRejectedValueOnce(new Error('boom'));
    const wrapper = mountCard();

    await toolsToggle(wrapper).trigger('click');
    await flushPromises();

    expect(wrapper.find('.bc__tools-error').exists()).toBe(true);
    expect(wrapper.text()).toContain('boom');
  });
});

describe('permission badge', () => {
  it('shows the single permission when every tool of the service requires the same one', () => {
    const wrapper = mount(ServiceCard, {
      props: {
        server: SERVER, // permission: 'read_data'
        poweredBy: {
          kind: 'identity' as const,
          label: 'ATLAS IAM',
          linked: true,
          linkHref: '/identities/#identity-card-atlas-oidc',
          linkLabel: 'Link ATLAS IAM account',
          relinkLabel: 'Reconnect ATLAS IAM account',
          noun: 'ATLAS IAM account',
        },
      },
    });

    const badge = wrapper.find('.bc__cap-badge');
    expect(badge.exists()).toBe(true);
    expect(badge.text()).toBe('read_data');
    expect(badge.attributes('aria-label')).toBe('Permission: read_data');
    expect(wrapper.find('.bc__cap-badge--mixed').exists()).toBe(false);
  });

  it('shows "mixed" (not an empty badge) when a service\'s tools require different permissions', () => {
    // A dict-form required_permission in services.yaml with no "__default__"
    // has no single representative value -- GET /v1/catalog reports that as
    // permission: null (see api/permissions.py's default_permission_label
    // docstring). Rendering that null straight into the old badge produced
    // an empty box with a "Requires permission: " tooltip and nothing after
    // the colon.
    const wrapper = mount(ServiceCard, {
      props: {
        server: { ...SERVER, permission: null },
        poweredBy: {
          kind: 'identity' as const,
          label: 'ATLAS IAM',
          linked: true,
          linkHref: '/identities/#identity-card-atlas-oidc',
          linkLabel: 'Link ATLAS IAM account',
          relinkLabel: 'Reconnect ATLAS IAM account',
          noun: 'ATLAS IAM account',
        },
      },
    });

    const badge = wrapper.find('.bc__cap-badge--mixed');
    expect(badge.exists()).toBe(true);
    expect(badge.text()).toBe('Several permissions');
    expect(wrapper.text()).toContain('Different methods require different permissions');
  });
});

describe('credential-type badge', () => {
  it('is left out when a Powered by identity already names the credential', () => {
    const wrapper = mountCard(); // SERVER.auth_type 'bearer', powered by ATLAS IAM

    expect(wrapper.find('.bc__powered-by').text()).toContain('ATLAS IAM');
    expect(wrapper.find('.bc__auth-badge').exists()).toBe(false);
  });

  it('is kept when there is no identity to name, so the credential type is still shown', () => {
    const wrapper = mount(ServiceCard, {
      props: {
        server: { ...SERVER, auth_type: 'bearer', credential_provider: null },
        poweredBy: {
          kind: 'none' as const,
          label: 'No credential required',
          linked: null,
          linkHref: null,
          linkLabel: null,
          relinkLabel: null,
          noun: null,
        },
      },
    });

    expect(wrapper.find('.bc__auth-badge').text()).toBe('bearer');
  });

  it('is left out for "none", which "No credential required" already says', () => {
    const wrapper = mount(ServiceCard, {
      props: {
        server: { ...SERVER, auth_type: 'none', credential_provider: null },
        poweredBy: {
          kind: 'none' as const,
          label: 'No credential required',
          linked: null,
          linkHref: null,
          linkLabel: null,
          relinkLabel: null,
          noun: null,
        },
      },
    });

    expect(wrapper.find('.bc__powered-by').text()).toBe('No credential required');
    expect(wrapper.find('.bc__auth-badge').exists()).toBe(false);
  });
});

describe('builtin af-mcp card (issue #240)', () => {
  it('renders no credential-type badge and no Powered by row', () => {
    // The gateway itself has no per-user credential, no identity to link,
    // and no backend that could be unreachable -- the card drops those
    // affordances entirely instead of showing "none"/"No credential
    // required" rows that read like states to fix.
    const wrapper = mountBuiltinCard();

    expect(wrapper.find('.bc__auth-badge').exists()).toBe(false);
    expect(wrapper.find('.bc__powered-by').exists()).toBe(false);
    // "__none__" already suppresses the permission badge, same as any other
    // open service.
    expect(wrapper.find('.bc__cap-badge').exists()).toBe(false);
  });

  it('still lists its methods through the same fetch-on-expand accordion', async () => {
    vi.mocked(fetchServerTools).mockResolvedValueOnce(
      listing({
        name: 'af-mcp',
        display_name: 'AF Gateway',
        status: 'ok',
        tools: [
          {
            name: 'af_whoami',
            description: 'Who am I.',
            action_type: 'read',
            permission: '__none__',
          },
          {
            name: 'af_usage',
            description: 'My usage.',
            action_type: 'read',
            permission: '__none__',
          },
        ],
      }),
    );
    const wrapper = mountBuiltinCard();

    await toolsToggle(wrapper).trigger('click');
    expect(fetchServerTools).toHaveBeenCalledWith('af-mcp');
    await flushPromises();

    expect(wrapper.text()).toContain('af_whoami');
    expect(wrapper.text()).toContain('af_usage');
    expect(countChip(wrapper)).toBe('2 methods');
  });
});

describe('status line', () => {
  function mountWith(overrides: Partial<CatalogServer>): VueWrapper {
    return mount(ServiceCard, {
      props: {
        server: { ...SERVER, ...overrides },
        poweredBy: {
          kind: 'identity' as const,
          label: 'ATLAS IAM',
          linked: false,
          linkHref: '/identities/#identity-card-atlas-oidc',
          linkLabel: 'Link ATLAS IAM account',
          relinkLabel: 'Reconnect ATLAS IAM account',
          noun: 'ATLAS IAM account',
        },
      },
    });
  }

  it('says "Not linked" and names the fix once, linking to the identity card', () => {
    const wrapper = mountWith({
      status: 'link_required',
      status_detail: 'Link your ATLAS IAM account to use this service.',
    });
    const status = wrapper.get('.bc__status-line');
    expect(status.text()).toContain('Not linked');
    const fix = status.get('a');
    expect(fix.text()).toBe('Link ATLAS IAM account');
    expect(fix.attributes('href')).toBe('/identities/#identity-card-atlas-oidc');
    // The status word and the fix already say it; no repeated sentence.
    expect(wrapper.find('.bc__status-detail').exists()).toBe(false);
  });

  it('shows "Not linked" once and marks the row as quiet', () => {
    const wrapper = mountWith({ status: 'link_required' });
    expect(wrapper.text().match(/Not linked/g)).toHaveLength(1);
    expect(wrapper.find('.af-mark.off').exists()).toBe(true);
    expect(wrapper.find('.af-mark.warn').exists()).toBe(false);
    expect(wrapper.classes()).toContain('bc--off');
  });

  it.each(['misconfigured', 'permission_required', 'unavailable'] as const)(
    'omits the identity link state on a %s row, where it is not the actionable fact',
    (status) => {
      const wrapper = mountWith({ status });
      expect(wrapper.get('.bc__powered-by').text()).toContain('Powered by ATLAS IAM');
      expect(wrapper.get('.bc__powered-by').text()).not.toContain('Not linked');
      expect(wrapper.find('.bc__powered-by .af-mark').exists()).toBe(false);
    },
  );

  it('shows the identity link state on an available row', () => {
    const wrapper = mountWith({ status: 'available' });
    expect(wrapper.get('.bc__powered-by').text()).toContain('Not linked');
  });

  it('leaves an available service at full emphasis', () => {
    const wrapper = mountWith({ status: 'available' });
    expect(wrapper.classes()).not.toContain('bc--off');
  });

  it('drops the sentence for an unavailable service, whose word already says it', () => {
    const wrapper = mountWith({
      status: 'unavailable',
      status_detail: 'This service is temporarily unreachable.',
    });
    expect(wrapper.find('.bc__status-detail').exists()).toBe(false);
  });

  it('marks unavailable as a warning and misconfigured as a problem, in different words', () => {
    const down = mountWith({ status: 'unavailable' });
    expect(down.get('.bc__status-line').text()).toContain('Unavailable');
    expect(down.get('.bc__status-line .af-mark').classes()).toContain('warn');
    const bad = mountWith({ status: 'misconfigured', correlation_id: 'abc123' });
    expect(bad.get('.bc__status-line').text()).toContain('Misconfigured');
    expect(bad.get('.bc__status-line .af-mark').classes()).toContain('bad');
    expect(bad.get('.bc__status-detail code').text()).toBe('abc123');
  });

  it('keeps the sentence and reference id when they add information', () => {
    const wrapper = mountWith({
      status: 'misconfigured',
      status_detail: 'This service is not configured correctly. Contact an administrator.',
      correlation_id: 'abc123',
    });
    const detail = wrapper.get('.bc__status-detail');
    expect(detail.text()).toContain('Contact an administrator');
    expect(detail.text()).toContain('abc123');
  });

  describe('rejected credential', () => {
    const rejected = () =>
      mountWith({
        status: 'link_required',
        link_state: 'rejected',
        status_detail: 'Your linked credential was rejected. Re-link your identity.',
      });

    it('says "Credential rejected" with the warning mark, never "Not linked"', () => {
      const wrapper = rejected();
      const status = wrapper.get('.bc__status-line');
      expect(status.text()).toContain('Credential rejected');
      expect(status.get('.af-mark').classes()).toContain('warn');
      expect(wrapper.text()).not.toContain('Not linked');
      expect(wrapper.find('.af-mark.off').exists()).toBe(false);
    });

    it('stays at full ink, not the greyed disabled treatment', () => {
      expect(rejected().classes()).not.toContain('bc--off');
    });

    it('says what happened in one sentence naming the identity', () => {
      const detail = rejected().get('.bc__status-detail');
      expect(detail.text()).toBe(
        'Your linked ATLAS IAM account was rejected. Re-link it to use this service.',
      );
    });

    it('offers the re-link action, named for the identity, linking to its card', () => {
      const fix = rejected().get('.bc__status-line a');
      expect(fix.text()).toBe('Reconnect ATLAS IAM account');
      expect(fix.attributes('href')).toBe('/identities/#identity-card-atlas-oidc');
    });

    it('does not mark the Powered by identity as Linked or Not linked', () => {
      const powered = rejected().get('.bc__powered-by');
      expect(powered.text()).toContain('Powered by ATLAS IAM');
      expect(powered.find('.af-mark').exists()).toBe(false);
    });
  });

  it('keeps a not-linked service quiet when link_state is "not_linked"', () => {
    const wrapper = mountWith({ status: 'link_required', link_state: 'not_linked' });
    expect(wrapper.classes()).toContain('bc--off');
    expect(wrapper.get('.bc__status-line').text()).toContain('Not linked');
    expect(wrapper.find('.af-mark.warn').exists()).toBe(false);
    expect(wrapper.find('.bc__status-detail').exists()).toBe(false);
  });
});
