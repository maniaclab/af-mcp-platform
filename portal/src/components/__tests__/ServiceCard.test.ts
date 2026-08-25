/**
 * Component tests for BackendCard.vue's fetch-on-expand Tools accordion.
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
import BackendCard from '../BackendCard.vue';

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
  capability: 'read_data',
  auth_type: 'bearer',
  action_type: 'read',
  credential_provider: 'atlas-oidc',
  status: 'available',
  status_detail: 'Available.',
  correlation_id: null,
};

function listing(overrides: Partial<ServerToolsResponse> = {}): ServerToolsResponse {
  return {
    name: 'rucio',
    display_name: 'Rucio',
    description: 'ATLAS distributed data management',
    status: 'ok',
    status_detail: 'Tools listed.',
    tools: [
      { name: 'rucio_list_dids', description: 'List DIDs.', action_type: 'read' },
      {
        name: 'rucio_add_rule',
        description: 'Add a replication rule.',
        action_type: 'state_change',
      },
    ],
    ...overrides,
  };
}

function mountCard(): VueWrapper {
  return mount(BackendCard, {
    props: {
      server: SERVER,
      poweredBy: {
        kind: 'identity' as const,
        label: 'ATLAS IAM',
        linked: true,
        linkHref: '/identities/',
      },
    },
  });
}

function toolsToggle(wrapper: VueWrapper) {
  const button = wrapper.find('button.bc__tools-toggle');
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
    expect(countChip(wrapper)).toBe('2 tools');
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
      listing({ tools: [{ name: 'rucio_whoami', description: '', action_type: 'read' }] }),
    );
    await flushPromises();
    d1.resolve(listing()); // the abandoned fetch (2 tools) lands LAST
    await flushPromises();

    // Fetch #2 belongs to the current open period and must win.
    expect(countChip(wrapper)).toBe('1 tool');
    expect(wrapper.text()).toContain('rucio_whoami');
    expect(wrapper.text()).not.toContain('rucio_list_dids');
  });

  it('explains a not_linked listing and links to the Identities page', async () => {
    vi.mocked(fetchServerTools).mockResolvedValueOnce(
      listing({
        status: 'not_linked',
        status_detail: "Link your identity to see this backend's tools.",
        tools: [],
      }),
    );
    const wrapper = mountCard();

    await toolsToggle(wrapper).trigger('click');
    await flushPromises();

    expect(wrapper.text()).toContain("Link your identity to see this backend's tools.");
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

    expect(wrapper.text()).toContain('This backend currently registers no tools.');
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
