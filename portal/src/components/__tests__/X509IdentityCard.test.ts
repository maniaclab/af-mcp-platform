/**
 * Component tests for X509IdentityCard.vue's fetch-on-expand accordions.
 *
 * Regression for the deployed "VOMS proxy details flips on every click" bug:
 * the accordion starts a fetch on expand, but a response landing AFTER the
 * accordion has collapsed (or after a newer expand) used to be applied
 * anyway — so with slow responses (and a backend whose
 * /v1/x509/proxy/status answer varies per request across replicas) the chip
 * was rewritten exactly at collapse time, one fetch behind the clicks,
 * ping-ponging active/no-proxy on every toggle. A response may only be
 * applied while the expand that initiated it is still the current, open
 * one; anything else is discarded.
 */
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { ProxyStatus, X509Preflight } from '../../lib/api';

vi.mock('../../lib/api', () => ({
  fetchProxyStatus: vi.fn(),
  fetchX509Preflight: vi.fn(),
  requestProxy: vi.fn(),
  revokeProxy: vi.fn(),
}));

import { fetchProxyStatus, fetchX509Preflight } from '../../lib/api';
import X509IdentityCard from '../X509IdentityCard.vue';

/** A promise whose resolution the test controls — stands in for a slow HTTP response. */
function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((r) => {
    resolve = r;
  });
  return { promise, resolve };
}

const ACTIVE: ProxyStatus = {
  cached: true,
  dn: '/DC=ch/DC=cern/CN=Test User',
  voms_attributes: ['/atlas'],
  expires_at: '2026-08-27T00:00:00+00:00',
  remaining_seconds: 3600,
};

const NO_PROXY: ProxyStatus = { cached: false, voms_attributes: [] };

const PREFLIGHT_OK: X509Preflight = {
  unixname: 'auser',
  root: '/home/auser/.globus',
  ok: true,
  checks: [],
};

function mountCard(): VueWrapper {
  return mount(X509IdentityCard, {
    props: {
      linked: true,
      display_name: 'Grid certificate (x509)',
      enables: 'VOMS proxy minting for x509-authenticated backends',
      x509_link_mode: 'auto-renew',
    },
  });
}

/** The two accordion toggle rows, in template order. */
function toggles(wrapper: VueWrapper) {
  const buttons = wrapper.findAll('button.xc__section-toggle');
  expect(buttons).toHaveLength(2);
  return { preflightToggle: buttons[0], proxyToggle: buttons[1] };
}

/** The proxy accordion's status chip text ("active" / "no proxy"), or null when no chip is rendered. */
function proxyChip(wrapper: VueWrapper): string | null {
  const chip = toggles(wrapper).proxyToggle.find('.xc__chip');
  return chip.exists() ? chip.text() : null;
}

beforeEach(() => {
  vi.restoreAllMocks();
});

describe('VOMS proxy details accordion', () => {
  it('applies a response that lands while its expand is still open', async () => {
    const d1 = deferred<ProxyStatus>();
    vi.mocked(fetchProxyStatus).mockReturnValueOnce(d1.promise);
    const wrapper = mountCard();

    await toggles(wrapper).proxyToggle.trigger('click'); // expand
    d1.resolve(ACTIVE);
    await flushPromises();

    expect(proxyChip(wrapper)).toBe('active');
    expect(wrapper.text()).toContain('Subject DN');
  });

  it('shows the resolved CERN account when the broker reports a nickname', async () => {
    const d1 = deferred<ProxyStatus>();
    vi.mocked(fetchProxyStatus).mockReturnValueOnce(d1.promise);
    const wrapper = mountCard();

    await toggles(wrapper).proxyToggle.trigger('click'); // expand
    d1.resolve({ ...ACTIVE, nickname: 'jdoe' });
    await flushPromises();

    expect(wrapper.text()).toContain('CERN account');
    expect(wrapper.text()).toContain('jdoe');
  });

  it('omits the CERN account row when no nickname is reported', async () => {
    const d1 = deferred<ProxyStatus>();
    vi.mocked(fetchProxyStatus).mockReturnValueOnce(d1.promise);
    const wrapper = mountCard();

    await toggles(wrapper).proxyToggle.trigger('click'); // expand
    d1.resolve(ACTIVE); // no nickname field
    await flushPromises();

    expect(wrapper.text()).not.toContain('CERN account');
  });

  it('never renders a VOMS attributes row (unparsed placeholder, not user-facing)', async () => {
    const d1 = deferred<ProxyStatus>();
    vi.mocked(fetchProxyStatus).mockReturnValueOnce(d1.promise);
    const wrapper = mountCard();

    await toggles(wrapper).proxyToggle.trigger('click'); // expand
    d1.resolve(ACTIVE);
    await flushPromises();

    expect(wrapper.text()).not.toContain('VOMS attributes');
  });

  it('discards a response that lands after the accordion collapsed', async () => {
    const d1 = deferred<ProxyStatus>();
    vi.mocked(fetchProxyStatus).mockReturnValueOnce(d1.promise);
    const wrapper = mountCard();
    const { proxyToggle } = toggles(wrapper);

    await proxyToggle.trigger('click'); // expand — fetch in flight
    await proxyToggle.trigger('click'); // collapse before it lands
    d1.resolve(NO_PROXY);
    await flushPromises();

    // The stale result must not rewrite the chip after collapse.
    expect(proxyChip(wrapper)).toBeNull();
  });

  it('discards a superseded response when the accordion is re-expanded', async () => {
    const d1 = deferred<ProxyStatus>();
    const d2 = deferred<ProxyStatus>();
    vi.mocked(fetchProxyStatus).mockReturnValueOnce(d1.promise).mockReturnValueOnce(d2.promise);
    const wrapper = mountCard();
    const { proxyToggle } = toggles(wrapper);

    await proxyToggle.trigger('click'); // expand — fetch #1 in flight
    await proxyToggle.trigger('click'); // collapse
    await proxyToggle.trigger('click'); // re-expand — fetch #2 in flight
    d2.resolve(ACTIVE);
    await flushPromises();
    d1.resolve(NO_PROXY); // the abandoned fetch lands LAST
    await flushPromises();

    // Fetch #2 belongs to the current open period and must win.
    expect(proxyChip(wrapper)).toBe('active');
  });

  it('never flips the chip at a collapse click (the deployed alternation repro)', async () => {
    // The deployed pattern: each expand's response landed only after the
    // following collapse click, and the backend alternated no-proxy/active
    // per request — so the chip was rewritten at every collapse, one fetch
    // behind the clicks.
    const d1 = deferred<ProxyStatus>();
    const d2 = deferred<ProxyStatus>();
    vi.mocked(fetchProxyStatus).mockReturnValueOnce(d1.promise).mockReturnValueOnce(d2.promise);
    const wrapper = mountCard();
    const { proxyToggle } = toggles(wrapper);

    await proxyToggle.trigger('click'); // click 1: expand — fetch #1 (no proxy) in flight
    await proxyToggle.trigger('click'); // click 2: collapse
    d1.resolve(NO_PROXY); // lands after the collapse — must be discarded
    await flushPromises();
    expect(proxyChip(wrapper)).toBeNull();

    await proxyToggle.trigger('click'); // click 3: expand — fetch #2 (active)
    d2.resolve(ACTIVE); // lands while open — applied
    await flushPromises();
    expect(proxyChip(wrapper)).toBe('active');

    await proxyToggle.trigger('click'); // click 4: collapse
    await flushPromises();
    expect(proxyChip(wrapper)).toBe('active'); // no rewrite at collapse
  });
});

describe('Grid Certificates accordion', () => {
  it('discards a preflight response that lands after the accordion collapsed', async () => {
    const d1 = deferred<X509Preflight>();
    vi.mocked(fetchX509Preflight).mockReturnValueOnce(d1.promise);
    const wrapper = mountCard();
    const { preflightToggle } = toggles(wrapper);

    await preflightToggle.trigger('click'); // expand — fetch in flight
    await preflightToggle.trigger('click'); // collapse before it lands
    d1.resolve(PREFLIGHT_OK);
    await flushPromises();

    expect(preflightToggle.find('.xc__chip').exists()).toBe(false);
  });
});
