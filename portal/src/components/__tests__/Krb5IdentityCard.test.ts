/**
 * Component tests for Krb5IdentityCard.vue — the Identities page's card for
 * a krb5-token entry (link_mechanism: "credential"). Unlike
 * X509IdentityCard.vue, this card has no accordions and no persisted custody
 * option: it mints a one-shot Kerberos ticket via POST /v1/krb5/ticket and
 * shows the result for the current page visit only (see the plan's scope
 * boundary — no "remember" checkbox, no revoke button, no fetch-on-expand
 * sections).
 *
 * There's no pre-existing submit-flow test to match a bar against (x509's
 * own test file only covers its two accordions), so this file covers the
 * basic mint flow from scratch, including the password-clearing discipline
 * X509IdentityCard.vue's handleSubmit follows for its passphrase.
 */
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { KrbTicketMetadata } from '../../lib/api';

// Mirrors AdminPage.test.ts's pattern: mock only the functions this
// component calls, but re-implement APIError/SessionExpiredError faithfully
// so krb5Identity.ts's real krb5LinkErrorMessage (imported by the component,
// NOT mocked here) still does its real instanceof-based branching against
// errors constructed in this file.
vi.mock('../../lib/api', () => ({
  requestKrb5Ticket: vi.fn(),
  SessionExpiredError: class SessionExpiredError extends Error {},
  APIError: class APIError extends Error {
    constructor(
      public readonly status: number,
      public readonly statusText: string,
      public readonly body: string,
    ) {
      super(`${status} ${statusText}: ${body}`);
      this.name = 'APIError';
    }
  },
}));

import { APIError, requestKrb5Ticket } from '../../lib/api';
import Krb5IdentityCard from '../Krb5IdentityCard.vue';

/** A promise whose resolution the test controls — stands in for a slow HTTP response. */
function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (err: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

const TICKET: KrbTicketMetadata = {
  target: 'lxplus',
  principal: 'jdoe@CERN.CH',
  realm: 'CERN.CH',
  expires_at: '2026-09-04T00:00:00+00:00',
  remaining_seconds: 36000,
  renew_until: '2026-09-10T00:00:00+00:00',
};

function mountCard(linked = false): VueWrapper {
  return mount(Krb5IdentityCard, {
    props: {
      linked,
      display_name: 'Kerberos ticket (krb5)',
      enables: 'Kerberos ticket minting for krb5-authenticated backends',
    },
  });
}

async function openForm(wrapper: VueWrapper) {
  await wrapper.find('button.kc__btn').trigger('click');
}

async function fillForm(wrapper: VueWrapper, username: string, password: string) {
  await wrapper.find('input[type="text"]').setValue(username);
  await wrapper.find('input[type="password"]').setValue(password);
}

function submit(wrapper: VueWrapper) {
  return wrapper.find('form').trigger('submit');
}

beforeEach(() => {
  vi.restoreAllMocks();
});

describe('badge and action button', () => {
  it('renders a "not linked" badge and a mint button when unlinked', () => {
    const wrapper = mountCard(false);
    expect(wrapper.text()).toContain('not linked');
    expect(wrapper.find('button.kc__btn').text()).toBe('Get Kerberos ticket');
  });

  it('renders a "linked" badge and a refresh button when linked', () => {
    const wrapper = mountCard(true);
    expect(wrapper.text()).toContain('linked');
    expect(wrapper.find('button.kc__btn').text()).toBe('Refresh ticket');
  });

  it('renders powers chips when provided', () => {
    const wrapper = mount(Krb5IdentityCard, {
      props: {
        linked: false,
        display_name: 'Kerberos ticket (krb5)',
        enables: 'Kerberos ticket minting for krb5-authenticated backends',
        powers: ['lxplus'],
      },
    });
    expect(wrapper.text()).toContain('lxplus');
  });
});

describe('form open/close', () => {
  it('opens the form with username/password inputs and no checkbox', async () => {
    const wrapper = mountCard();
    await openForm(wrapper);

    expect(wrapper.find('input[type="text"]').exists()).toBe(true);
    expect(wrapper.find('input[type="password"]').exists()).toBe(true);
    expect(wrapper.find('input[type="checkbox"]').exists()).toBe(false);
  });

  it('cancel closes the form and clears both fields without submitting', async () => {
    const wrapper = mountCard();
    await openForm(wrapper);
    await fillForm(wrapper, 'jdoe', 'hunter2');

    await wrapper.find('button.kc__btn--cancel').trigger('click');

    expect(wrapper.find('form').exists()).toBe(false);
    expect(requestKrb5Ticket).not.toHaveBeenCalled();

    // Re-open and confirm the fields didn't survive the cancel.
    await openForm(wrapper);
    expect((wrapper.find('input[type="text"]').element as HTMLInputElement).value).toBe('');
    expect((wrapper.find('input[type="password"]').element as HTMLInputElement).value).toBe('');
  });
});

describe('submit disabled state', () => {
  it('is disabled while either field is empty', async () => {
    const wrapper = mountCard();
    await openForm(wrapper);
    const submitBtn = wrapper.find('button.kc__btn--submit');
    expect(submitBtn.attributes('disabled')).toBeDefined();

    await wrapper.find('input[type="text"]').setValue('jdoe');
    expect(submitBtn.attributes('disabled')).toBeDefined(); // password still empty

    await wrapper.find('input[type="password"]').setValue('hunter2');
    expect(submitBtn.attributes('disabled')).toBeUndefined();
  });

  it('is disabled while the request is in flight', async () => {
    const d = deferred<KrbTicketMetadata>();
    vi.mocked(requestKrb5Ticket).mockReturnValueOnce(d.promise);
    const wrapper = mountCard();
    await openForm(wrapper);
    await fillForm(wrapper, 'jdoe', 'hunter2');

    await submit(wrapper);
    expect(wrapper.find('button.kc__btn--submit').attributes('disabled')).toBeDefined();

    d.resolve(TICKET);
    await flushPromises();
  });
});

describe('successful submission', () => {
  it('calls requestKrb5Ticket with username/password, closes the form, emits linked, and shows the result', async () => {
    vi.mocked(requestKrb5Ticket).mockResolvedValueOnce(TICKET);
    const wrapper = mountCard();
    await openForm(wrapper);
    await fillForm(wrapper, 'jdoe', 'hunter2');

    await submit(wrapper);
    await flushPromises();

    expect(requestKrb5Ticket).toHaveBeenCalledWith('jdoe', 'hunter2');
    expect(wrapper.find('form').exists()).toBe(false);
    expect(wrapper.emitted('linked')).toEqual([[TICKET]]);

    expect(wrapper.text()).toContain('jdoe@CERN.CH');
    expect(wrapper.text()).toContain('CERN.CH');
  });

  it('clears the password from component state before the request resolves', async () => {
    const d = deferred<KrbTicketMetadata>();
    vi.mocked(requestKrb5Ticket).mockReturnValueOnce(d.promise);
    const wrapper = mountCard();
    await openForm(wrapper);
    await fillForm(wrapper, 'jdoe', 'hunter2');

    await submit(wrapper);

    // The request is still pending, but the password field must already be
    // cleared from state — captured and blanked before the await, exactly
    // like X509IdentityCard.vue's handleSubmit does for its passphrase.
    expect((wrapper.find('input[type="password"]').element as HTMLInputElement).value).toBe('');

    d.resolve(TICKET);
    await flushPromises();
  });
});

describe('failed submission', () => {
  it('clears the password from component state before the request rejects', async () => {
    const d = deferred<KrbTicketMetadata>();
    vi.mocked(requestKrb5Ticket).mockReturnValueOnce(d.promise);
    const wrapper = mountCard();
    await openForm(wrapper);
    await fillForm(wrapper, 'jdoe', 'wrongpass');

    await submit(wrapper);

    expect((wrapper.find('input[type="password"]').element as HTMLInputElement).value).toBe('');

    d.reject(new APIError(400, 'Bad Request', 'not-json'));
    await flushPromises();

    // Still cleared, and the form stays open with the field empty for retry.
    expect((wrapper.find('input[type="password"]').element as HTMLInputElement).value).toBe('');
  });

  it.each([
    [400, /username|password/i],
    [403, /revoked|expired/i],
    [422, /invalid/i],
    [429, /too many/i],
    [502, /unavailable/i],
  ])(
    'surfaces the krb5LinkErrorMessage text for a %i response and does not close the form or emit',
    async (status, expected) => {
      vi.mocked(requestKrb5Ticket).mockRejectedValueOnce(new APIError(status, 'Error', 'not-json'));
      const wrapper = mountCard();
      await openForm(wrapper);
      await fillForm(wrapper, 'jdoe', 'wrongpass');

      await submit(wrapper);
      await flushPromises();

      const alert = wrapper.find('[role="alert"]');
      expect(alert.exists()).toBe(true);
      expect(alert.text()).toMatch(expected);
      expect(wrapper.find('form').exists()).toBe(true);
      expect(wrapper.emitted('linked')).toBeUndefined();
    },
  );
});
