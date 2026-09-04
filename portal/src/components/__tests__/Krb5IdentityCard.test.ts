/**
 * Component tests for Krb5IdentityCard.vue — the Identities page's card for
 * a krb5-token entry (link_mechanism: "credential"). Unlike
 * X509IdentityCard.vue, this card has no accordions: it offers two separate
 * actions — a one-shot Kerberos ticket mint via POST /v1/krb5/ticket, and a
 * durable keytab upload via POST /v1/krb5/keytab — and shows the mint
 * result for the current page visit only. It carries a "Forget this ticket"
 * affordance once linked, which calls the shared unlinkIdentity() (see
 * IdentityLink.vue's use of it) to delete the whole Vault record.
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
  linkKrb5Keytab: vi.fn(),
  unlinkIdentity: vi.fn(),
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

import { APIError, linkKrb5Keytab, requestKrb5Ticket, unlinkIdentity } from '../../lib/api';
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
      id: 'krb5',
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

function openKeytabForm(wrapper: VueWrapper) {
  return wrapper.find('button.kc__btn--keytab').trigger('click');
}

/** A small fake keytab file — a real one is a few KB of binary, this is enough to exercise FileReader. */
function makeKeytabFile(bytes: number[] = [1, 2, 3, 4]): File {
  return new File([new Uint8Array(bytes)], 'jdoe.keytab');
}

async function setKeytabFile(wrapper: VueWrapper, file: File) {
  const input = wrapper.find('input[type="file"]');
  Object.defineProperty(input.element, 'files', { value: [file], configurable: true });
  await input.trigger('change');
}

async function fillKeytabForm(wrapper: VueWrapper, username: string, file: File) {
  await wrapper.find('input[type="text"]').setValue(username);
  await setKeytabFile(wrapper, file);
}

/**
 * jsdom's FileReader dispatches its `load` event via a real timer, not a
 * microtask — flushPromises()'s single setImmediate tick fires before it,
 * so a submit that goes through fileToBase64() needs a genuine elapsed
 * macrotask (a real setTimeout) for the read to actually complete.
 */
function waitForFileRead() {
  return new Promise((resolve) => setTimeout(resolve, 10));
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
        id: 'krb5',
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
  it('opens the form with username/password inputs', async () => {
    const wrapper = mountCard();
    await openForm(wrapper);

    expect(wrapper.find('input[type="text"]').exists()).toBe(true);
    expect(wrapper.find('input[type="password"]').exists()).toBe(true);
  });

  it('never renders a "remember this ticket" checkbox (removed — see the keytab-upload flow instead)', async () => {
    const wrapper = mountCard();
    expect(wrapper.find('input[type="checkbox"]').exists()).toBe(false);

    await openForm(wrapper);
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

    expect(requestKrb5Ticket).toHaveBeenCalledWith(
      'jdoe',
      'hunter2',
      undefined,
      undefined,
      undefined,
    );
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

describe('forget affordance', () => {
  it('does not render a Forget button when unlinked', () => {
    const wrapper = mountCard(false);
    expect(wrapper.find('button.kc__btn--forget').exists()).toBe(false);
  });

  it('renders a Forget button when linked', () => {
    const wrapper = mountCard(true);
    expect(wrapper.find('button.kc__btn--forget').exists()).toBe(true);
  });

  it('requires a second click to confirm, then calls unlinkIdentity with the provider id and emits revoked', async () => {
    vi.mocked(unlinkIdentity).mockResolvedValueOnce(undefined);
    const wrapper = mountCard(true);

    await wrapper.find('button.kc__btn--forget').trigger('click');
    expect(unlinkIdentity).not.toHaveBeenCalled();
    expect(wrapper.find('button.kc__btn--forget').text()).toMatch(/confirm/i);

    await wrapper.find('button.kc__btn--forget').trigger('click');
    await flushPromises();

    expect(unlinkIdentity).toHaveBeenCalledWith('krb5');
    expect(wrapper.emitted('revoked')).toEqual([[]]);
  });

  it('surfaces an error and does not emit revoked when unlinkIdentity fails', async () => {
    vi.mocked(unlinkIdentity).mockRejectedValueOnce(new Error('boom'));
    const wrapper = mountCard(true);

    await wrapper.find('button.kc__btn--forget').trigger('click');
    await wrapper.find('button.kc__btn--forget').trigger('click');
    await flushPromises();

    expect(wrapper.find('[role="alert"]').exists()).toBe(true);
    expect(wrapper.emitted('revoked')).toBeUndefined();
  });

  it('cancel on the forget row resets the armed confirmation without calling unlinkIdentity', async () => {
    // Earlier tests in this describe block also call unlinkIdentity('krb5');
    // clear its call history so this test's own not.toHaveBeenCalled()
    // assertion reflects only what happens below, regardless of run order.
    vi.mocked(unlinkIdentity).mockClear();
    const wrapper = mountCard(true);

    await wrapper.find('button.kc__btn--forget').trigger('click');
    expect(wrapper.find('button.kc__btn--forget').text()).toMatch(/confirm/i);

    await wrapper.find('.kc__forget-row button.kc__btn--cancel').trigger('click');

    expect(wrapper.find('button.kc__btn--forget').text()).toBe('Forget this ticket');
    expect(unlinkIdentity).not.toHaveBeenCalled();
  });

  it('opening the mint form (e.g. via "Refresh ticket") disarms a pending forget confirmation, even after the form is cancelled', async () => {
    // See the previous test's comment on clearing shared mock call history.
    vi.mocked(unlinkIdentity).mockClear();
    const wrapper = mountCard(true);

    // Arm the forget confirmation.
    await wrapper.find('button.kc__btn--forget').trigger('click');
    expect(wrapper.find('button.kc__btn--forget').text()).toMatch(/confirm/i);

    // Opening the mint form hides the forget row entirely — it must not
    // leave forgetArmed set for when the row reappears.
    await openForm(wrapper);
    await wrapper.find('button.kc__btn--cancel').trigger('click');

    // The forget row is back, but must require a fresh confirm click before
    // it would actually call unlinkIdentity.
    expect(wrapper.find('button.kc__btn--forget').text()).toBe('Forget this ticket');
    await wrapper.find('button.kc__btn--forget').trigger('click');
    expect(unlinkIdentity).not.toHaveBeenCalled();
  });

  it('opening the mint form clears a stale forgetError from a previous failed forget attempt', async () => {
    vi.mocked(unlinkIdentity).mockRejectedValueOnce(new Error('boom'));
    const wrapper = mountCard(true);

    await wrapper.find('button.kc__btn--forget').trigger('click');
    await wrapper.find('button.kc__btn--forget').trigger('click');
    await flushPromises();
    expect(wrapper.find('[role="alert"]').exists()).toBe(true);

    await openForm(wrapper);

    expect(wrapper.find('[role="alert"]').exists()).toBe(false);
  });
});

describe('keytab upload', () => {
  it('opens the keytab form with username/file inputs, separate from the password form', async () => {
    const wrapper = mountCard();
    await openKeytabForm(wrapper);

    expect(wrapper.find('input[type="text"]').exists()).toBe(true);
    expect(wrapper.find('input[type="file"]').exists()).toBe(true);
    // Separate action: the password form's password input must not appear.
    expect(wrapper.find('input[type="password"]').exists()).toBe(false);
  });

  it('opening the keytab form closes an already-open password form, and vice versa', async () => {
    const wrapper = mountCard();

    await openForm(wrapper);
    expect(wrapper.find('input[type="password"]').exists()).toBe(true);

    await openKeytabForm(wrapper);
    expect(wrapper.find('input[type="password"]').exists()).toBe(false);
    expect(wrapper.find('input[type="file"]').exists()).toBe(true);

    await openForm(wrapper);
    expect(wrapper.find('input[type="file"]').exists()).toBe(false);
    expect(wrapper.find('input[type="password"]').exists()).toBe(true);
  });

  it('reproduces the exact lxplus keytab-generation sequence in the instructions', async () => {
    const wrapper = mountCard();
    await openKeytabForm(wrapper);

    const text = wrapper.text().replace(/\s+/g, ' ');
    expect(text).toContain('ssh <username>@lxplus.cern.ch');
    expect(text).toContain('cern-get-keytab --keytab <username>.keytab --user');
    expect(text).toContain('kinit -kt <username>.keytab <username>@CERN.CH');
    expect(text).toContain('echo $?');
  });

  it('cancel closes the keytab form and clears both fields without submitting', async () => {
    const wrapper = mountCard();
    await openKeytabForm(wrapper);
    await fillKeytabForm(wrapper, 'jdoe', makeKeytabFile());

    await wrapper.find('form button.kc__btn--cancel').trigger('click');

    expect(wrapper.find('form').exists()).toBe(false);
    expect(linkKrb5Keytab).not.toHaveBeenCalled();

    await openKeytabForm(wrapper);
    expect((wrapper.find('input[type="text"]').element as HTMLInputElement).value).toBe('');
  });

  it('submit is disabled until both a username and a file are provided', async () => {
    const wrapper = mountCard();
    await openKeytabForm(wrapper);
    const submitBtn = wrapper.find('form button.kc__btn--submit');
    expect(submitBtn.attributes('disabled')).toBeDefined();

    await wrapper.find('input[type="text"]').setValue('jdoe');
    expect(submitBtn.attributes('disabled')).toBeDefined(); // no file yet

    await setKeytabFile(wrapper, makeKeytabFile());
    expect(submitBtn.attributes('disabled')).toBeUndefined();
  });

  it('reads the file, base64-encodes it, and calls linkKrb5Keytab with username + keytab_b64, closing the form and emitting linked', async () => {
    vi.mocked(linkKrb5Keytab).mockResolvedValueOnce(TICKET);
    const wrapper = mountCard();
    await openKeytabForm(wrapper);
    await fillKeytabForm(wrapper, 'jdoe', makeKeytabFile([1, 2, 3, 4]));

    await submit(wrapper);
    await waitForFileRead();
    await flushPromises();

    expect(linkKrb5Keytab).toHaveBeenCalledTimes(1);
    const [username, keytabB64] = vi.mocked(linkKrb5Keytab).mock.calls[0];
    expect(username).toBe('jdoe');
    expect(keytabB64).toBe(Buffer.from([1, 2, 3, 4]).toString('base64'));

    expect(wrapper.find('form').exists()).toBe(false);
    expect(wrapper.emitted('linked')).toEqual([[TICKET]]);
    expect(wrapper.text()).toContain('jdoe@CERN.CH');
  });

  it.each([
    [400, /username|password|keytab/i],
    [403, /revoked|expired/i],
    [422, /invalid/i],
    [429, /too many/i],
    [502, /unavailable/i],
  ])(
    'surfaces the krb5LinkErrorMessage text for a %i response and does not close the form or emit',
    async (status, expected) => {
      vi.mocked(linkKrb5Keytab).mockRejectedValueOnce(new APIError(status, 'Error', 'not-json'));
      const wrapper = mountCard();
      await openKeytabForm(wrapper);
      await fillKeytabForm(wrapper, 'jdoe', makeKeytabFile());

      await submit(wrapper);
      await waitForFileRead();
      await flushPromises();

      const alert = wrapper.find('[role="alert"]');
      expect(alert.exists()).toBe(true);
      expect(alert.text()).toMatch(expected);
      expect(wrapper.find('form').exists()).toBe(true);
      expect(wrapper.emitted('linked')).toBeUndefined();
    },
  );
});
