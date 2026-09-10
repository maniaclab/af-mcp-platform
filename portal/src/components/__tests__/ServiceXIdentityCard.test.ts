/**
 * Component tests for ServiceXIdentityCard.vue — the Identities page's card
 * for a servicex-token entry (link_mechanism: "servicex-token"). Simpler
 * than Krb5IdentityCard.vue: one action (paste a refresh token), no
 * keytab-equivalent durable upload, no hands-free-attempt-before-form flow
 * — mirrors its submit/forget test structure, minus those two.
 */
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { ServiceXTokenMetadata } from '../../lib/api';

// Mirrors Krb5IdentityCard.test.ts's pattern: mock only the functions this
// component calls, but re-implement APIError/SessionExpiredError faithfully
// so servicexIdentity.ts's real servicexLinkErrorMessage (imported by the
// component, NOT mocked here) still does its real instanceof-based
// branching against errors constructed in this file.
vi.mock('../../lib/api', () => ({
  linkServiceXToken: vi.fn(),
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

import { APIError, linkServiceXToken, unlinkIdentity } from '../../lib/api';
import ServiceXIdentityCard from '../ServiceXIdentityCard.vue';

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

const TOKEN_METADATA: ServiceXTokenMetadata = {
  target: 'servicex-target',
  expires_at: '2026-09-04T00:00:00+00:00',
  remaining_seconds: 3600,
};

function mountCard(linked = false, externalLoginUrl?: string | null): VueWrapper {
  return mount(ServiceXIdentityCard, {
    props: {
      id: 'servicex',
      linked,
      display_name: 'ServiceX',
      enables: 'On-demand data delivery via servicex-mcp',
      external_login_url: externalLoginUrl,
    },
  });
}

async function openForm(wrapper: VueWrapper) {
  const btnClass = wrapper.find('button.sc__btn--link').exists()
    ? 'button.sc__btn--link'
    : 'button.sc__btn--relink';
  await wrapper.find(btnClass).trigger('click');
}

async function fillForm(wrapper: VueWrapper, token: string) {
  await wrapper.find('input[type="password"]').setValue(token);
}

function submit(wrapper: VueWrapper) {
  return wrapper.find('form').trigger('submit');
}

beforeEach(() => {
  vi.restoreAllMocks();
});

describe('badge and action button', () => {
  it('renders a "not linked" badge and a Link button when unlinked', () => {
    const wrapper = mountCard(false);
    expect(wrapper.text()).toContain('not linked');
    expect(wrapper.find('button.sc__btn--link').text()).toBe('Link ServiceX token');
  });

  it('renders a "linked" badge and a Re-link button when linked', () => {
    const wrapper = mountCard(true);
    expect(wrapper.text()).toContain('linked');
    expect(wrapper.find('button.sc__btn--relink').text()).toBe('Re-link');
  });

  it('renders powers chips when provided', () => {
    const wrapper = mount(ServiceXIdentityCard, {
      props: {
        id: 'servicex',
        linked: false,
        display_name: 'ServiceX',
        enables: 'On-demand data delivery via servicex-mcp',
        powers: ['servicex'],
      },
    });
    expect(wrapper.text()).toContain('servicex');
  });

  it('does not render the external-login button when external_login_url is unset', () => {
    const wrapper = mountCard(false, null);
    expect(wrapper.find('a.sc__btn--external').exists()).toBe(false);
  });

  it('renders the external-login button with the configured href when set', () => {
    const wrapper = mountCard(false, 'https://servicex.example.org/api-token');
    const link = wrapper.find('a.sc__btn--external');
    expect(link.exists()).toBe(true);
    expect(link.attributes('href')).toBe('https://servicex.example.org/api-token');
    expect(link.attributes('target')).toBe('_blank');
    expect(link.attributes('rel')).toBe('noopener');
  });
});

describe('form open/close', () => {
  it('opens the form with a password-masked token input', async () => {
    const wrapper = mountCard();
    await openForm(wrapper);

    expect(wrapper.find('input[type="password"]').exists()).toBe(true);
  });

  it('cancel closes the form and clears the field without submitting', async () => {
    const wrapper = mountCard();
    await openForm(wrapper);
    await fillForm(wrapper, 'a-refresh-token');

    await wrapper.find('button.sc__btn--cancel').trigger('click');

    expect(wrapper.find('form').exists()).toBe(false);
    expect(linkServiceXToken).not.toHaveBeenCalled();

    // Re-open and confirm the field didn't survive the cancel.
    await openForm(wrapper);
    expect((wrapper.find('input[type="password"]').element as HTMLInputElement).value).toBe('');
  });
});

describe('submit disabled state', () => {
  it('is disabled while the token field is empty', async () => {
    const wrapper = mountCard();
    await openForm(wrapper);
    const submitBtn = wrapper.find('button.sc__btn--submit');
    expect(submitBtn.attributes('disabled')).toBeDefined();

    await wrapper.find('input[type="password"]').setValue('a-refresh-token');
    expect(submitBtn.attributes('disabled')).toBeUndefined();
  });

  it('is disabled while the request is in flight', async () => {
    const d = deferred<ServiceXTokenMetadata>();
    vi.mocked(linkServiceXToken).mockReturnValueOnce(d.promise);
    const wrapper = mountCard();
    await openForm(wrapper);
    await fillForm(wrapper, 'a-refresh-token');

    await submit(wrapper);
    expect(wrapper.find('button.sc__btn--submit').attributes('disabled')).toBeDefined();

    d.resolve(TOKEN_METADATA);
    await flushPromises();
  });
});

describe('successful submission', () => {
  it('calls linkServiceXToken with the token, closes the form, emits linked, and shows the result', async () => {
    vi.mocked(linkServiceXToken).mockResolvedValueOnce(TOKEN_METADATA);
    const wrapper = mountCard();
    await openForm(wrapper);
    await fillForm(wrapper, 'a-refresh-token');

    await submit(wrapper);
    await flushPromises();

    expect(linkServiceXToken).toHaveBeenCalledWith('a-refresh-token');
    expect(wrapper.find('form').exists()).toBe(false);
    expect(wrapper.emitted('linked')).toEqual([[TOKEN_METADATA]]);
    expect(wrapper.text()).toContain('Access token expires');
  });

  it('clears the refresh token from component state before the request resolves', async () => {
    const d = deferred<ServiceXTokenMetadata>();
    vi.mocked(linkServiceXToken).mockReturnValueOnce(d.promise);
    const wrapper = mountCard();
    await openForm(wrapper);
    await fillForm(wrapper, 'a-refresh-token');

    await submit(wrapper);

    // The request is still pending, but the field must already be cleared
    // from state — captured and blanked before the await, exactly like
    // X509IdentityCard.vue's handleSubmit does for its passphrase.
    expect((wrapper.find('input[type="password"]').element as HTMLInputElement).value).toBe('');

    d.resolve(TOKEN_METADATA);
    await flushPromises();
  });
});

describe('failed submission', () => {
  it('clears the refresh token from component state before the request rejects', async () => {
    const d = deferred<ServiceXTokenMetadata>();
    vi.mocked(linkServiceXToken).mockReturnValueOnce(d.promise);
    const wrapper = mountCard();
    await openForm(wrapper);
    await fillForm(wrapper, 'a-bad-token');

    await submit(wrapper);

    expect((wrapper.find('input[type="password"]').element as HTMLInputElement).value).toBe('');

    d.reject(new APIError(400, 'Bad Request', 'not-json'));
    await flushPromises();

    // Still cleared, and the form stays open with the field empty for retry.
    expect((wrapper.find('input[type="password"]').element as HTMLInputElement).value).toBe('');
  });

  it.each([
    [400, /token/i],
    [502, /unavailable/i],
  ])(
    'surfaces the servicexLinkErrorMessage text for a %i response and does not close the form or emit',
    async (status, expected) => {
      vi.mocked(linkServiceXToken).mockRejectedValueOnce(new APIError(status, 'Error', 'not-json'));
      const wrapper = mountCard();
      await openForm(wrapper);
      await fillForm(wrapper, 'a-bad-token');

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
    expect(wrapper.find('button.sc__btn--forget').exists()).toBe(false);
  });

  it('renders a Forget button when linked', () => {
    const wrapper = mountCard(true);
    expect(wrapper.find('button.sc__btn--forget').exists()).toBe(true);
  });

  it('requires a second click to confirm, then calls unlinkIdentity with the provider id and emits revoked', async () => {
    vi.mocked(unlinkIdentity).mockResolvedValueOnce(undefined);
    const wrapper = mountCard(true);

    await wrapper.find('button.sc__btn--forget').trigger('click');
    expect(unlinkIdentity).not.toHaveBeenCalled();
    expect(wrapper.find('button.sc__btn--forget').text()).toMatch(/confirm/i);

    await wrapper.find('button.sc__btn--forget').trigger('click');
    await flushPromises();

    expect(unlinkIdentity).toHaveBeenCalledWith('servicex');
    expect(wrapper.emitted('revoked')).toEqual([[]]);
  });

  it('surfaces an error and does not emit revoked when unlinkIdentity fails', async () => {
    vi.mocked(unlinkIdentity).mockRejectedValueOnce(new Error('boom'));
    const wrapper = mountCard(true);

    await wrapper.find('button.sc__btn--forget').trigger('click');
    await wrapper.find('button.sc__btn--forget').trigger('click');
    await flushPromises();

    expect(wrapper.find('[role="alert"]').exists()).toBe(true);
    expect(wrapper.emitted('revoked')).toBeUndefined();
  });

  it('cancel on the forget row resets the armed confirmation without calling unlinkIdentity', async () => {
    vi.mocked(unlinkIdentity).mockClear();
    const wrapper = mountCard(true);

    await wrapper.find('button.sc__btn--forget').trigger('click');
    expect(wrapper.find('button.sc__btn--forget').text()).toMatch(/confirm/i);

    await wrapper.find('.sc__forget-row button.sc__btn--cancel').trigger('click');

    expect(wrapper.find('button.sc__btn--forget').text()).toBe('Forget this token');
    expect(unlinkIdentity).not.toHaveBeenCalled();
  });
});
