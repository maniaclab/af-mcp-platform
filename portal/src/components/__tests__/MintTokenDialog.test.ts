/**
 * Component contract tests for MintTokenDialog.vue: the parent opens it via
 * the exposed `open(trigger)`, it mints through the API, reveals the token
 * once, scrubs it on close, and emits `done` only when the user presses Done.
 */
import { flushPromises, mount } from '@vue/test-utils';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../lib/api', () => ({
  mintToken: vi.fn(),
  fetchPermissions: vi.fn(),
}));

import { fetchPermissions, mintToken } from '../../lib/api';
import MintTokenDialog from '../MintTokenDialog.vue';

const MINTED = {
  token: 'mcp_pat_SECRET',
  lookup_id: 'NEW1',
  name: 'my-client',
  note: null,
  expires_at: null,
  permission_grant: null,
};

// astro check types .vue imports as Astro components, so the exposed method is declared here.
interface MintDialogApi {
  open(trigger: HTMLButtonElement): Promise<void>;
}
const api = (wrapper: { vm: unknown }) => wrapper.vm as MintDialogApi;

async function mountOpen() {
  const wrapper = mount(MintTokenDialog, {
    props: { brokerOrigin: 'https://broker.example.org' },
    attachTo: document.body,
  });
  await flushPromises();
  const trigger = document.createElement('button');
  document.body.appendChild(trigger);
  await api(wrapper).open(trigger);
  await flushPromises();
  return { wrapper, trigger };
}

beforeEach(() => {
  vi.resetAllMocks();
  vi.mocked(fetchPermissions).mockResolvedValue({ grants: [] } as never);
  HTMLDialogElement.prototype.showModal = vi.fn(function (this: HTMLDialogElement) {
    this.setAttribute('open', '');
  });
  HTMLDialogElement.prototype.close = vi.fn(function (this: HTMLDialogElement) {
    this.removeAttribute('open');
    this.dispatchEvent(new Event('close'));
  });
});

afterEach(() => {
  // @ts-expect-error -- deleting a test-only stub
  delete HTMLDialogElement.prototype.showModal;
  // @ts-expect-error -- deleting a test-only stub
  delete HTMLDialogElement.prototype.close;
  document.body.innerHTML = '';
});

describe('MintTokenDialog', () => {
  it('is closed until open() is called, then shows the empty form', async () => {
    const wrapper = mount(MintTokenDialog, {
      props: { brokerOrigin: '' },
      attachTo: document.body,
    });
    await flushPromises();
    expect(wrapper.find('dialog[open]').exists()).toBe(false);

    await api(wrapper).open(document.createElement('button'));

    expect(wrapper.find('dialog[open] #tp-name').exists()).toBe(true);
    expect((wrapper.get('#tp-name').element as HTMLInputElement).value).toBe('');
  });

  it('mints with the form values and reveals the token', async () => {
    vi.mocked(mintToken).mockResolvedValue(MINTED as never);
    const { wrapper } = await mountOpen();

    await wrapper.get('#tp-name').setValue('  my-client  ');
    await wrapper.get('#tp-ttl').setValue('30');
    await wrapper.get('form').trigger('submit');
    await flushPromises();

    expect(mintToken).toHaveBeenCalledWith('my-client', undefined, 30, false, undefined);
    expect(wrapper.get('dialog').text()).toContain('mcp_pat_SECRET');
  });

  it('shows a mint failure in the form and keeps it open', async () => {
    vi.mocked(mintToken).mockRejectedValue(new Error('duplicate name'));
    const { wrapper } = await mountOpen();

    await wrapper.get('form').trigger('submit');
    await flushPromises();

    expect(wrapper.get('form [role="alert"]').text()).toContain('duplicate name');
    expect(wrapper.find('dialog[open]').exists()).toBe(true);
  });

  it('emits done and scrubs the token when Done is pressed', async () => {
    vi.mocked(mintToken).mockResolvedValue(MINTED as never);
    const { wrapper } = await mountOpen();
    await wrapper.get('form').trigger('submit');
    await flushPromises();

    await wrapper.get('footer .btn').trigger('click');
    await flushPromises();

    expect(wrapper.emitted('done')).toHaveLength(1);
    expect(wrapper.find('dialog[open]').exists()).toBe(false);
    expect(wrapper.text()).not.toContain('mcp_pat_SECRET');
  });

  it('scrubs the token without emitting done when the dialog is dismissed', async () => {
    vi.mocked(mintToken).mockResolvedValue(MINTED as never);
    const { wrapper } = await mountOpen();
    await wrapper.get('form').trigger('submit');
    await flushPromises();

    wrapper.get('dialog').element.dispatchEvent(new Event('close'));
    await flushPromises();

    expect(wrapper.emitted('done')).toBeUndefined();
    expect(wrapper.text()).not.toContain('mcp_pat_SECRET');
  });

  it('returns focus to the trigger on close', async () => {
    const { wrapper, trigger } = await mountOpen();
    const focus = vi.spyOn(trigger, 'focus');

    wrapper.get('dialog').element.dispatchEvent(new Event('close'));

    expect(focus).toHaveBeenCalled();
  });
});
