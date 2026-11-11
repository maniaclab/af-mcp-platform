/**
 * Component tests for ConfirmDialog.vue.
 *
 * jsdom does not implement HTMLDialogElement.showModal()/close(), so these
 * tests stub them the way a supporting browser behaves (toggle `open`, fire
 * `close` on close, including for Escape). A separate test covers the
 * component's own fallback when the methods are missing.
 */
import { mount } from '@vue/test-utils';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { defineComponent, h, ref } from 'vue';
import ConfirmDialog from '../ConfirmDialog.vue';

function stubDialogApi() {
  HTMLDialogElement.prototype.showModal = vi.fn(function (this: HTMLDialogElement) {
    this.setAttribute('open', '');
  });
  HTMLDialogElement.prototype.close = vi.fn(function (this: HTMLDialogElement) {
    this.removeAttribute('open');
    this.dispatchEvent(new Event('close'));
  });
}

function unstubDialogApi() {
  // @ts-expect-error -- deleting a test-only stub
  delete HTMLDialogElement.prototype.showModal;
  // @ts-expect-error -- deleting a test-only stub
  delete HTMLDialogElement.prototype.close;
}

const props = { open: false, title: 'Revoke token?', confirmLabel: 'Revoke' };

function mountDialog(extra: Record<string, unknown> = {}) {
  return mount(ConfirmDialog, {
    props: { ...props, ...extra },
    slots: { default: '<p class="body">This cannot be undone.</p>' },
    attachTo: document.body,
  });
}

describe('ConfirmDialog', () => {
  beforeEach(stubDialogApi);
  afterEach(() => {
    unstubDialogApi();
    document.body.innerHTML = '';
  });

  it('renders title, body, and buttons with the confirming action last', () => {
    const w = mountDialog();
    const dialog = w.find('dialog');
    expect(dialog.classes()).toContain('dialog');
    expect(dialog.attributes('aria-labelledby')).toBe(w.find('h2').attributes('id'));
    expect(w.find('h2').text()).toBe('Revoke token?');
    expect(w.find('.body').exists()).toBe(true);
    const buttons = w.findAll('footer button');
    expect(buttons.map((b) => b.text())).toEqual(['Cancel', 'Revoke']);
    expect(buttons[0].attributes('data-variant')).toBe('ghost');
    expect(buttons[1].attributes('data-variant')).toBeUndefined();
    expect(buttons[1].classes()).not.toContain('af-danger');
  });

  it('uses the danger style and custom cancel label', () => {
    const w = mountDialog({ danger: true, cancelLabel: 'Keep it' });
    const buttons = w.findAll('footer button');
    expect(buttons[0].text()).toBe('Keep it');
    expect(buttons[1].classes()).toContain('af-danger');
    expect(buttons[1].attributes('data-variant')).toBe('outline');
  });

  it('opens modally and focuses Cancel when open becomes true', async () => {
    const w = mountDialog();
    await w.setProps({ open: true } as never);
    await w.vm.$nextTick();
    expect(HTMLDialogElement.prototype.showModal).toHaveBeenCalledTimes(1);
    expect(document.activeElement).toBe(w.findAll('footer button')[0].element);
  });

  it('closes the native dialog when open becomes false', async () => {
    const w = mountDialog({ open: true });
    await w.vm.$nextTick();
    await w.setProps({ open: false } as never);
    expect(HTMLDialogElement.prototype.close).toHaveBeenCalled();
    expect(w.find('dialog').attributes('open')).toBeUndefined();
  });

  it('emits confirm without closing itself', async () => {
    const w = mountDialog({ open: true });
    await w.vm.$nextTick();
    await w.findAll('footer button')[1].trigger('click');
    expect(w.emitted('confirm')).toHaveLength(1);
    expect(w.emitted('update:open')).toBeUndefined();
  });

  it('Cancel emits cancel once and requests close', async () => {
    const w = mountDialog({ open: true });
    await w.vm.$nextTick();
    await w.findAll('footer button')[0].trigger('click');
    expect(w.emitted('cancel')).toHaveLength(1);
    expect(w.emitted('update:open')?.[0]).toEqual([false]);
  });

  it('shows busyLabel and disables confirm while busy', () => {
    const w = mountDialog({ busy: true, busyLabel: 'Revoking…' });
    const confirm = w.findAll('footer button')[1];
    expect(confirm.text()).toBe('Revoking…');
    expect(confirm.attributes('disabled')).toBeDefined();
  });

  it('returns focus to the previously focused element on close', async () => {
    const trigger = document.createElement('button');
    document.body.appendChild(trigger);
    trigger.focus();

    const w = mountDialog();
    await w.setProps({ open: true } as never);
    await w.vm.$nextTick();
    expect(document.activeElement).not.toBe(trigger);

    await w.setProps({ open: false } as never);
    expect(document.activeElement).toBe(trigger);
  });

  it('treats Escape (a native close while open) as cancel and restores focus', async () => {
    const trigger = document.createElement('button');
    document.body.appendChild(trigger);
    trigger.focus();

    const w = mountDialog();
    await w.setProps({ open: true } as never);
    await w.vm.$nextTick();

    // What the browser does on Escape: closes the dialog and fires `close`.
    w.find('dialog').element.removeAttribute('open');
    await w.find('dialog').trigger('close');

    expect(w.emitted('cancel')).toHaveLength(1);
    expect(w.emitted('update:open')?.at(-1)).toEqual([false]);
    expect(document.activeElement).toBe(trigger);
  });

  it('works under v-model:open end to end', async () => {
    const Host = defineComponent({
      setup() {
        const open = ref(false);
        const confirmed = ref(0);
        return () =>
          h('div', [
            h('button', { id: 'opener', onClick: () => (open.value = true) }, 'Open'),
            h(
              ConfirmDialog,
              {
                open: open.value,
                'onUpdate:open': (v: boolean) => (open.value = v),
                title: 'T',
                confirmLabel: 'Go',
                onConfirm: () => {
                  confirmed.value += 1;
                  open.value = false;
                },
              },
              () => 'body',
            ),
            h('span', { id: 'count' }, String(confirmed.value)),
          ]);
      },
    });
    const w = mount(Host, { attachTo: document.body });
    const opener = w.find('#opener');
    (opener.element as HTMLElement).focus();
    await opener.trigger('click');
    await w.vm.$nextTick();
    expect(w.find('dialog').attributes('open')).toBeDefined();

    await w.findAll('footer button')[1].trigger('click');
    expect(w.find('#count').text()).toBe('1');
    expect(w.find('dialog').attributes('open')).toBeUndefined();
    expect(document.activeElement).toBe(opener.element);
  });

  it('degrades to the open attribute where showModal is unavailable', async () => {
    unstubDialogApi();
    const w = mountDialog();
    await w.setProps({ open: true } as never);
    expect(w.find('dialog').attributes('open')).toBeDefined();
    await w.setProps({ open: false } as never);
    expect(w.find('dialog').attributes('open')).toBeUndefined();
  });
});
