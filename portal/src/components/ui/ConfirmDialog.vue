<script setup lang="ts">
/**
 * ConfirmDialog.vue — a modal confirm on the native <dialog> (Basecoat's `.dialog`):
 * the platform supplies the focus trap, inert page behind it, and Escape.
 *
 * Confirm only emits; the caller decides when to close (it may need to show
 * `busy` while the action runs). Focus starts on Cancel so the destructive
 * button is never the default, and returns to whatever was focused before
 * opening, however the dialog closes.
 */
import { onMounted, useId, useTemplateRef, watch } from 'vue';

withDefaults(
  defineProps<{
    title: string;
    confirmLabel: string;
    cancelLabel?: string;
    busy?: boolean;
    busyLabel?: string;
    danger?: boolean;
  }>(),
  { cancelLabel: 'Cancel', busy: false, busyLabel: undefined, danger: false },
);

const emit = defineEmits<{ confirm: []; cancel: [] }>();
const open = defineModel<boolean>('open', { default: false });

const titleId = useId();
const dialog = useTemplateRef<HTMLDialogElement>('dialog');
const cancelButton = useTemplateRef<HTMLButtonElement>('cancelButton');
let returnFocusTo: HTMLElement | null = null;

function show(el: HTMLDialogElement): void {
  // Without showModal (jsdom, very old browsers) the open attribute still
  // renders the dialog, just without the modal behaviour.
  if (typeof el.showModal === 'function') el.showModal();
  else el.setAttribute('open', '');
}

function hide(el: HTMLDialogElement): void {
  if (typeof el.close === 'function') {
    el.close();
  } else {
    el.removeAttribute('open');
    el.dispatchEvent(new Event('close'));
  }
}

function sync(isOpen: boolean): void {
  const el = dialog.value;
  if (!el) return;
  if (isOpen && !el.open) {
    returnFocusTo = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    show(el);
    cancelButton.value?.focus();
  } else if (!isOpen && el.open) {
    hide(el);
  }
}

watch(open, sync, { flush: 'post' });
onMounted(() => sync(open.value));

function cancel(): void {
  emit('cancel');
  open.value = false;
}

// The native `close` event fires for Escape as well as for hide(), so this
// is the one place focus is restored. A close while the model is still open
// can only be Escape (or the browser's close request): treat it as Cancel.
function onClose(): void {
  if (open.value) cancel();
  returnFocusTo?.focus();
  returnFocusTo = null;
}
</script>

<template>
  <dialog ref="dialog" class="dialog af-modal" :aria-labelledby="titleId" @close="onClose">
    <div>
      <header>
        <h2 :id="titleId">{{ title }}</h2>
      </header>
      <section><slot /></section>
      <footer>
        <button ref="cancelButton" type="button" class="btn" data-variant="ghost" @click="cancel">
          {{ cancelLabel }}
        </button>
        <button
          type="button"
          class="btn"
          :class="{ 'af-danger': danger }"
          :data-variant="danger ? 'outline' : undefined"
          :disabled="busy"
          :aria-busy="busy"
          @click="emit('confirm')"
        >
          {{ busy && busyLabel ? busyLabel : confirmLabel }}
        </button>
      </footer>
    </div>
  </dialog>
</template>
