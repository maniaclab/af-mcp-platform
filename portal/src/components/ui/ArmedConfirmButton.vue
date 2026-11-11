<script setup lang="ts">
/**
 * ArmedConfirmButton.vue — two-step inline confirm for a destructive action
 * that does not warrant a dialog: the first click arms the button, the
 * second (now labelled with `armedLabel`) emits `confirm`, and Cancel
 * disarms. `v-model:armed` lets the owner disarm it, e.g. when the form it
 * sits beside opens.
 *
 * One button element carries both states, so a call site's own class hook
 * (passed to `triggerClass` and `confirmClass`) keeps matching one element.
 */
import { computed } from 'vue';

const props = defineProps<{
  label: string;
  armedLabel: string;
  busyLabel: string;
  busy?: boolean;
  triggerClass?: string;
  confirmClass?: string;
  cancelClass?: string;
}>();

const emit = defineEmits<{ confirm: [] }>();
const armed = defineModel<boolean>('armed', { default: false });

const text = computed(() => {
  if (!armed.value) return props.label;
  return props.busy ? props.busyLabel : props.armedLabel;
});

function onClick(): void {
  if (!armed.value) {
    armed.value = true;
    return;
  }
  emit('confirm');
}
</script>

<template>
  <span class="armed-confirm">
    <button
      type="button"
      class="af-btn danger s"
      :class="armed ? confirmClass : triggerClass"
      :disabled="busy"
      :aria-busy="busy"
      @click="onClick"
    >
      {{ text }}
    </button>
    <button
      v-if="armed && !busy"
      type="button"
      class="af-btn quiet s"
      :class="cancelClass"
      @click="armed = false"
    >
      Cancel
    </button>
  </span>
</template>

<style scoped>
.armed-confirm {
  display: inline-flex;
  flex-wrap: wrap;
  gap: var(--space-8);
}
</style>
