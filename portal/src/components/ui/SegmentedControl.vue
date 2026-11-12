<script setup lang="ts">
/**
 * SegmentedControl.vue — a single-choice toggle group (a Basecoat `.button-group`), e.g. the
 * trailing-window and catalog-filter pickers. Buttons rather than radios
 * because each choice applies immediately.
 */
defineProps<{
  options: { value: string; label: string }[];
  ariaLabel: string;
}>();

const model = defineModel<string>({ required: true });

function select(value: string): void {
  if (model.value !== value) model.value = value;
}
</script>

<template>
  <div class="button-group af-toggle" role="group" :aria-label="ariaLabel">
    <button
      v-for="opt in options"
      :key="opt.value"
      type="button"
      class="btn"
      data-variant="outline"
      data-size="sm"
      :aria-pressed="model === opt.value"
      @click="select(opt.value)"
    >
      {{ opt.label }}
    </button>
  </div>
</template>
