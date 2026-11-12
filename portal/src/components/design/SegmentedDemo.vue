<script setup lang="ts">
/**
 * SegmentedDemo.vue — the real SegmentedControl with its own state, as the
 * Usage page's range control uses it.
 */
import { ref } from 'vue';
import SegmentedControl from '../ui/SegmentedControl.vue';

const OPTIONS = [
  { value: '7', label: '7 days' },
  { value: '30', label: '30 days' },
  { value: '90', label: '90 days' },
];

const range = ref('30');
</script>

<template>
  <SegmentedControl v-model="range" :options="OPTIONS" aria-label="Range, example" />
</template>
