<script setup lang="ts">
/**
 * StatusMark.vue — a status word with its shape-coded mark. The mark is
 * decoration (shape and colour repeat the meaning); the word carries it, so
 * the mark is hidden from assistive tech.
 */
defineProps<{
  tone: 'ok' | 'warn' | 'bad' | 'info' | 'busy' | 'off';
  label?: string;
}>();
</script>

<template>
  <span class="af-st">
    <span class="af-mark" :class="tone" aria-hidden="true"></span>
    <span
      ><slot>{{ label }}</slot></span
    >
  </span>
</template>
