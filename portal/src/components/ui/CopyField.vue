<script setup lang="ts">
/**
 * CopyField.vue — a read-only value with a Copy button (`.af-copy`).
 *
 * The button reads "Copied" for two seconds after a successful copy. A
 * polite live region repeats the outcome for screen readers (the button's own
 * text change is not announced) and carries the failure message, which stays
 * visible so the user can select the value by hand.
 */
import { Copy } from '@lucide/vue';
import { computed, onBeforeUnmount, ref } from 'vue';
import { copyText } from '../../lib/clipboard';

const COPIED_RESET_MS = 2000;

const props = withDefaults(
  defineProps<{
    value: string;
    /** Accessible name of the button; keep the word "Copy" in it. */
    label?: string;
    /** Wrap a long value (a snippet) instead of truncating one line. */
    multiline?: boolean;
  }>(),
  { label: 'Copy', multiline: false },
);

const copied = ref(false);
const failed = ref(false);
let resetTimer: ReturnType<typeof setTimeout> | undefined;

const status = computed(() => {
  if (copied.value) return 'Copied to clipboard';
  if (failed.value) return 'Copy failed — select and copy manually';
  return '';
});

async function copy(): Promise<void> {
  clearTimeout(resetTimer);
  failed.value = false;
  copied.value = await copyText(props.value);
  failed.value = !copied.value;
  if (copied.value) {
    resetTimer = setTimeout(() => {
      copied.value = false;
    }, COPIED_RESET_MS);
  }
}

onBeforeUnmount(() => clearTimeout(resetTimer));
</script>

<template>
  <div class="af-copy" :class="{ 'copy--multiline': multiline }">
    <pre v-if="multiline" class="copy__pre"><code class="copy__value">{{ value }}</code></pre>
    <code v-else class="copy__value">{{ value }}</code>
    <button type="button" class="af-btn secondary s" :aria-label="label" @click="copy">
      <Copy class="af-icon" :size="16" aria-hidden="true" />
      {{ copied ? 'Copied' : 'Copy' }}
    </button>
    <span role="status" :class="failed ? 'copy__failed' : 'sr-only'">{{ status }}</span>
  </div>
</template>

<style scoped>
.copy__value {
  font-family: var(--font-mono);
}

/* A snippet needs its full height and width; the single-line box is a
 * fixed-height control. */
.copy--multiline {
  height: auto;
  max-width: none;
  align-items: flex-start;
  padding-block: var(--space-8);
}

.copy__pre {
  flex: 1;
  min-width: 0;
  margin: 0;
}

.copy__pre .copy__value {
  white-space: pre-wrap;
  overflow-wrap: anywhere;
  overflow: visible;
}

.copy__failed {
  font-size: var(--text-13);
  color: var(--color-af-bad);
}
</style>
