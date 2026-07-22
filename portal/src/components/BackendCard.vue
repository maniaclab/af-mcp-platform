<script setup lang="ts">
import { ref, computed } from 'vue';
import type { BackendGroup } from '../lib/api';
import ToolTable from './ToolTable.vue';

const props = defineProps<{
  backend: BackendGroup;
}>();

const expanded = ref(false);

// computed() so the badges track the parent's filtered `tools`.
const stateChangeCount = computed(
  () => props.backend.tools.filter((t) => t.action_type === 'state_change').length,
);
const readCount = computed(
  () => props.backend.tools.filter((t) => t.action_type === 'read').length,
);
</script>

<template>
  <div class="bc" :class="{ 'bc--expanded': expanded }">
    <!-- Header row — always visible -->
    <button
      class="bc__header"
      :aria-expanded="expanded"
      :aria-controls="`tools-${backend.backend}`"
      @click="expanded = !expanded"
    >
      <div class="bc__header-left">
        <span class="bc__prefix">{{ backend.backend }}</span>
      </div>

      <div class="bc__header-right">
        <!-- Capability badges -->
        <span
          v-for="cap in backend.capabilities"
          :key="cap"
          class="bc__cap-badge"
          :title="`Requires capability: ${cap}`"
        >
          {{ cap }}
        </span>

        <!-- Tool counts -->
        <span v-if="readCount > 0" class="bc__count bc__count--read"> {{ readCount }} read </span>
        <span v-if="stateChangeCount > 0" class="bc__count bc__count--state">
          {{ stateChangeCount }} write
        </span>

        <!-- Expand/collapse chevron -->
        <svg
          class="bc__chevron"
          :class="{ 'bc__chevron--open': expanded }"
          width="14"
          height="14"
          viewBox="0 0 14 14"
          fill="none"
          aria-hidden="true"
        >
          <path
            d="M3 5L7 9L11 5"
            stroke="currentColor"
            stroke-width="1.5"
            stroke-linecap="round"
            stroke-linejoin="round"
          />
        </svg>
      </div>
    </button>

    <!-- Tool list — visible when expanded -->
    <div
      :id="`tools-${backend.backend}`"
      class="bc__tools"
      :class="{ 'bc__tools--visible': expanded }"
      role="region"
      :aria-label="`Tools for ${backend.backend}`"
    >
      <ToolTable :tools="backend.tools" />
    </div>
  </div>
</template>

<style scoped>
.bc {
  border: 1px solid var(--color-af-border);
  border-radius: 4px;
  overflow: hidden;
  transition: border-color 150ms;
}

.bc:hover,
.bc--expanded {
  border-color: var(--color-af-muted);
}

.bc--expanded {
  border-color: rgb(from var(--color-af-teal) r g b / 0.25);
}

.bc__header {
  width: 100%;
  display: flex;
  align-items: center;
  gap: 1rem;
  padding: 0.875rem 1rem;
  background: var(--color-af-surface);
  cursor: pointer;
  text-align: left;
  border: none;
  transition: background 120ms;
}

.bc__header:hover,
.bc__header:focus-visible {
  background: #1a2235;
  outline: none;
}

.bc__header:focus-visible {
  outline: 2px solid var(--color-af-teal);
  outline-offset: -2px;
}

.bc__header-left {
  flex: 1;
  display: flex;
  align-items: baseline;
  gap: 0.75rem;
  min-width: 0;
  flex-wrap: wrap;
}

.bc__prefix {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.75rem;
  font-weight: 600;
  letter-spacing: 0.04em;
  color: var(--color-af-teal);
  white-space: nowrap;
}

.bc__name {
  font-family: 'IBM Plex Sans', system-ui, sans-serif;
  font-size: 0.9375rem;
  font-weight: 600;
  color: var(--color-af-text);
  white-space: nowrap;
}

.bc__desc {
  font-family: 'IBM Plex Sans', system-ui, sans-serif;
  font-size: 0.8125rem;
  color: var(--color-af-dim);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.bc__header-right {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  flex-shrink: 0;
}

.bc__cap-badge {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.5625rem;
  font-weight: 600;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  padding: 0.1875rem 0.5rem;
  border-radius: 2px;
  background: rgb(from var(--color-af-teal) r g b / 0.08);
  color: var(--color-af-teal);
  border: 1px solid rgb(from var(--color-af-teal) r g b / 0.2);
}

.bc__count {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.5625rem;
  font-weight: 600;
  letter-spacing: 0.06em;
  text-transform: uppercase;
  padding: 0.1875rem 0.5rem;
  border-radius: 2px;
}

.bc__count--read {
  background: rgb(from var(--color-af-green) r g b / 0.08);
  color: var(--color-af-green);
  border: 1px solid rgb(from var(--color-af-green) r g b / 0.18);
}

.bc__count--state {
  background: rgb(from var(--color-af-amber) r g b / 0.08);
  color: var(--color-af-amber);
  border: 1px solid rgb(from var(--color-af-amber) r g b / 0.18);
}

.bc__chevron {
  color: var(--color-af-dim);
  transition:
    transform 200ms,
    color 150ms;
  flex-shrink: 0;
}
.bc__chevron--open {
  transform: rotate(180deg);
  color: var(--color-af-teal);
}

.bc__tools {
  display: none;
  border-top: 1px solid var(--color-af-border);
  padding: 0.25rem 0;
  background: rgb(from var(--color-af-void) r g b / 0.5);
}

.bc__tools--visible {
  display: block;
}

@media (max-width: 640px) {
  .bc__desc {
    display: none;
  }
  .bc__cap-badge {
    display: none;
  }
}
</style>
