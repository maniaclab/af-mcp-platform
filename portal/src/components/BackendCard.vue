<script setup lang="ts">
import { ref } from 'vue';
import type { CatalogEntry } from '../lib/api';
import ToolTable from './ToolTable.vue';

const props = defineProps<{
  backend: CatalogEntry;
}>();

const expanded = ref(false);

const stateChangeCount = props.backend.tools.filter(t => t.action_type === 'state_change').length;
const readCount = props.backend.tools.filter(t => t.action_type === 'read').length;
</script>

<template>
  <div class="bc" :class="{ 'bc--expanded': expanded }">
    <!-- Header row — always visible -->
    <button
      class="bc__header"
      :aria-expanded="expanded"
      :aria-controls="`tools-${backend.prefix}`"
      @click="expanded = !expanded"
    >
      <div class="bc__header-left">
        <span class="bc__prefix">{{ backend.prefix }}</span>
        <span class="bc__name">{{ backend.backend }}</span>
        <span v-if="backend.description" class="bc__desc">{{ backend.description }}</span>
      </div>

      <div class="bc__header-right">
        <!-- Capability badge -->
        <span class="bc__cap-badge" :title="`Requires capability: ${backend.capability}`">
          {{ backend.capability }}
        </span>

        <!-- Tool counts -->
        <span v-if="readCount > 0" class="bc__count bc__count--read">
          {{ readCount }} read
        </span>
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
          <path d="M3 5L7 9L11 5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
      </div>
    </button>

    <!-- Tool list — visible when expanded -->
    <div
      :id="`tools-${backend.prefix}`"
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
  border: 1px solid #1F2937;
  border-radius: 4px;
  overflow: hidden;
  transition: border-color 150ms;
}

.bc:hover,
.bc--expanded {
  border-color: #374151;
}

.bc--expanded {
  border-color: rgba(0, 212, 200, 0.25);
}

.bc__header {
  width: 100%;
  display: flex;
  align-items: center;
  gap: 1rem;
  padding: 0.875rem 1rem;
  background: #111827;
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
  outline: 2px solid #00D4C8;
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
  color: #00D4C8;
  white-space: nowrap;
}

.bc__name {
  font-family: 'IBM Plex Sans', system-ui, sans-serif;
  font-size: 0.9375rem;
  font-weight: 600;
  color: #E8ECF0;
  white-space: nowrap;
}

.bc__desc {
  font-family: 'IBM Plex Sans', system-ui, sans-serif;
  font-size: 0.8125rem;
  color: #6B7280;
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
  background: rgba(0, 212, 200, 0.08);
  color: #00D4C8;
  border: 1px solid rgba(0, 212, 200, 0.2);
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
  background: rgba(16, 185, 129, 0.08);
  color: #10B981;
  border: 1px solid rgba(16, 185, 129, 0.18);
}

.bc__count--state {
  background: rgba(245, 158, 11, 0.08);
  color: #F59E0B;
  border: 1px solid rgba(245, 158, 11, 0.18);
}

.bc__chevron {
  color: #6B7280;
  transition: transform 200ms, color 150ms;
  flex-shrink: 0;
}
.bc__chevron--open {
  transform: rotate(180deg);
  color: #00D4C8;
}

.bc__tools {
  display: none;
  border-top: 1px solid #1F2937;
  padding: 0.25rem 0;
  background: rgba(10, 14, 26, 0.5);
}

.bc__tools--visible {
  display: block;
}

@media (max-width: 640px) {
  .bc__desc { display: none; }
  .bc__cap-badge { display: none; }
}
</style>
