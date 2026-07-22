<script setup lang="ts">
import type { CatalogTool } from '../lib/api';

defineProps<{
  tools: CatalogTool[];
}>();
</script>

<template>
  <div class="tool-table" role="region" aria-label="Tool listing">
    <table class="tool-table__table" aria-label="Available tools">
      <thead>
        <tr>
          <th scope="col" class="tool-table__th">Tool name</th>
          <th scope="col" class="tool-table__th tool-table__th--type">Type</th>
          <th scope="col" class="tool-table__th tool-table__th--desc">Description</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="tool in tools" :key="tool.name" class="tool-table__row">
          <td class="tool-table__td tool-table__td--name">
            <code class="tool-table__code">{{ tool.name }}</code>
          </td>
          <td class="tool-table__td tool-table__td--type">
            <span
              class="tool-table__badge"
              :class="
                tool.action_type === 'state_change'
                  ? 'tool-table__badge--state'
                  : 'tool-table__badge--read'
              "
              :title="
                tool.action_type === 'state_change'
                  ? 'Modifies state — use with care'
                  : 'Read-only — no side effects'
              "
            >
              {{ tool.action_type === 'state_change' ? 'write' : 'read' }}
            </span>
          </td>
          <td class="tool-table__td tool-table__td--desc">
            {{ tool.description }}
          </td>
        </tr>
      </tbody>
    </table>
  </div>
</template>

<style scoped>
.tool-table {
  overflow-x: auto;
}

.tool-table__table {
  width: 100%;
  border-collapse: collapse;
  font-family: 'IBM Plex Sans', system-ui, sans-serif;
  font-size: 0.8125rem;
}

.tool-table__th {
  text-align: left;
  padding: 0.5rem 0.75rem;
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.625rem;
  font-weight: 600;
  letter-spacing: 0.1em;
  text-transform: uppercase;
  color: var(--color-af-dim);
  border-bottom: 1px solid var(--color-af-border);
  white-space: nowrap;
}

.tool-table__th--type {
  width: 5rem;
}
.tool-table__th--desc {
  width: auto;
}

.tool-table__row {
  border-bottom: 1px solid var(--color-af-border);
  transition: background 120ms;
}
.tool-table__row:hover {
  background: rgba(255, 255, 255, 0.025);
}
.tool-table__row:last-child {
  border-bottom: none;
}

.tool-table__td {
  padding: 0.625rem 0.75rem;
  vertical-align: top;
  color: var(--color-af-text);
}

.tool-table__td--name {
  white-space: nowrap;
}

.tool-table__code {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.75rem;
  color: var(--color-af-teal);
  background: rgb(from var(--color-af-teal) r g b / 0.08);
  padding: 0.125rem 0.375rem;
  border-radius: 2px;
}

.tool-table__td--desc {
  color: #9ca3af;
  line-height: 1.5;
}

.tool-table__badge {
  display: inline-block;
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.5625rem;
  font-weight: 600;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  padding: 0.1875rem 0.5rem;
  border-radius: 2px;
}

.tool-table__badge--read {
  background: rgb(from var(--color-af-green) r g b / 0.12);
  color: var(--color-af-green);
  border: 1px solid rgb(from var(--color-af-green) r g b / 0.25);
}

.tool-table__badge--state {
  background: rgb(from var(--color-af-amber) r g b / 0.12);
  color: var(--color-af-amber);
  border: 1px solid rgb(from var(--color-af-amber) r g b / 0.25);
}
</style>
