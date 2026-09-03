<script setup lang="ts">
import { computed, ref } from 'vue';
import type { CatalogTool } from '../lib/api';
import { parseToolDescription } from '../lib/toolDescription';
import InfoTooltip from './InfoTooltip.vue';

const props = defineProps<{
  tools: CatalogTool[];
}>();

// A tool's own docstring is written summary-paragraph-first (Google style:
// one short sentence, then elaboration -- see toolDescription.ts), so the
// first paragraph alone is a fair teaser. Everything after it (further
// paragraphs, parsed args, parsed returns) starts collapsed: a service with
// a handful of tools can otherwise turn "scan the method list" into
// "scroll past a wall of docstring prose" (e.g. an ami_execute-style tool
// with a full worked-example block). Parsed once per render, not once per
// template interpolation -- v-for can't bind a per-iteration computed value
// the way a plain script-side map can.
const rows = computed(() =>
  props.tools.map((tool) => {
    const parsed = parseToolDescription(tool.description);
    const paragraphs = parsed.summary.split(/\n\s*\n/).filter((p) => p.trim() !== '');
    const teaser = paragraphs[0] ?? '';
    const restSummary = paragraphs.slice(1).join('\n\n');
    const hasMore = restSummary !== '' || parsed.args.length > 0 || parsed.returns !== null;
    return { tool, parsed, teaser, restSummary, hasMore };
  }),
);

const expanded = ref<Set<string>>(new Set());

function toggleExpanded(name: string): void {
  if (expanded.value.has(name)) {
    expanded.value.delete(name);
  } else {
    expanded.value.add(name);
  }
}

// "No specific permission required" covers both "__none__" (the explicit
// opt-in) and a service-level scalar permission that's already named on the
// READ/WRITE badge's own row -- same "__none__" convention CatalogServer.
// permission uses, just resolved per tool here instead of per service.
function permissionNote(permission: string): string {
  return permission === '__none__' ? 'No specific permission required.' : `Requires ${permission}.`;
}
</script>

<template>
  <!--
    A list of tool rows, not a table -- a table forced the description
    column into one wide, unbroken cell (a docstring's own newlines were
    collapsed by default `white-space`, and a single long, unbreakable
    example string like a full dataset name could force the whole table
    into horizontal scroll). Each tool's own vertical block avoids both:
    it wraps normally at any width, and only ever grows downward.
  -->
  <div class="tool-table" role="list" aria-label="Available methods">
    <div
      v-for="{ tool, parsed, teaser, restSummary, hasMore } in rows"
      :key="tool.name"
      class="tool-table__row"
      role="listitem"
    >
      <div class="tool-table__row-header">
        <code class="tool-table__code">{{ tool.name }}</code>
        <!-- Focusable button + aria-describedby tooltip, not a bare title
             attribute -- same pattern as ServiceCard.vue's badges and
             TokensPage.vue's note icon: keyboard-reachable and always
             present in the DOM for assistive tech. -->
        <InfoTooltip :tooltip-id="`tt-badge-${tool.name}`">
          <button
            type="button"
            class="tool-table__badge"
            :class="
              tool.action_type === 'state_change'
                ? 'tool-table__badge--state'
                : 'tool-table__badge--read'
            "
            :aria-describedby="`tt-badge-${tool.name}`"
          >
            {{ tool.action_type === 'state_change' ? 'write' : 'read' }}
          </button>
          <template #tooltip>
            {{
              tool.action_type === 'state_change'
                ? 'Modifies state — use with care.'
                : 'Read-only — no side effects.'
            }}
            {{ permissionNote(tool.permission) }}
          </template>
        </InfoTooltip>
      </div>

      <p class="tool-table__summary">{{ teaser }}</p>

      <button
        v-if="hasMore"
        type="button"
        class="tool-table__more-toggle"
        :aria-expanded="expanded.has(tool.name)"
        @click="toggleExpanded(tool.name)"
      >
        {{ expanded.has(tool.name) ? 'Show less' : 'Show more' }}
      </button>

      <template v-if="hasMore && expanded.has(tool.name)">
        <p v-if="restSummary" class="tool-table__summary">{{ restSummary }}</p>

        <dl v-if="parsed.args.length > 0" class="tool-table__args">
          <div v-for="arg in parsed.args" :key="arg.name" class="tool-table__arg-row">
            <dt class="tool-table__arg-name">{{ arg.name }}</dt>
            <dd class="tool-table__arg-desc">{{ arg.desc }}</dd>
          </div>
        </dl>

        <p v-if="parsed.returns" class="tool-table__returns">
          <span class="tool-table__returns-label">Returns:</span>
          {{ parsed.returns }}
        </p>
      </template>
    </div>
  </div>
</template>

<style scoped>
.tool-table {
  display: flex;
  flex-direction: column;
}

.tool-table__row {
  padding: 0.75rem 1rem;
  border-bottom: 1px solid var(--color-af-border);
}
.tool-table__row:last-child {
  border-bottom: none;
}

.tool-table__row-header {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  margin-bottom: 0.375rem;
}

.tool-table__code {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.75rem;
  color: var(--color-af-teal);
  background: rgb(from var(--color-af-teal) r g b / 0.08);
  padding: 0.125rem 0.375rem;
  border-radius: 2px;
}

.tool-table__summary {
  margin: 0;
  color: var(--color-af-dim);
  font-family: 'IBM Plex Sans', system-ui, sans-serif;
  font-size: 0.8125rem;
  line-height: 1.6;
  /* Preserves the docstring's own paragraph breaks and indented example
     blocks as authored, rather than collapsing them into one run-on line. */
  white-space: pre-wrap;
  overflow-wrap: anywhere;
}

.tool-table__more-toggle {
  display: inline-block;
  margin-top: 0.375rem;
  background: none;
  border: none;
  padding: 0;
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.6875rem;
  font-weight: 600;
  letter-spacing: 0.04em;
  color: var(--color-af-teal);
  cursor: pointer;
}
.tool-table__more-toggle:hover {
  text-decoration: underline;
}
.tool-table__more-toggle:focus-visible {
  outline: 2px solid var(--color-af-teal);
  outline-offset: 2px;
}

.tool-table__args {
  margin: 0.625rem 0 0;
  display: flex;
  flex-direction: column;
  gap: 0.375rem;
}

.tool-table__arg-row {
  display: grid;
  grid-template-columns: minmax(6rem, max-content) 1fr;
  gap: 0.75rem;
  align-items: baseline;
}

.tool-table__arg-name {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.75rem;
  color: var(--color-af-text);
}

.tool-table__arg-desc {
  margin: 0;
  font-family: 'IBM Plex Sans', system-ui, sans-serif;
  font-size: 0.8125rem;
  color: var(--color-af-dim);
  line-height: 1.5;
  overflow-wrap: anywhere;
}

.tool-table__returns {
  margin: 0.625rem 0 0;
  font-family: 'IBM Plex Sans', system-ui, sans-serif;
  font-size: 0.8125rem;
  color: var(--color-af-dim);
  line-height: 1.5;
  overflow-wrap: anywhere;
}

.tool-table__returns-label {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.6875rem;
  font-weight: 600;
  letter-spacing: 0.04em;
  text-transform: uppercase;
  color: var(--color-af-label);
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
  cursor: pointer;
}
.tool-table__badge:focus-visible {
  outline: 2px solid var(--color-af-teal);
  outline-offset: 1px;
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
