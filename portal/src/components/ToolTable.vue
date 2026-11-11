<script setup lang="ts">
import { computed, ref } from 'vue';
import type { CatalogTool } from '../lib/api';
import { parseToolDescription } from '../lib/toolDescription';
import { Eye, Pencil } from '@lucide/vue';
import PopoverTooltip from './PopoverTooltip.vue';

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
    // Computed once per row rather than re-evaluated in the template.
    const badgeTooltip = `${
      tool.action_type === 'state_change'
        ? 'Modifies state — use with care.'
        : 'Read-only — no side effects.'
    } ${permissionNote(tool.permission)}`;
    return { tool, parsed, teaser, restSummary, hasMore, badgeTooltip };
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
// read/write tag's own row -- same "__none__" convention CatalogServer.
// permission uses, just resolved per tool here instead of per service.
function permissionNote(permission: string): string {
  return permission === '__none__' ? 'No specific permission required.' : `Requires ${permission}.`;
}
</script>

<template>
  <!--
    One row per tool. The description column wraps normally at any width (a
    docstring's own newlines are preserved, and a single long unbreakable
    example string such as a full dataset name cannot force the page into
    horizontal scroll); the box scrolls sideways only for a very narrow
    viewport.
  -->
  <div class="af-tbl-box">
    <table class="af-tbl tool-table" aria-label="Available methods">
      <thead>
        <tr>
          <th scope="col">Method</th>
          <th scope="col">Access</th>
          <th scope="col">Description</th>
        </tr>
      </thead>
      <tbody>
        <tr
          v-for="{ tool, parsed, teaser, restSummary, hasMore, badgeTooltip } in rows"
          :key="tool.name"
          class="tool-table__row"
        >
          <td class="tool-table__name">
            <code class="tool-table__code">{{ tool.name }}</code>
          </td>
          <td>
            <PopoverTooltip :tooltip-id="`tt-badge-${tool.name}`" side="top">
              <button
                type="button"
                class="af-tag tool-table__badge"
                :class="
                  tool.action_type === 'state_change'
                    ? 'tool-table__badge--state'
                    : 'tool-table__badge--read'
                "
                :aria-describedby="`tt-badge-${tool.name}`"
              >
                <Pencil v-if="tool.action_type === 'state_change'" :size="12" aria-hidden="true" />
                <Eye v-else :size="12" aria-hidden="true" />
                {{ tool.action_type === 'state_change' ? 'write' : 'read' }}
              </button>
              <template #tooltip>{{ badgeTooltip }}</template>
            </PopoverTooltip>
          </td>
          <td>
            <p class="tool-table__summary">{{ teaser }}</p>

            <button
              v-if="hasMore"
              type="button"
              class="af-btn quiet s tool-table__more-toggle"
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
          </td>
        </tr>
      </tbody>
    </table>
  </div>
</template>

<style scoped>
/* A description can be many lines, so rows size to their content instead of
 * the table's fixed row height, and cells align to the first line. */
.tool-table td {
  height: auto;
  padding-block: var(--space-12);
  vertical-align: top;
  white-space: normal;
}

.tool-table__name {
  min-width: 12rem;
  overflow-wrap: anywhere;
}

.tool-table__code {
  font-family: var(--font-mono);
}

.tool-table__summary {
  margin: 0;
  color: var(--color-af-text-secondary);
  /* Preserves the docstring's own paragraph breaks and indented example
     blocks as authored, rather than collapsing them into one run-on line. */
  white-space: pre-wrap;
  overflow-wrap: anywhere;
  min-width: 16rem;
}

.tool-table__more-toggle {
  margin-top: var(--space-4);
  margin-left: calc(-1 * var(--space-8));
}

.tool-table__args {
  margin: var(--space-8) 0 0;
  display: flex;
  flex-direction: column;
  gap: var(--space-4);
}

.tool-table__arg-row {
  display: grid;
  grid-template-columns: minmax(6rem, max-content) 1fr;
  gap: var(--space-12);
  align-items: baseline;
}

.tool-table__arg-name {
  font-family: var(--font-mono);
  font-size: var(--text-13);
}

.tool-table__arg-desc {
  margin: 0;
  color: var(--color-af-text-secondary);
  overflow-wrap: anywhere;
}

.tool-table__returns {
  margin: var(--space-8) 0 0;
  color: var(--color-af-text-secondary);
  overflow-wrap: anywhere;
}

.tool-table__returns-label {
  font-weight: 500;
  color: var(--color-af-text);
}

/* The read/write tag is a category, so it stays neutral: the word and the
 * icon carry the difference, not colour. */
.tool-table__badge {
  gap: var(--space-4);
  color: inherit;
  font-family: var(--font-sans);
  cursor: help;
}
</style>
