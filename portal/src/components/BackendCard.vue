<script setup lang="ts">
import { computed } from 'vue';
import type { CatalogServer } from '../lib/api';
import type { PoweredBy } from '../lib/catalog';
import { resolveBackendStatus, resolvePoweredByLinked } from '../lib/backendStatus';
import ToolTable from './ToolTable.vue';

const props = defineProps<{
  server: CatalogServer;
  poweredBy: PoweredBy;
}>();

const actionLabel = props.server.action_type === 'state_change' ? 'write' : 'read';
const statusView = computed(() => resolveBackendStatus(props.server));
// "link_required" is authoritative over the identities response's own
// linked flag -- see resolvePoweredByLinked's docstring for why the two can
// disagree for a moment.
const poweredByLinked = computed(() =>
  resolvePoweredByLinked(props.server.status, props.poweredBy.linked),
);
</script>

<template>
  <div class="bc">
    <!-- Header row -->
    <div class="bc__header">
      <div class="bc__header-left">
        <span class="bc__prefix">{{ server.name }}</span>
        <span class="bc__name">{{ server.display_name }}</span>
        <span class="bc__desc">{{ server.description }}</span>
      </div>

      <div class="bc__header-right">
        <!-- Badges below use a focusable button + aria-describedby tooltip
             (same pattern as TokensPage.vue's note icon) rather than a bare
             `title` attribute -- title-only meant the badge's meaning was
             invisible on touch and unreliable across screen readers. -->
        <span v-if="server.capability !== '__none__'" class="bc__badge-wrap">
          <button
            type="button"
            class="bc__cap-badge"
            :aria-describedby="`bc-cap-${server.name}`"
          >
            {{ server.capability }}
          </button>
          <span :id="`bc-cap-${server.name}`" class="bc__badge-tooltip" role="tooltip">
            Requires capability: {{ server.capability }}
          </span>
        </span>

        <span class="bc__badge-wrap">
          <button
            type="button"
            class="bc__auth-badge"
            :aria-describedby="`bc-auth-${server.name}`"
          >
            {{ server.auth_type }}
          </button>
          <span :id="`bc-auth-${server.name}`" class="bc__badge-tooltip" role="tooltip">
            Credential type: {{ server.auth_type }}
          </span>
        </span>

        <span
          v-if="server.status !== 'available'"
          class="bc__status-badge"
          :class="`bc__status-badge--${statusView.severity}`"
          :title="statusView.detail"
        >
          {{ statusView.label }}
        </span>

        <span class="bc__badge-wrap">
          <button
            type="button"
            class="bc__count"
            :class="server.action_type === 'state_change' ? 'bc__count--state' : 'bc__count--read'"
            :aria-describedby="`bc-count-${server.name}`"
          >
            {{ actionLabel }}
          </button>
          <span :id="`bc-count-${server.name}`" class="bc__badge-tooltip" role="tooltip">
            {{
              server.action_type === 'state_change'
                ? 'Has at least one state-changing tool — use with care'
                : 'Read-only — no side effects'
            }}
          </span>
        </span>
      </div>
    </div>

    <!-- Powered by -->
    <div class="bc__powered-by">
      <span class="bc__powered-by-label">Powered by:</span>
      <span v-if="poweredBy.kind === 'none'" class="bc__powered-by-value">
        {{ poweredBy.label }}
      </span>
      <template v-else>
        <a :href="poweredBy.linkHref ?? '#'" class="bc__powered-by-value bc__powered-by-link">
          {{ poweredBy.label }}
        </a>
        <span
          v-if="poweredByLinked !== null"
          class="bc__link-status"
          :class="poweredByLinked ? 'bc__link-status--linked' : 'bc__link-status--unlinked'"
        >
          {{ poweredByLinked ? 'linked' : 'unlinked' }}
        </span>
      </template>
    </div>

    <!-- Status detail + call to action -->
    <div
      v-if="server.status !== 'available'"
      class="bc__status"
      :class="`bc__status--${statusView.severity}`"
      role="status"
    >
      <span class="bc__status-detail">{{ statusView.detail }}</span>
      <a v-if="statusView.cta" :href="statusView.cta.href" class="bc__status-cta">
        {{ statusView.cta.label }} →
      </a>
      <span v-if="statusView.correlationId" class="bc__status-ref">
        ref: {{ statusView.correlationId }}
      </span>
    </div>

    <!-- Tools -- collapsed by default (a backend can register dozens of
         tools; the catalog's job is a quick scan of reachable backends, not
         reading every tool's docstring up front). Same <details> pattern as
         TokensPage.vue's "Use from the command line" section. -->
    <details v-if="server.tools.length > 0" class="bc__tools">
      <summary class="bc__tools-summary">
        {{ server.tools.length }} {{ server.tools.length === 1 ? 'tool' : 'tools' }}
      </summary>
      <div class="bc__tools-body" role="region" :aria-label="`Tools for ${server.name}`">
        <ToolTable :tools="server.tools" />
      </div>
    </details>
    <p v-else class="bc__tools-placeholder">Tool listing coming soon.</p>
  </div>
</template>

<style scoped>
.bc {
  border: 1px solid var(--color-af-border);
  border-radius: 4px;
  overflow: hidden;
  transition: border-color 150ms;
}

.bc:hover {
  border-color: var(--color-af-muted);
}

.bc__header {
  width: 100%;
  display: flex;
  align-items: center;
  gap: 1rem;
  padding: 0.875rem 1rem;
  background: var(--color-af-surface);
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

/* Badge wrapper + tooltip -- the badge itself is a <button> (focusable,
 * keyboard-operable) describedby a tooltip span that stays in the DOM at all
 * times (hidden via opacity/visibility, not display: none) so aria-describedby
 * reaches it for assistive tech regardless of hover/focus state. Same
 * pattern as TokensPage.vue's note-icon/note-tooltip. */
.bc__badge-wrap {
  position: relative;
  display: inline-flex;
}

.bc__badge-tooltip {
  position: absolute;
  top: 100%;
  left: 0;
  margin-top: 0.375rem;
  max-width: 16rem;
  padding: 0.5rem 0.625rem;
  background: var(--color-af-void);
  border: 1px solid var(--color-af-muted);
  border-radius: 4px;
  font-family: 'IBM Plex Sans', system-ui, sans-serif;
  font-size: 0.75rem;
  font-weight: 400;
  text-transform: none;
  letter-spacing: normal;
  line-height: 1.5;
  color: var(--color-af-text);
  white-space: normal;
  opacity: 0;
  visibility: hidden;
  transition: opacity 120ms;
  pointer-events: none;
  z-index: 10;
}
.bc__badge-wrap:hover .bc__badge-tooltip,
.bc__badge-wrap:focus-within .bc__badge-tooltip {
  opacity: 1;
  visibility: visible;
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
  cursor: pointer;
}
.bc__cap-badge:focus-visible {
  outline: 2px solid var(--color-af-teal);
  outline-offset: 1px;
}

.bc__auth-badge {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.5625rem;
  font-weight: 600;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  padding: 0.1875rem 0.5rem;
  border-radius: 2px;
  background: rgb(from var(--color-af-dim) r g b / 0.08);
  color: var(--color-af-dim);
  border: 1px solid rgb(from var(--color-af-dim) r g b / 0.2);
  cursor: pointer;
}
.bc__auth-badge:focus-visible {
  outline: 2px solid var(--color-af-teal);
  outline-offset: 1px;
}

.bc__count {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.5625rem;
  font-weight: 600;
  letter-spacing: 0.06em;
  text-transform: uppercase;
  padding: 0.1875rem 0.5rem;
  border-radius: 2px;
  cursor: pointer;
}
.bc__count:focus-visible {
  outline: 2px solid var(--color-af-teal);
  outline-offset: 1px;
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

.bc__status-badge {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.5625rem;
  font-weight: 600;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  padding: 0.1875rem 0.5rem;
  border-radius: 2px;
}

.bc__status-badge--info {
  background: rgb(from var(--color-af-teal) r g b / 0.08);
  color: var(--color-af-teal);
  border: 1px solid rgb(from var(--color-af-teal) r g b / 0.2);
}

.bc__status-badge--warning {
  background: rgb(from var(--color-af-amber) r g b / 0.08);
  color: var(--color-af-amber);
  border: 1px solid rgb(from var(--color-af-amber) r g b / 0.2);
}

.bc__status-badge--error {
  background: rgb(from var(--color-af-red) r g b / 0.08);
  color: var(--color-af-red);
  border: 1px solid rgb(from var(--color-af-red) r g b / 0.2);
}

/* Powered by */
.bc__powered-by {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.5rem 1rem;
  border-top: 1px solid var(--color-af-border);
  background: rgb(from var(--color-af-void) r g b / 0.5);
  font-size: 0.75rem;
}

.bc__powered-by-label {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.625rem;
  font-weight: 600;
  letter-spacing: 0.06em;
  text-transform: uppercase;
  color: var(--color-af-label);
}

.bc__powered-by-value {
  color: var(--color-af-dim);
}

.bc__powered-by-link {
  color: var(--color-af-teal);
  text-decoration: none;
}
.bc__powered-by-link:hover {
  text-decoration: underline;
}

.bc__link-status {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.5625rem;
  font-weight: 600;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  padding: 0.125rem 0.375rem;
  border-radius: 2px;
}

.bc__link-status--linked {
  background: rgb(from var(--color-af-green) r g b / 0.12);
  color: var(--color-af-green);
  border: 1px solid rgb(from var(--color-af-green) r g b / 0.25);
}

.bc__link-status--unlinked {
  background: rgb(from var(--color-af-dim) r g b / 0.12);
  color: var(--color-af-dim);
  border: 1px solid rgb(from var(--color-af-dim) r g b / 0.25);
}

/* Status detail + call to action */
.bc__status {
  display: flex;
  align-items: baseline;
  flex-wrap: wrap;
  gap: 0.5rem;
  padding: 0.5rem 1rem;
  border-top: 1px solid var(--color-af-border);
  font-size: 0.8125rem;
}

.bc__status--info {
  color: var(--color-af-teal);
  background: rgb(from var(--color-af-teal) r g b / 0.05);
}

.bc__status--warning {
  color: var(--color-af-amber);
  background: rgb(from var(--color-af-amber) r g b / 0.05);
}

.bc__status--error {
  color: var(--color-af-red);
  background: rgb(from var(--color-af-red) r g b / 0.05);
}

.bc__status-detail {
  color: inherit;
}

.bc__status-cta {
  color: inherit;
  font-weight: 600;
  text-decoration: none;
  white-space: nowrap;
}
.bc__status-cta:hover {
  text-decoration: underline;
}

.bc__status-ref {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.6875rem;
  color: var(--color-af-dim);
  white-space: nowrap;
}

/* Tools -- collapsed by default via <details>/<summary> */
.bc__tools {
  border-top: 1px solid var(--color-af-border);
  background: rgb(from var(--color-af-void) r g b / 0.5);
}

.bc__tools-summary {
  cursor: pointer;
  padding: 0.625rem 1rem;
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.6875rem;
  font-weight: 600;
  letter-spacing: 0.06em;
  color: var(--color-af-dim);
}
.bc__tools-summary:focus-visible {
  outline: 2px solid var(--color-af-teal);
  outline-offset: -2px;
}

.bc__tools-body {
  padding: 0 0 0.25rem;
}

.bc__tools-placeholder {
  margin: 0;
  padding: 0.75rem 1rem;
  font-size: 0.8125rem;
  font-style: italic;
  color: var(--color-af-dim);
  border-top: 1px solid var(--color-af-border);
  background: rgb(from var(--color-af-void) r g b / 0.5);
}

@media (max-width: 640px) {
  .bc__desc {
    display: none;
  }
  .bc__cap-badge {
    display: none;
  }
  .bc__auth-badge {
    display: none;
  }
}
</style>
