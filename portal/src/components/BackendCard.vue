<script setup lang="ts">
import type { CatalogServer } from '../lib/api';
import type { PoweredBy } from '../lib/catalog';
import ToolTable from './ToolTable.vue';

const props = defineProps<{
  server: CatalogServer;
  poweredBy: PoweredBy;
}>();

const actionLabel = props.server.action_type === 'state_change' ? 'write' : 'read';
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
        <span
          v-if="server.capability !== '__none__'"
          class="bc__cap-badge"
          :title="`Requires capability: ${server.capability}`"
        >
          {{ server.capability }}
        </span>

        <span class="bc__auth-badge" :title="`Credential type: ${server.auth_type}`">
          {{ server.auth_type }}
        </span>

        <span
          class="bc__count"
          :class="server.action_type === 'state_change' ? 'bc__count--state' : 'bc__count--read'"
          :title="
            server.action_type === 'state_change'
              ? 'Has at least one state-changing tool — use with care'
              : 'Read-only — no side effects'
          "
        >
          {{ actionLabel }}
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
          v-if="poweredBy.linked !== null"
          class="bc__link-status"
          :class="poweredBy.linked ? 'bc__link-status--linked' : 'bc__link-status--unlinked'"
        >
          {{ poweredBy.linked ? 'linked' : 'unlinked' }}
        </span>
      </template>
    </div>

    <!-- Tools -->
    <div class="bc__tools" role="region" :aria-label="`Tools for ${server.name}`">
      <ToolTable v-if="server.tools.length > 0" :tools="server.tools" />
      <p v-else class="bc__tools-placeholder">Tool listing coming soon.</p>
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
  color: #4b5563;
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

/* Tools */
.bc__tools {
  border-top: 1px solid var(--color-af-border);
  padding: 0.25rem 0;
  background: rgb(from var(--color-af-void) r g b / 0.5);
}

.bc__tools-placeholder {
  margin: 0;
  padding: 0.75rem 1rem;
  font-size: 0.8125rem;
  font-style: italic;
  color: var(--color-af-dim);
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
