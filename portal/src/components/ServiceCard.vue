<script setup lang="ts">
import { computed } from 'vue';
import { Eye, Pencil } from '@lucide/vue';
import { fetchServerTools } from '../lib/api';
import type { CatalogServer } from '../lib/api';
import type { PoweredBy } from '../lib/catalog';
import { resolveServiceStatus, resolvePoweredByLinked } from '../lib/serviceStatus';
import type { StatusSeverity } from '../lib/serviceStatus';
import { resolveToolListing, toolCountLabel } from '../lib/serverTools';
import { useFetchOnExpand } from '../lib/useFetchOnExpand';
import Disclosure from './ui/Disclosure.vue';
import StatusMark from './ui/StatusMark.vue';
import PopoverTooltip from './PopoverTooltip.vue';
import ToolTable from './ToolTable.vue';

const props = defineProps<{
  server: CatalogServer;
  poweredBy: PoweredBy;
}>();

const TONE: Record<StatusSeverity, 'ok' | 'off' | 'info' | 'warn' | 'bad'> = {
  ok: 'ok',
  off: 'off',
  info: 'info',
  warning: 'warn',
  error: 'bad',
};

const isWrite = props.server.action_type === 'state_change';
const actionLabel = isWrite ? 'write' : 'read';
// Computed once, alongside actionLabel, rather than re-evaluated in the template.
const actionTooltip = isWrite
  ? 'Has at least one state-changing tool — use with care'
  : 'Read-only — no side effects';
const statusView = computed(() => resolveServiceStatus(props.server));
const statusTone = computed(() => TONE[statusView.value.severity]);
// The fix names the action the Identities page uses for the same account and
// links to that account's card.
const fix = computed(() => {
  const cta = statusView.value.cta;
  if (!cta) return null;
  const { kind, linkLabel, linkHref } = props.poweredBy;
  return kind === 'identity' && linkLabel && linkHref ? { label: linkLabel, href: linkHref } : cta;
});
// The status word, plus the fix link, already says why a service is not
// linked or unavailable; the broker's sentence is kept where it adds
// something (what to do, a reference id).
const showStatusDetail = computed(
  () => !['available', 'link_required', 'unavailable'].includes(props.server.status),
);
// "link_required" is authoritative over the identities response's own
// linked flag -- see resolvePoweredByLinked's docstring for why the two can
// disagree for a moment.
const poweredByLinked = computed(() =>
  resolvePoweredByLinked(props.server.status, props.poweredBy.linked),
);
// A service whose only obstacle is an unlinked account reads as disabled, not
// broken: the user chose not to link it, and that only keeps its tools unused.
const isDisabled = computed(() => props.server.status === 'link_required');

// Methods list -- fetched on expand, never on page load: the catalog's job is
// a quick scan of reachable backends, and each listing fans the broker out to
// that one backend.
const {
  open: toolsOpen,
  data: toolListing,
  loading: toolsLoading,
  error: toolsError,
  toggle: toggleTools,
} = useFetchOnExpand(() => fetchServerTools(props.server.name), 'Could not load methods.');
const toolsView = computed(() =>
  toolListing.value ? resolveToolListing(toolListing.value) : null,
);
</script>

<template>
  <div class="bc" :class="{ 'bc--off': isDisabled }">
    <div class="bc__main">
      <div class="bc__title">
        <span class="bc__name">{{ server.display_name }}</span>
        <!-- The technical prefix (what tool names are actually namespaced
             under, e.g. rucio_list_dids) is only shown separately when it's
             not already identical to the display name above -- a backend
             with no configured display_name would otherwise show the same
             string twice. -->
        <code v-if="server.name !== server.display_name" class="bc__prefix">{{ server.name }}</code>
      </div>

      <!-- Reachability, with the fix right beside it when the user can act. -->
      <div class="bc__status-line">
        <StatusMark :tone="statusTone" :label="statusView.label" />
        <a v-if="fix" :href="fix.href" class="bc__status-cta">{{ fix.label }}</a>
      </div>
    </div>

    <p v-if="server.description" class="bc__description">{{ server.description }}</p>

    <!-- Status detail: what to do when the status word alone does not say. -->
    <p v-if="showStatusDetail" class="bc__status-detail" role="status">
      {{ statusView.detail }}
      <span v-if="statusView.correlationId" class="bc__status-ref">
        Reference: <code>{{ statusView.correlationId }}</code>
      </span>
    </p>

    <!-- One meta line: category tags, then the identity that powers the
         service. The tags are neutral (categories, not status) and are
         buttons with an aria-describedby tooltip rather than a bare `title`,
         so their meaning is available on touch and to screen readers. -->
    <div class="bc__meta">
      <div class="bc__tags">
        <!-- server.permission is null when this service's tools require
           different permissions from each other (services.yaml's dict-form
           required_permission with no single "__default__") -- there is no
           one tag that could truthfully summarize that, so this shows
           "mixed" and points at the per-tool Methods list instead of either
           guessing or rendering an empty tag. -->
        <PopoverTooltip
          v-if="server.permission === null"
          :tooltip-id="`bc-cap-${server.name}`"
          side="top"
        >
          <button
            type="button"
            class="af-tag bc__tag bc__cap-badge bc__cap-badge--mixed"
            :aria-describedby="`bc-cap-${server.name}`"
          >
            mixed
          </button>
          <template #tooltip
            >Different methods require different permissions — see Methods below for each
            one.</template
          >
        </PopoverTooltip>
        <PopoverTooltip
          v-else-if="server.permission !== '__none__'"
          :tooltip-id="`bc-cap-${server.name}`"
          side="top"
        >
          <button
            type="button"
            class="af-tag bc__tag bc__cap-badge"
            :aria-describedby="`bc-cap-${server.name}`"
          >
            {{ server.permission }}
          </button>
          <template #tooltip>Requires permission: {{ server.permission }}</template>
        </PopoverTooltip>

        <!-- The builtin af-mcp entry (issue #240) has no per-user credential
           concept at all -- a "none" credential-type tag would read like
           a state to fix, so it renders no tag instead. -->
        <PopoverTooltip v-if="!server.builtin" :tooltip-id="`bc-auth-${server.name}`" side="top">
          <button
            type="button"
            class="af-tag bc__tag bc__auth-badge"
            :aria-describedby="`bc-auth-${server.name}`"
          >
            {{ server.auth_type }}
          </button>
          <template #tooltip>Credential type: {{ server.auth_type }}</template>
        </PopoverTooltip>

        <PopoverTooltip :tooltip-id="`bc-count-${server.name}`" side="top">
          <button
            type="button"
            class="af-tag bc__tag bc__count"
            :class="isWrite ? 'bc__count--state' : 'bc__count--read'"
            :aria-describedby="`bc-count-${server.name}`"
          >
            <Pencil v-if="isWrite" :size="12" aria-hidden="true" />
            <Eye v-else :size="12" aria-hidden="true" />
            {{ actionLabel }}
          </button>
          <template #tooltip>{{ actionTooltip }}</template>
        </PopoverTooltip>
      </div>

      <!-- Powered by -- omitted for the builtin af-mcp entry (issue #240):
         the gateway powers itself, there is no identity to link or
         credential provider to name. -->
      <p v-if="!server.builtin" class="bc__powered-by">
        <span v-if="poweredBy.kind === 'none'">{{ poweredBy.label }}</span>
        <template v-else>
          Powered by
          <a :href="poweredBy.linkHref ?? '#'" class="bc__powered-by-link">{{ poweredBy.label }}</a>
          <!-- The status line already says "Not linked" for a disabled row. -->
          <StatusMark
            v-if="poweredByLinked !== null && !isDisabled"
            :tone="poweredByLinked ? 'ok' : 'off'"
            :label="poweredByLinked ? 'Linked' : 'Not linked'"
          />
        </template>
      </p>
    </div>

    <!-- Methods -- collapsed by default (a backend can register dozens of
         tools; the catalog's job is a quick scan of reachable backends, not
         reading every tool's docstring up front) and fetched on expand from
         GET /v1/catalog/{service}/tools. -->
    <Disclosure
      :open="toolsOpen"
      :region-label="`Methods for ${server.name}`"
      @toggle="toggleTools"
    >
      <template #label>Methods</template>
      <template #badge>
        <span v-if="toolsView && toolsView.kind !== 'blocked'" class="af-tag bc__tools-count">
          {{ toolCountLabel(toolsView.kind === 'tools' ? toolsView.tools.length : 0) }}
        </span>
      </template>
      <div class="bc__tools-body">
        <p v-if="toolsLoading" class="bc__tools-note" aria-live="polite">Loading methods…</p>
        <div v-else-if="toolsError" class="af-note bad bc__tools-error" role="alert">
          <span class="af-mark bad" aria-hidden="true"></span>
          <span>{{ toolsError }}</span>
        </div>
        <template v-else-if="toolsView">
          <ToolTable v-if="toolsView.kind === 'tools'" :tools="toolsView.tools" />
          <p v-else-if="toolsView.kind === 'empty'" class="bc__tools-note">
            {{ toolsView.message }}
          </p>
          <!-- Blocked (not_linked/unauthorized/unavailable/permission_
               required): the broker's own status_detail sentence, plus a
               link to the Identities page when linking is the fix. -->
          <p v-else class="bc__tools-note">
            {{ toolsView.message }}
            <a v-if="toolsView.cta" :href="toolsView.cta.href" class="bc__tools-cta">
              {{ toolsView.cta.label }}
            </a>
          </p>
        </template>
      </div>
    </Disclosure>
  </div>
</template>

<style scoped>
.bc {
  display: flex;
  flex-direction: column;
  gap: var(--space-8);
  padding: var(--space-12) var(--space-16);
}

.bc__main {
  display: flex;
  flex-wrap: wrap;
  align-items: baseline;
  justify-content: space-between;
  gap: var(--space-4) var(--space-16);
}

.bc__title {
  display: flex;
  flex-wrap: wrap;
  align-items: baseline;
  gap: var(--space-8);
  min-width: 0;
}

.bc__name {
  color: var(--color-af-text);
  font-size: var(--text-16);
  font-weight: 500;
}

/* Secondary ink still meets AA contrast; the row just stops competing with
 * the services the user can use. */
.bc--off .bc__name {
  color: var(--color-af-text-secondary);
}

.bc__prefix {
  color: var(--color-af-text-secondary);
  font-size: var(--text-13);
}

.bc__status-line {
  display: flex;
  flex-wrap: wrap;
  align-items: baseline;
  gap: var(--space-4) var(--space-12);
}

.bc__status-cta {
  font-weight: 500;
  white-space: nowrap;
}

.bc__description,
.bc__status-detail,
.bc__powered-by {
  margin: 0;
  color: var(--color-af-text-secondary);
}

.bc__status-ref {
  white-space: nowrap;
}

.bc__meta {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: var(--space-4) var(--space-16);
}

.bc__tags {
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-8);
}

/* Tags are categories, so they stay neutral; the button reset keeps them
 * looking like the plain .af-tag while remaining focusable for the tooltip. */
.bc__tag {
  gap: var(--space-4);
  color: inherit;
  font-family: var(--font-sans);
  cursor: help;
}

.bc__powered-by {
  display: flex;
  flex-wrap: wrap;
  align-items: baseline;
  gap: var(--space-4) var(--space-8);
  font-size: var(--text-13);
}

.bc__tools-count {
  margin-left: var(--space-4);
  color: var(--color-af-text-secondary);
}

/* A backend can register dozens of tools -- without a cap here, expanding
 * one pushes every row below it down the page indefinitely. Scrolling
 * within the row keeps the rest of the list in place. */
.bc__tools-body {
  max-height: 26rem;
  overflow-y: auto;
}

.bc__tools-note {
  margin: 0;
  color: var(--color-af-text-secondary);
}

.bc__tools-cta {
  font-weight: 500;
  white-space: nowrap;
}
</style>
