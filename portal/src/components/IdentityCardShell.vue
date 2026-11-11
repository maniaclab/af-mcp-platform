<script setup lang="ts">
/**
 * IdentityCardShell.vue — the shared frame of an Identities page row: icon,
 * name, status mark and word, what the identity enables, what it powers, an
 * actions column, and a full-width form region. The four identity components
 * (IdentityLink, X509IdentityCard, Krb5IdentityCard, ServiceXIdentityCard)
 * differ only in what they put in the slots.
 *
 * Slots: `status-extra` (beside the status word), default (details under the
 * description), `actions`, `form` (full width, below).
 */
import type { Component } from 'vue';
import { useId } from 'vue';
import StatusMark from './ui/StatusMark.vue';

defineProps<{
  displayName: string;
  enables: string;
  statusTone: 'ok' | 'warn' | 'bad' | 'info' | 'busy' | 'off';
  statusLabel: string;
  /** Extra class on the status element, for callers that expose a per-state hook. */
  statusClass?: string;
  /** Display names of catalog backends this credential powers. */
  powers?: string[];
  /** A Lucide icon component naming the credential type. */
  icon?: Component;
}>();

const nameId = useId();
</script>

<template>
  <section class="ids" :aria-labelledby="nameId">
    <div class="ids__main">
      <div class="ids__header">
        <component :is="icon" v-if="icon" class="af-icon ids__icon" aria-hidden="true" />
        <h3 :id="nameId" class="ids__name">{{ displayName }}</h3>
        <StatusMark :class="statusClass" :tone="statusTone" :label="statusLabel" />
        <slot name="status-extra" />
      </div>

      <p class="ids__desc">{{ enables }}</p>

      <div v-if="powers && powers.length" class="ids__powers">
        <span class="ids__powers-label">Powers</span>
        <span v-for="power in powers" :key="power" class="af-tag">{{ power }}</span>
      </div>

      <slot />
    </div>

    <div class="ids__actions">
      <slot name="actions" />
    </div>

    <div v-if="$slots.form" class="ids__form">
      <slot name="form" />
    </div>
  </section>
</template>

<style scoped>
.ids {
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto;
  gap: var(--space-16);
  padding: var(--space-16) var(--space-24);
  border: 1px solid var(--color-af-border);
  border-radius: var(--radius-10);
}

.ids__main {
  min-width: 0;
  display: flex;
  flex-direction: column;
  gap: var(--space-8);
}

.ids__header {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: var(--space-8) var(--space-12);
}

.ids__icon {
  color: var(--color-af-text-secondary);
}

.ids__name {
  margin: 0;
  font-size: var(--text-16);
  line-height: 1.4;
}

.ids__desc {
  margin: 0;
  color: var(--color-af-text-secondary);
}

.ids__powers {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: var(--space-8);
  font-size: var(--text-13);
  color: var(--color-af-text-secondary);
}

.ids__actions {
  display: flex;
  flex-direction: column;
  align-items: flex-start;
  gap: var(--space-8);
  min-width: 160px;
}

.ids__actions:empty {
  display: none;
}

/* The form spans the row under both columns. */
.ids__form {
  grid-column: 1 / -1;
  padding-top: var(--space-16);
  border-top: 1px solid var(--color-af-border);
}

/* Slot content carries the caller's scope id, so the shell reaches it with :deep. */
.ids__form :deep(form) {
  display: flex;
  flex-direction: column;
  gap: var(--space-16);
}

.ids__form :deep(.ids__form-actions) {
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-8);
}

@media (max-width: 640px) {
  .ids {
    grid-template-columns: minmax(0, 1fr);
    padding: var(--space-16);
  }
  .ids__actions {
    flex-direction: row;
    flex-wrap: wrap;
  }
}
</style>
