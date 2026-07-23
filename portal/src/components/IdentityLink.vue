<script setup lang="ts">
import { ref } from 'vue';
import { startIdpLink } from '../lib/auth';

const props = defineProps<{
  provider: string;
  alias: string;
  linked: boolean;
  display_name: string;
  description: string;
  sub?: string;
}>();

const busy = ref(false);
const error = ref<string | null>(null);

// Shared by both the "Link account" and "Reconnect" buttons below — same
// LINK_IDP flow either way, just re-run to overwrite a stale stored token in
// place when already linked (see ../lib/auth.ts::startIdpLink).
async function handleLink() {
  busy.value = true;
  error.value = null;
  try {
    await startIdpLink({ providerAlias: props.alias, returnUrl: '/identities/' });
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Link failed. Try again.';
    busy.value = false;
  }
}

// Provider icon character — monospaced glyph, not an emoji
const providerGlyph: Record<string, string> = {
  'atlas-iam': 'A',
  cern: 'C',
};
const glyph = providerGlyph[props.provider] ?? props.provider[0]?.toUpperCase() ?? '?';
</script>

<template>
  <div class="il" :class="{ 'il--linked': linked }">
    <!-- Provider icon + identity info -->
    <div class="il__icon" aria-hidden="true">{{ glyph }}</div>

    <div class="il__body">
      <div class="il__header">
        <span class="il__name">{{ display_name }}</span>
        <span v-if="linked" class="il__status il__status--linked">linked</span>
        <span v-else class="il__status il__status--unlinked">not linked</span>
      </div>

      <p class="il__desc">{{ description }}</p>

      <div v-if="linked && sub" class="il__subject">
        <span class="il__subject-label">Subject</span>
        <code class="il__subject-val">{{ sub }}</code>
      </div>

      <div v-if="error" class="il__error" role="alert">{{ error }}</div>
    </div>

    <!-- Action -->
    <div class="il__actions">
      <button
        v-if="!linked"
        class="il__btn il__btn--link"
        :disabled="busy"
        @click="handleLink"
        :aria-busy="busy"
      >
        {{ busy ? 'Redirecting…' : 'Link account' }}
      </button>

      <!--
      Unlinking isn't exposed by the broker (DELETE returns 501) and most AF
      users don't have Keycloak admin access anyway. Reconnect re-runs the
      same LINK_IDP flow, which overwrites the stored token in place — the
      fix for a stale/broken linkage without touching the Keycloak
      federated_identity record.
      -->
      <button
        v-else
        class="il__btn il__btn--reconnect"
        :disabled="busy"
        @click="handleLink"
        :aria-busy="busy"
      >
        {{ busy ? 'Redirecting…' : 'Reconnect' }}
      </button>
    </div>
  </div>
</template>

<style scoped>
.il {
  display: grid;
  grid-template-columns: 2.5rem 1fr auto;
  gap: 1rem;
  align-items: start;
  padding: 1.25rem;
  border: 1px solid var(--color-af-border);
  border-radius: 4px;
  background: var(--color-af-surface);
  transition: border-color 150ms;
}

.il--linked {
  border-color: rgb(from var(--color-af-teal) r g b / 0.2);
}

.il__icon {
  width: 2.5rem;
  height: 2.5rem;
  border-radius: 4px;
  background: var(--color-af-border);
  border: 1px solid var(--color-af-muted);
  display: flex;
  align-items: center;
  justify-content: center;
  font-family: 'IBM Plex Mono', monospace;
  font-size: 1.125rem;
  font-weight: 700;
  color: var(--color-af-dim);
  flex-shrink: 0;
}

.il--linked .il__icon {
  background: rgb(from var(--color-af-teal) r g b / 0.08);
  border-color: rgb(from var(--color-af-teal) r g b / 0.25);
  color: var(--color-af-teal);
}

.il__body {
  min-width: 0;
  display: flex;
  flex-direction: column;
  gap: 0.375rem;
}

.il__header {
  display: flex;
  align-items: center;
  gap: 0.625rem;
}

.il__name {
  font-family: 'IBM Plex Sans', system-ui, sans-serif;
  font-size: 0.9375rem;
  font-weight: 600;
  color: var(--color-af-text);
}

.il__status {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.5625rem;
  font-weight: 600;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  padding: 0.125rem 0.375rem;
  border-radius: 2px;
}

.il__status--linked {
  background: rgb(from var(--color-af-green) r g b / 0.12);
  color: var(--color-af-green);
  border: 1px solid rgb(from var(--color-af-green) r g b / 0.25);
}

.il__status--unlinked {
  background: rgb(from var(--color-af-dim) r g b / 0.12);
  color: var(--color-af-dim);
  border: 1px solid rgb(from var(--color-af-dim) r g b / 0.25);
}

.il__desc {
  font-size: 0.8125rem;
  color: var(--color-af-dim);
  margin: 0;
  line-height: 1.5;
}

.il__subject {
  display: flex;
  align-items: baseline;
  gap: 0.5rem;
  flex-wrap: wrap;
}

.il__subject-label {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.5625rem;
  font-weight: 600;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  color: var(--color-af-dim);
}

.il__subject-val {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.6875rem;
  color: #9ca3af;
  word-break: break-all;
}

.il__error {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.75rem;
  color: var(--color-af-red);
  margin-top: 0.25rem;
}

.il__actions {
  flex-shrink: 0;
  padding-top: 0.125rem;
  max-width: 14rem;
  text-align: right;
}

/*
 * .il's grid keeps align-items: start so the icon lines up with the top of
 * the body text — but the linked-state action (button or, formerly, hint
 * text) has a different natural height than the body column (name + status +
 * description + subject line), which left it stranded near the top of a
 * taller row instead of centered in it. Scoped to the linked variant only —
 * the unlinked row's single-line body keeps looking right at align-items: start.
 */
.il--linked .il__actions {
  align-self: center;
}

/* Buttons */
.il__btn {
  display: inline-flex;
  align-items: center;
  padding: 0.4375rem 0.875rem;
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.6875rem;
  font-weight: 600;
  letter-spacing: 0.06em;
  text-transform: uppercase;
  border-radius: 3px;
  border: 1px solid;
  cursor: pointer;
  transition:
    background 120ms,
    color 120ms,
    border-color 120ms;
  white-space: nowrap;
}
.il__btn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}
.il__btn:focus-visible {
  outline: 2px solid var(--color-af-teal);
  outline-offset: 2px;
}

.il__btn--link {
  background: rgb(from var(--color-af-teal) r g b / 0.1);
  color: var(--color-af-teal);
  border-color: rgb(from var(--color-af-teal) r g b / 0.3);
}
.il__btn--link:not(:disabled):hover {
  background: rgb(from var(--color-af-teal) r g b / 0.18);
  border-color: rgb(from var(--color-af-teal) r g b / 0.5);
}

/* Reconnect: a maintenance action, not a required one — deliberately more
   subdued than the primary Link CTA (dashed border, smaller, quieter teal). */
.il__btn--reconnect {
  background: transparent;
  color: var(--color-af-teal);
  border-style: dashed;
  border-color: rgb(from var(--color-af-teal) r g b / 0.35);
  font-size: 0.625rem;
  padding: 0.375rem 0.75rem;
}
.il__btn--reconnect:not(:disabled):hover {
  background: rgb(from var(--color-af-teal) r g b / 0.08);
  border-color: rgb(from var(--color-af-teal) r g b / 0.5);
}

@media (max-width: 640px) {
  .il {
    grid-template-columns: 2rem 1fr;
    grid-template-rows: auto auto;
  }
  .il__icon {
    width: 2rem;
    height: 2rem;
    font-size: 0.875rem;
  }
  .il__actions {
    grid-column: 2;
    padding-top: 0;
  }
}
</style>
