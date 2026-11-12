<script setup lang="ts">
/**
 * AsyncState.vue — the ladder every data page renders: loading, session
 * expired, access denied, error, optional empty, then the content. Pair it
 * with useLoadState(). The first state that applies wins, so a page never
 * shows a stale empty state under an error. The optional `error-hint` slot
 * adds a pointer (e.g. a link to where the fix lives) inside the error banner.
 */
import type { AccessDeniedError } from '../../lib/api';

withDefaults(
  defineProps<{
    loading: boolean;
    error: string | null;
    /** Bold heading of the generic error banner, e.g. "Usage unavailable". */
    errorTitle: string;
    sessionExpired: boolean;
    accessDenied: AccessDeniedError | null;
    empty?: boolean;
    loadingLabel?: string;
    /** Render the failure states as an in-section `.af-note` instead of a page `.af-banner`. */
    inline?: boolean;
  }>(),
  { empty: false, loadingLabel: 'Loading…', inline: false },
);

function reload(): void {
  location.reload();
}
</script>

<template>
  <div v-if="loading" class="async__loading" role="status">
    <span class="async__spinner" aria-hidden="true"></span>
    <span>{{ loadingLabel }}</span>
  </div>

  <div
    v-else-if="sessionExpired"
    :class="['alert', inline ? 'af-note' : 'af-banner', 'bad', { async__inline: inline }]"
    role="alert"
  >
    <span class="af-mark bad" aria-hidden="true"></span>
    <div>
      <b>Session expired</b>
      Your session has expired. Reload to re-authenticate.
    </div>
    <button type="button" class="btn" data-variant="outline" data-size="sm" @click="reload">
      Reload
    </button>
  </div>

  <!-- A valid session that lacks the audience this platform needs: reloading
       cannot fix it, only an administrator granting access can. -->
  <div
    v-else-if="accessDenied"
    :class="['alert', inline ? 'af-note' : 'af-banner', 'warn', { async__inline: inline }]"
    role="alert"
  >
    <span class="af-mark warn" aria-hidden="true"></span>
    <div>
      <b>Access not yet granted</b>
      {{ accessDenied.message }}
    </div>
  </div>

  <div
    v-else-if="error"
    :class="['alert', inline ? 'af-note' : 'af-banner', 'bad', { async__inline: inline }]"
    role="alert"
  >
    <span class="af-mark bad" aria-hidden="true"></span>
    <div>
      <b>{{ errorTitle }}</b>
      {{ error }}
      <slot name="error-hint" />
    </div>
  </div>

  <div v-else-if="empty" class="empty border-input border">
    <slot name="empty" />
  </div>

  <slot v-else />
</template>

<style scoped>
/* A note lays its mark, text and button out in one row; the title runs into
   the sentence rather than stacking like a banner's. */
.async__inline > div {
  flex: 1 1 auto;
  min-width: 0;
}

.async__inline b {
  margin-right: var(--space-8);
  font-weight: 600;
}

.async__loading {
  display: flex;
  align-items: center;
  gap: var(--space-8);
  padding: var(--space-16) 0;
  color: var(--color-af-text-secondary);
  font-size: var(--text-13);
}

.async__spinner {
  width: 16px;
  height: 16px;
  flex: none;
  border: 2px solid var(--color-af-border-strong);
  border-top-color: var(--color-af-text-secondary);
  border-radius: 50%;
  animation: async-spin 0.8s linear infinite;
}

@keyframes async-spin {
  to {
    transform: rotate(360deg);
  }
}

/* A frozen ring still reads as "working" next to the label. */
@media (prefers-reduced-motion: reduce) {
  .async__spinner {
    animation: none;
  }
}
</style>
