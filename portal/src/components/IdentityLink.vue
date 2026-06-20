<script setup lang="ts">
import { ref } from 'vue';
import { startIdentityLink, unlinkIdentity } from '../lib/api';

const props = defineProps<{
  provider: string;
  linked: boolean;
  display_name: string;
  description: string;
  capabilities_unlocked: string[];
  subject?: string;
  linked_at?: string;
}>();

const emit = defineEmits<{
  (e: 'linked', provider: string): void;
  (e: 'unlinked', provider: string): void;
}>();

const busy = ref(false);
const error = ref<string | null>(null);
const showConfirm = ref(false);

async function handleLink() {
  busy.value = true;
  error.value = null;
  try {
    const { redirect_url } = await startIdentityLink(props.provider);
    // Redirect the top-level window to the IdP
    window.location.href = redirect_url;
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Link failed. Try again.';
    busy.value = false;
  }
}

async function confirmUnlink() {
  showConfirm.value = false;
  busy.value = true;
  error.value = null;
  try {
    await unlinkIdentity(props.provider);
    emit('unlinked', props.provider);
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Unlink failed. Try again.';
  } finally {
    busy.value = false;
  }
}

function formatDate(iso?: string): string {
  if (!iso) return '';
  return new Date(iso).toLocaleDateString('en-US', {
    year: 'numeric', month: 'short', day: 'numeric',
  });
}

// Provider icon character — monospaced glyph, not an emoji
const providerGlyph: Record<string, string> = {
  'atlas-iam': 'A',
  'cern':      'C',
  'gitlab':    'G',
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

      <div v-if="linked && subject" class="il__subject">
        <span class="il__subject-label">Subject</span>
        <code class="il__subject-val">{{ subject }}</code>
      </div>

      <div v-if="linked && linked_at" class="il__meta">
        Linked {{ formatDate(linked_at) }}
      </div>

      <div v-if="capabilities_unlocked.length > 0" class="il__caps">
        <span class="il__caps-label">Unlocks</span>
        <span
          v-for="cap in capabilities_unlocked"
          :key="cap"
          class="il__cap-badge"
        >{{ cap }}</span>
      </div>

      <div v-if="error" class="il__error" role="alert">{{ error }}</div>
    </div>

    <!-- Action button -->
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

      <button
        v-else
        class="il__btn il__btn--unlink"
        :disabled="busy"
        @click="showConfirm = true"
        :aria-busy="busy"
      >
        {{ busy ? 'Removing…' : 'Unlink' }}
      </button>
    </div>

    <!-- Confirm unlink modal -->
    <Teleport to="body">
      <div v-if="showConfirm" class="il__modal-backdrop" role="dialog" aria-modal="true" :aria-label="`Unlink ${display_name}`">
        <div class="il__modal">
          <h2 class="il__modal-title">Unlink {{ display_name }}?</h2>
          <p class="il__modal-body">
            This removes the identity association. Any capabilities that depend on
            <strong>{{ display_name }}</strong> will stop working until you re-link.
          </p>
          <div class="il__modal-actions">
            <button class="il__btn il__btn--cancel" @click="showConfirm = false">
              Cancel
            </button>
            <button class="il__btn il__btn--confirm" @click="confirmUnlink">
              Remove link
            </button>
          </div>
        </div>
      </div>
    </Teleport>
  </div>
</template>

<style scoped>
.il {
  display: grid;
  grid-template-columns: 2.5rem 1fr auto;
  gap: 1rem;
  align-items: start;
  padding: 1.25rem;
  border: 1px solid #1F2937;
  border-radius: 4px;
  background: #111827;
  transition: border-color 150ms;
}

.il--linked {
  border-color: rgba(0, 212, 200, 0.2);
}

.il__icon {
  width: 2.5rem;
  height: 2.5rem;
  border-radius: 4px;
  background: #1F2937;
  border: 1px solid #374151;
  display: flex;
  align-items: center;
  justify-content: center;
  font-family: 'IBM Plex Mono', monospace;
  font-size: 1.125rem;
  font-weight: 700;
  color: #6B7280;
  flex-shrink: 0;
}

.il--linked .il__icon {
  background: rgba(0, 212, 200, 0.08);
  border-color: rgba(0, 212, 200, 0.25);
  color: #00D4C8;
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
  color: #E8ECF0;
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
  background: rgba(16, 185, 129, 0.12);
  color: #10B981;
  border: 1px solid rgba(16, 185, 129, 0.25);
}

.il__status--unlinked {
  background: rgba(107, 114, 128, 0.12);
  color: #6B7280;
  border: 1px solid rgba(107, 114, 128, 0.25);
}

.il__desc {
  font-size: 0.8125rem;
  color: #6B7280;
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
  color: #6B7280;
}

.il__subject-val {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.6875rem;
  color: #9CA3AF;
  word-break: break-all;
}

.il__meta {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.6875rem;
  color: #4B5563;
}

.il__caps {
  display: flex;
  align-items: center;
  gap: 0.375rem;
  flex-wrap: wrap;
  margin-top: 0.25rem;
}

.il__caps-label {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.5625rem;
  font-weight: 600;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  color: #6B7280;
}

.il__cap-badge {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.5625rem;
  font-weight: 600;
  letter-spacing: 0.06em;
  text-transform: uppercase;
  padding: 0.125rem 0.375rem;
  border-radius: 2px;
  background: rgba(0, 212, 200, 0.08);
  color: #00D4C8;
  border: 1px solid rgba(0, 212, 200, 0.18);
}

.il__error {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.75rem;
  color: #EF4444;
  margin-top: 0.25rem;
}

.il__actions {
  flex-shrink: 0;
  padding-top: 0.125rem;
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
  transition: background 120ms, color 120ms, border-color 120ms;
  white-space: nowrap;
}
.il__btn:disabled { opacity: 0.5; cursor: not-allowed; }
.il__btn:focus-visible { outline: 2px solid #00D4C8; outline-offset: 2px; }

.il__btn--link {
  background: rgba(0, 212, 200, 0.1);
  color: #00D4C8;
  border-color: rgba(0, 212, 200, 0.3);
}
.il__btn--link:not(:disabled):hover {
  background: rgba(0, 212, 200, 0.18);
  border-color: rgba(0, 212, 200, 0.5);
}

.il__btn--unlink {
  background: transparent;
  color: #6B7280;
  border-color: #374151;
}
.il__btn--unlink:not(:disabled):hover {
  color: #EF4444;
  border-color: rgba(239, 68, 68, 0.35);
  background: rgba(239, 68, 68, 0.06);
}

.il__btn--cancel {
  background: transparent;
  color: #6B7280;
  border-color: #374151;
}
.il__btn--cancel:hover {
  color: #E8ECF0;
  border-color: #6B7280;
}

.il__btn--confirm {
  background: rgba(239, 68, 68, 0.1);
  color: #EF4444;
  border-color: rgba(239, 68, 68, 0.3);
}
.il__btn--confirm:hover {
  background: rgba(239, 68, 68, 0.18);
  border-color: rgba(239, 68, 68, 0.5);
}

/* Modal */
.il__modal-backdrop {
  position: fixed;
  inset: 0;
  background: rgba(10, 14, 26, 0.85);
  backdrop-filter: blur(4px);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 100;
  padding: 1rem;
}

.il__modal {
  background: #111827;
  border: 1px solid #374151;
  border-radius: 6px;
  padding: 1.75rem;
  max-width: 28rem;
  width: 100%;
}

.il__modal-title {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 1rem;
  font-weight: 600;
  letter-spacing: 0.02em;
  color: #E8ECF0;
  margin: 0 0 0.75rem;
}

.il__modal-body {
  font-size: 0.875rem;
  color: #9CA3AF;
  line-height: 1.6;
  margin: 0 0 1.5rem;
}

.il__modal-body strong {
  color: #E8ECF0;
}

.il__modal-actions {
  display: flex;
  gap: 0.75rem;
  justify-content: flex-end;
}

@media (max-width: 640px) {
  .il {
    grid-template-columns: 2rem 1fr;
    grid-template-rows: auto auto;
  }
  .il__icon { width: 2rem; height: 2rem; font-size: 0.875rem; }
  .il__actions {
    grid-column: 2;
    padding-top: 0;
  }
}
</style>
