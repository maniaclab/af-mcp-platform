<script setup lang="ts">
import { nextTick, ref } from 'vue';
import { fetchOAuth21AuthorizeUrl, unlinkIdentity, type ProviderType } from '../lib/api';
import { startIdpLink } from '../lib/auth';

const props = defineProps<{
  id: string;
  type: ProviderType;
  linked: boolean;
  display_name: string;
  enables: string;
  link_url: string | null;
}>();

const emit = defineEmits<{
  (e: 'unlinked'): void;
}>();

const busy = ref(false);
const error = ref<string | null>(null);

// keycloak-brokered providers always carry link_url: null (issue #66 PR4) —
// the broker can't build a URL the portal could navigate to directly and
// have it complete (see the comment in handleLink() below), so link_url's
// presence isn't a usable signal for these. `id` doubling as the broker's
// configured alias (no separate id-to-alias mapping) is what makes linking
// possible regardless.
const canLink = props.type === 'keycloak-brokered' || !!props.link_url;

// Unlinking is only wired up for oauth21-direct aliases — DELETE
// /v1/identities/link/{provider} still returns 501 for keycloak-brokered
// ones (Keycloak admin API unlink is out of scope, see api.ts's
// linking-mechanisms note), so the action is never shown for those.
const canUnlink = props.type === 'oauth21-direct';

// Unlink-confirm dialog uses the native <dialog> element (showModal()), same
// pattern as ProxyStatus.vue's revoke-confirm dialog — real focus trap, ESC
// to close, inert siblings for free. We only need to remember the trigger so
// focus can return to it on close.
const unlinkDialog = ref<HTMLDialogElement | null>(null);
const unlinkTrigger = ref<HTMLButtonElement | null>(null);
const cancelUnlinkBtn = ref<HTMLButtonElement | null>(null);

async function openUnlinkConfirm(evt: Event) {
  unlinkTrigger.value = evt.currentTarget as HTMLButtonElement;
  await nextTick();
  unlinkDialog.value?.showModal();
  // Move focus off the destructive "Unlink" button — start on Cancel.
  cancelUnlinkBtn.value?.focus();
}

function closeUnlinkConfirm() {
  unlinkDialog.value?.close();
}

// Native <dialog> fires `close` whether it was closed by ESC, form method="dialog",
// or an explicit .close() call — this is our single place to restore focus.
function onUnlinkDialogClose() {
  unlinkTrigger.value?.focus();
  unlinkTrigger.value = null;
}

async function handleUnlink() {
  closeUnlinkConfirm();
  busy.value = true;
  error.value = null;
  try {
    await unlinkIdentity(props.id);
    emit('unlinked');
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Unlink failed. Try again.';
  } finally {
    busy.value = false;
  }
}

// Shared by both the "Link account" and "Reconnect" buttons below — same
// flow either way, just re-run to overwrite a stale stored token in place
// when already linked.
async function handleLink() {
  busy.value = true;
  error.value = null;
  try {
    if (props.type === 'keycloak-brokered') {
      // Keycloak's kc_action=LINK_IDP flow's callback lands on /callback,
      // which only completes via oidc-client-ts's own locally-stored
      // PKCE/state (see ../lib/api.ts's linking-mechanisms note) — a bare
      // top-level navigation can't complete that handshake, so always
      // re-run the portal's own client-side flow instead. `id` is the same
      // alias the broker configured this provider under, so there's no URL
      // to parse.
      await startIdpLink({ providerAlias: props.id, returnUrl: '/identities/' });
    } else if (props.link_url) {
      // A top-level `window.location.href` navigation to link_url can't
      // carry the SPA's Bearer (browsers don't attach JS-held Authorization
      // headers to top-level navigations), so fetch the actual backend AS
      // authorize_url with the Bearer first, then navigate to that instead
      // — see api/oauth21.py::authorize's content negotiation.
      const authorizeUrl = await fetchOAuth21AuthorizeUrl(props.link_url);
      window.location.href = authorizeUrl;
    }
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Link failed. Try again.';
    busy.value = false;
  }
}

// Provider icon character — monospaced glyph, not an emoji
const glyph = props.id[0]?.toUpperCase() ?? '?';
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

      <p class="il__desc">{{ enables }}</p>

      <div v-if="error" class="il__error" role="alert">{{ error }}</div>
    </div>

    <!-- Action -->
    <div class="il__actions">
      <button
        v-if="!linked && canLink"
        class="il__btn il__btn--link"
        :disabled="busy"
        @click="handleLink"
        :aria-busy="busy"
      >
        {{ busy ? 'Redirecting…' : 'Link account' }}
      </button>

      <!--
      Reconnect re-runs the same linking flow, which overwrites the stored
      token in place — a fix for a stale/broken linkage without an explicit
      unlink. Unlink (oauth21-direct only — DELETE still returns 501 for
      keycloak-brokered, Keycloak admin API unlink is out of scope) actually
      revokes the stored token instead.
      -->
      <div v-else-if="linked && canLink" class="il__linked-actions">
        <button
          class="il__btn il__btn--reconnect"
          :disabled="busy"
          @click="handleLink"
          :aria-busy="busy"
        >
          {{ busy ? 'Redirecting…' : 'Reconnect' }}
        </button>
        <button
          v-if="canUnlink"
          class="il__btn il__btn--unlink"
          :disabled="busy"
          @click="openUnlinkConfirm"
          :aria-busy="busy"
        >
          {{ busy ? 'Unlinking…' : 'Unlink' }}
        </button>
      </div>
    </div>

    <!--
      Native <dialog> gives us a real focus trap (TAB cycles inside), ESC to
      close, and inert siblings, all handled by the platform — same pattern
      as ProxyStatus.vue's revoke-confirm dialog. We restore focus to the
      trigger button in onUnlinkDialogClose.
    -->
    <dialog
      ref="unlinkDialog"
      class="il__modal"
      :aria-labelledby="`il-unlink-title-${id}`"
      @close="onUnlinkDialogClose"
    >
      <h2 :id="`il-unlink-title-${id}`" class="il__modal-title">Unlink {{ display_name }}?</h2>
      <p class="il__modal-body">
        This revokes the stored token for {{ display_name }}. Tools that depend on it will stop
        working until you link it again.
      </p>
      <div class="il__modal-actions">
        <button
          ref="cancelUnlinkBtn"
          type="button"
          class="il__btn il__btn--cancel"
          @click="closeUnlinkConfirm"
        >
          Cancel
        </button>
        <button
          type="button"
          class="il__btn il__btn--confirm-unlink"
          :disabled="busy"
          @click="handleUnlink"
        >
          {{ busy ? 'Unlinking…' : 'Unlink' }}
        </button>
      </div>
    </dialog>
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

.il__error {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.75rem;
  color: var(--color-af-red);
  margin-top: 0.25rem;
}

.il__actions {
  flex-shrink: 0;
  padding-top: 0.125rem;
  max-width: 18rem;
  text-align: right;
}

.il__linked-actions {
  display: flex;
  align-items: center;
  justify-content: flex-end;
  gap: 0.5rem;
  flex-wrap: wrap;
}

/*
 * .il's grid keeps align-items: start so the icon lines up with the top of
 * the body text — but the linked-state action (button or, formerly, hint
 * text) has a different natural height than the body column (name + status +
 * description), which left it stranded near the top of a taller row instead
 * of centered in it. Scoped to the linked variant only — the unlinked row's
 * single-line body keeps looking right at align-items: start.
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

/* Unlink: a destructive action — quiet by default, red on hover, matching
   ProxyStatus.vue's ps__btn--revoke treatment. */
.il__btn--unlink {
  background: transparent;
  color: var(--color-af-dim);
  border-color: var(--color-af-muted);
  font-size: 0.625rem;
  padding: 0.375rem 0.75rem;
}
.il__btn--unlink:not(:disabled):hover {
  color: var(--color-af-red);
  border-color: rgb(from var(--color-af-red) r g b / 0.35);
  background: rgb(from var(--color-af-red) r g b / 0.06);
}

.il__btn--cancel {
  background: transparent;
  color: var(--color-af-dim);
  border-color: var(--color-af-muted);
}
.il__btn--cancel:hover {
  color: var(--color-af-text);
  border-color: var(--color-af-dim);
}

.il__btn--confirm-unlink {
  background: rgb(from var(--color-af-red) r g b / 0.1);
  color: var(--color-af-red);
  border-color: rgb(from var(--color-af-red) r g b / 0.3);
}
.il__btn--confirm-unlink:hover {
  background: rgb(from var(--color-af-red) r g b / 0.18);
}

/* Modal — the native <dialog> element centers itself when opened via
 * showModal(), via the UA stylesheet's `margin: auto` on `dialog:modal`
 * (restored in global.css, where Tailwind's Preflight otherwise zeroes it
 * out -- see the comment there and issue #152). Here we only override the
 * box chrome and add our own ::backdrop with the AF ground tint (same
 * treatment as ProxyStatus.vue's revoke-confirm modal).
 */
.il__modal {
  background: var(--color-af-surface);
  border: 1px solid var(--color-af-muted);
  border-radius: 6px;
  padding: 1.75rem;
  max-width: 28rem;
  width: calc(100% - 2rem);
  color: inherit;
}

.il__modal::backdrop {
  background: rgb(from var(--color-af-void) r g b / 0.85);
  backdrop-filter: blur(4px);
}

.il__modal-title {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 1rem;
  font-weight: 600;
  color: var(--color-af-text);
  margin: 0 0 0.75rem;
}

.il__modal-body {
  font-size: 0.875rem;
  color: #9ca3af;
  line-height: 1.6;
  margin: 0 0 1.5rem;
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
