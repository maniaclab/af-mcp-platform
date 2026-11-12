<script setup lang="ts">
import { LINK_ACTION_LABEL, RELINK_ACTION_LABEL } from '../lib/identityLinkLabel';
import { Link2 } from '@lucide/vue';
import { ref } from 'vue';
import { fetchOAuth21AuthorizeUrl, unlinkIdentity, type ProviderType } from '../lib/api';
import { startIdpLink } from '../lib/auth';
import IdentityCardShell from './IdentityCardShell.vue';
import ConfirmDialog from './ui/ConfirmDialog.vue';

const props = defineProps<{
  id: string;
  type: ProviderType;
  linked: boolean;
  /** True when a credential is stored but a backend rejected it (`linked` is
   * false then): the user must re-link, which is not the same as never having
   * linked. Absent reads as false. */
  rejected?: boolean;
  display_name: string;
  enables: string;
  /** Display names of catalog backends this identity's credential powers, empty/absent if none. */
  powers?: string[];
  link_url: string | null;
  /** True when Keycloak's stored-broker-token endpoint last answered 403 —
   * the caller's own access token lacks the `read-token` client role, not
   * simply "never linked". Only ever set on a keycloak-brokered entry. */
  link_permission_denied?: boolean;
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

// The unlink confirm is a modal ConfirmDialog (native <dialog>: focus trap,
// Escape, inert page behind it, focus returned to the trigger on close).
const unlinkOpen = ref(false);

async function handleUnlink() {
  unlinkOpen.value = false;
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
</script>

<template>
  <IdentityCardShell
    class="il"
    :icon="Link2"
    :display-name="display_name"
    :enables="enables"
    :powers="powers"
    :status-tone="linked ? 'ok' : rejected || link_permission_denied ? 'warn' : 'off'"
    :status-label="
      linked
        ? 'Linked'
        : rejected
          ? 'Credential rejected'
          : link_permission_denied
            ? 'Access required'
            : 'Not linked'
    "
    :status-class="
      linked
        ? 'il__status il__status--linked'
        : rejected
          ? 'il__status il__status--rejected'
          : link_permission_denied
            ? 'il__status il__status--permission-denied'
            : 'il__status il__status--unlinked'
    "
  >
    <p v-if="!linked && rejected" class="alert af-note warn il__notice" role="status">
      {{ display_name }} rejected the linked credential. Re-link it to restore the services that use
      it.
    </p>
    <p v-if="!linked && link_permission_denied" class="alert af-note warn il__notice" role="status">
      Your account isn't authorized to use this identity yet. Contact the platform team to request
      access.
    </p>
    <p v-if="error" class="alert af-note bad il__error" role="alert">{{ error }}</p>

    <ConfirmDialog
      v-model:open="unlinkOpen"
      :title="`Unlink ${display_name}?`"
      confirm-label="Unlink account"
      busy-label="Unlinking…"
      :busy="busy"
      danger
      @confirm="handleUnlink"
    >
      This revokes the stored token for {{ display_name }}. Tools that depend on it stop working
      until you link it again.
    </ConfirmDialog>

    <template #actions>
      <button
        v-if="!linked && !rejected && canLink"
        type="button"
        class="btn il__btn il__btn--link"
        data-variant="outline"
        data-size="sm"
        :disabled="busy"
        :aria-busy="busy"
        @click="handleLink"
      >
        {{ busy ? 'Redirecting…' : LINK_ACTION_LABEL.account }}
      </button>

      <!--
      Reconnect re-runs the same linking flow, which overwrites the stored
      token in place — a fix for a stale/broken or rejected linkage without an
      explicit unlink. Unlink (oauth21-direct only — DELETE still returns 501 for
      keycloak-brokered, Keycloak admin API unlink is out of scope) actually
      revokes the stored token instead.
      -->
      <template v-else-if="(linked || rejected) && canLink">
        <button
          type="button"
          class="btn il__btn il__btn--reconnect"
          data-variant="outline"
          data-size="sm"
          :disabled="busy"
          :aria-busy="busy"
          @click="handleLink"
        >
          {{ busy ? 'Redirecting…' : RELINK_ACTION_LABEL.account }}
        </button>
        <button
          v-if="canUnlink"
          type="button"
          class="btn af-danger il__btn il__btn--unlink"
          data-variant="outline"
          data-size="sm"
          :disabled="busy"
          :aria-busy="busy"
          @click="unlinkOpen = true"
        >
          {{ busy ? 'Unlinking…' : 'Unlink' }}
        </button>
      </template>
    </template>
  </IdentityCardShell>
</template>
