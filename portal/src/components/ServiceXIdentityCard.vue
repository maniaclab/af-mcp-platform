<script setup lang="ts">
/**
 * ServiceXIdentityCard.vue — the Identities page's card for a servicex-token
 * entry (link_mechanism: "servicex-token").
 *
 * Deliberately NOT full OAuth automation: ServiceX's own token-minting
 * endpoint is gated by a Flask session cookie only ServiceX's own
 * /auth-callback can create, and the token it mints is only ever handed to
 * the user's own browser (a config-file download or a profile-page view),
 * never to a third party via redirect or API — so there is no way for this
 * card to obtain the token on the user's behalf. Instead this is "make the
 * manual step as easy as one click + paste": an external-link button (href
 * from the `external_login_url` prop, operator-configured to wherever the
 * ServiceX deployment mints/shows personal tokens) opens ServiceX's own
 * token page in a new tab, and a single paste field POSTs the copied value
 * to POST /v1/servicex/link (api.ts's linkServiceXToken), which the broker
 * verifies with one redeem before persisting anything.
 *
 * Simpler than X509IdentityCard.vue: no proxy-expiry/custody-mode concept
 * (a servicex-token link is always the hands-free-renewal shape, no
 * "until-expiry" alternative), no POSIX/preflight section. Closer to
 * Krb5IdentityCard.vue's single-secret-field shape, but with only one
 * action (there is no separate durable-keytab-equivalent upload) and no
 * hands-free-attempt-before-form flow (there is nothing to attempt without
 * a first link).
 *
 * CRITICAL SECURITY NOTE (same contract as X509IdentityCard.vue's
 * passphrase / Krb5IdentityCard.vue's password): the refresh-token input is
 * captured and cleared immediately before the API call, regardless of
 * success or failure. It is never stored anywhere beyond the controlled
 * ref() within this component's lifecycle.
 */
import { LINK_ACTION_LABEL } from '../lib/identityLinkLabel';
import { Cable, ExternalLink } from '@lucide/vue';
import { nextTick, ref } from 'vue';
import { linkServiceXToken, unlinkIdentity, type ServiceXTokenMetadata } from '../lib/api';
import { formatDateTime } from '../lib/relativeTime';
import { servicexLinkErrorMessage } from '../lib/servicexIdentity';
import IdentityCardShell from './IdentityCardShell.vue';
import ArmedConfirmButton from './ui/ArmedConfirmButton.vue';

const props = defineProps<{
  id: string;
  linked: boolean;
  display_name: string;
  enables: string;
  /** Display names of catalog backends this identity's credential powers, empty/absent if none. */
  powers?: string[];
  /** URL of ServiceX's own token page, e.g.
   * "https://servicex.af.uchicago.edu/api-token" -- opened in a new tab.
   * The "Get your ServiceX token" button is hidden when this is null/absent
   * (an operator hasn't configured one). */
  external_login_url?: string | null;
}>();

const emit = defineEmits<{
  (e: 'linked', meta: ServiceXTokenMetadata): void;
  (e: 'revoked'): void;
}>();

// Form state — refreshToken is ref('') and cleared immediately after use.
const formOpen = ref(false);
const refreshToken = ref('');
const busy = ref(false);
const error = ref<string | null>(null);
const tokenInput = ref<HTMLInputElement | null>(null);

// Transient result of the last successful link — local state only, gone on
// reload, same treatment as Krb5IdentityCard.vue's `result`.
const result = ref<ServiceXTokenMetadata | null>(null);

// Two-step "Forget" confirmation (ArmedConfirmButton), same inline pattern as
// X509IdentityCard.vue's proxy revoke / Krb5IdentityCard.vue's forget.
const forgetArmed = ref(false);
const forgetError = ref<string | null>(null);

function resetForgetState() {
  forgetArmed.value = false;
  forgetError.value = null;
}

async function openForm() {
  formOpen.value = true;
  error.value = null;
  resetForgetState();
  await nextTick();
  tokenInput.value?.focus();
}

function closeForm() {
  formOpen.value = false;
  refreshToken.value = '';
  error.value = null;
  resetForgetState();
}

async function handleSubmit() {
  if (!refreshToken.value) return;

  busy.value = true;
  error.value = null;

  // Capture and immediately clear the refresh token from Vue state
  const captured = refreshToken.value;
  refreshToken.value = ''; // cleared before the await — regardless of outcome

  try {
    const meta = await linkServiceXToken(captured);
    formOpen.value = false;
    result.value = meta;
    emit('linked', meta);
  } catch (err) {
    // 400 = bad refresh token, 502 = redeem service down — see
    // servicexLinkErrorMessage's contract notes.
    error.value = servicexLinkErrorMessage(err);
  } finally {
    busy.value = false;
    // refreshToken was already cleared above — this is belt-and-suspenders
    refreshToken.value = '';
  }
}

async function handleForget() {
  busy.value = true;
  forgetError.value = null;
  try {
    await unlinkIdentity(props.id);
    forgetArmed.value = false;
    result.value = null;
    emit('revoked');
  } catch (err) {
    forgetError.value = err instanceof Error ? err.message : 'Forget failed. Try again.';
  } finally {
    busy.value = false;
  }
}
</script>

<template>
  <IdentityCardShell
    class="sc"
    :icon="Cable"
    :display-name="display_name"
    :enables="enables"
    :powers="powers"
    :status-tone="linked ? 'ok' : 'off'"
    :status-label="linked ? 'Linked' : 'Not linked'"
  >
    <!-- Transient link result — local state only, gone on reload. -->
    <dl v-if="result" class="af-kv sc__result">
      <dt>Access token expires</dt>
      <dd>{{ formatDateTime(new Date(result.expires_at)) }}</dd>
    </dl>

    <p v-if="forgetError" class="af-note bad sc__error" role="alert">{{ forgetError }}</p>

    <template #actions>
      <a
        v-if="external_login_url"
        :href="external_login_url"
        target="_blank"
        rel="noopener"
        class="af-btn secondary s sc__btn sc__btn--external"
      >
        Get your ServiceX token
        <ExternalLink class="af-icon" :size="16" aria-hidden="true" />
      </a>

      <button
        v-if="!formOpen && !linked"
        type="button"
        class="af-btn secondary s sc__btn sc__btn--link"
        :disabled="busy"
        @click="openForm"
      >
        {{ LINK_ACTION_LABEL.servicex }}
      </button>

      <!-- Re-link overwrites the stored refresh token in place — the fix
           for a rotated/regenerated ServiceX token. -->
      <button
        v-else-if="!formOpen && linked"
        type="button"
        class="af-btn secondary s sc__btn sc__btn--relink"
        :disabled="busy"
        @click="openForm"
      >
        Re-link
      </button>

      <!-- "Forget" deletes the whole stored Vault record (refresh token and
           any cached access token) -- shown only once linked, with the same
           two-step confirm as X509IdentityCard.vue's proxy revoke /
           Krb5IdentityCard.vue's forget. -->
      <div v-if="!formOpen && linked" class="sc__forget-row">
        <ArmedConfirmButton
          v-model:armed="forgetArmed"
          label="Forget this token"
          armed-label="Confirm forget"
          busy-label="Forgetting…"
          :busy="busy"
          trigger-class="sc__btn sc__btn--forget"
          confirm-class="sc__btn sc__btn--forget"
          cancel-class="sc__btn sc__btn--cancel"
          @confirm="handleForget"
        />
      </div>
    </template>

    <!-- Refresh-token paste form — in-page, never a redirect: there is no
         URL ServiceX could redirect the token back to (see the module doc
         comment). -->
    <template v-if="formOpen" #form>
      <form novalidate @submit.prevent="handleSubmit">
        <p class="sc__form-hint">
          Log in via the button above, generate or copy your personal ServiceX token from its page,
          then paste it below.
        </p>

        <div class="af-field">
          <label for="servicex-link-token">ServiceX personal token</label>
          <input
            id="servicex-link-token"
            ref="tokenInput"
            v-model="refreshToken"
            type="password"
            class="af-input"
            autocomplete="off"
            :disabled="busy"
            required
            aria-required="true"
            aria-describedby="servicex-link-token-hint"
          />
          <span id="servicex-link-token-hint" class="hint">
            Verified with one redeem before it's stored — cleared from this page immediately after
            submission.
          </span>
        </div>

        <p v-if="error" class="af-note bad sc__error" role="alert">{{ error }}</p>

        <div class="ids__form-actions">
          <button
            type="button"
            class="af-btn quiet sc__btn sc__btn--cancel"
            :disabled="busy"
            @click="closeForm"
          >
            Cancel
          </button>
          <button
            type="submit"
            class="af-btn secondary sc__btn sc__btn--submit"
            :disabled="busy || !refreshToken"
            :aria-busy="busy"
          >
            {{ busy ? 'Linking…' : linked ? 'Re-link' : 'Link' }}
          </button>
        </div>
      </form>
    </template>
  </IdentityCardShell>
</template>

<style scoped>
.sc__form-hint {
  margin: 0;
  color: var(--color-af-text-secondary);
}
</style>
