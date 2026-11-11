<script setup lang="ts">
/**
 * Krb5IdentityCard.vue — the Identities page's card for a krb5-token entry
 * (link_mechanism: "credential").
 *
 * Two separate, mutually exclusive actions live in this card, gated by
 * their own `formOpen`/`keytabFormOpen` refs (opening one closes the
 * other):
 *
 * - "Get Kerberos ticket" / "Refresh ticket" — while linked, this button
 *   does NOT open the password form directly: it first attempts a
 *   hands-free mint (POST /v1/krb5/ticket with no credential at all).
 *   The broker's KrbTokenProvider.issue() tries, in order, a cached ticket,
 *   a still-renewable one (tier 3, no credential), and THEN a linked
 *   keytab (tier 4, no credential either) before ever needing a password
 *   -- see krb5.py's module docstring -- so demanding one upfront would be
 *   needless friction for exactly the callers this card marks "keytab
 *   linked". Only when every one of those rejects does the attempt come
 *   back 409 (`APIError` status 409 -- nothing usable without a
 *   credential), and openForm() then runs, falling back to the in-page
 *   username/password form that POSTs to the same endpoint with both
 *   fields set. Since a linked keytab always implies `linked` too, a bad
 *   stored keytab (tier 4's own `Krb5TokenBadCredentialError` handling)
 *   is *always* what a 409 means for a caller who had one -- the broker
 *   proactively deletes it server-side right there, so the fallback form
 *   says so explicitly (and this card emits `keytab-unlinked` to drop its
 *   own badge immediately) rather than reusing the plain "enter your
 *   password" wording a caller with no keytab at all gets. An unlinked
 *   caller skips the hands-free attempt entirely (guaranteed to need a
 *   password on a first link) and goes straight to the form. No custody
 *   either way: the broker uses a submitted password once and never
 *   stores it, and submitting the form alone establishes no durable
 *   renewal link.
 * - "Link a keytab" / "Replace keytab" — a durable link. The user
 *   generates a keytab themselves (on lxplus, per the in-form instructions
 *   — the broker cannot generate one itself, see krb5.py's module
 *   docstring for why) and uploads it via POST /v1/krb5/keytab. The broker
 *   validates the keytab by minting a ticket with it (mirroring
 *   krb5-token-service's tier-4 remint) before persisting it; a keytab
 *   that doesn't authenticate is rejected with nothing stored. This is
 *   what makes the hands-free refresh above actually succeed for a linked
 *   caller, rather than always falling through to 409.
 *
 * All three routes return the same `KrbTicketMetadata` shape, so a
 * successful call from any of them shares the same transient result
 * rendering below (principal/realm/expiry) — shown in local component
 * state only, never persisted, and gone on reload, leaving just the plain
 * linked/not-linked badge (and, once a keytab is linked, the separate
 * "keytab linked" badge) from props.
 *
 * Once linked, a "Forget this ticket" button calls the shared
 * unlinkIdentity() (already used by IdentityLink.vue) to delete the whole
 * Vault record — the stored keytab included, not just the current ticket.
 *
 * CRITICAL SECURITY NOTE (same contract as X509IdentityCard.vue's
 * passphrase): the password input is captured and cleared immediately
 * before the API call, regardless of success or failure. It is never stored
 * anywhere beyond the controlled ref() within this component's lifecycle.
 * The keytab file's contents pass through this component only as a
 * transient base64 string built for the one POST body — also never
 * persisted client-side.
 */
import { LINK_ACTION_LABEL } from '../lib/identityLinkLabel';
import { Ticket } from '@lucide/vue';
import { computed, nextTick, ref } from 'vue';
import {
  APIError,
  linkKrb5Keytab,
  requestKrb5Ticket,
  unlinkIdentity,
  type KrbTicketMetadata,
} from '../lib/api';
import { describeKrb5Source, krb5LinkErrorMessage } from '../lib/krb5Identity';
import { formatDateTime } from '../lib/relativeTime';
import IdentityCardShell from './IdentityCardShell.vue';
import ArmedConfirmButton from './ui/ArmedConfirmButton.vue';
import StatusMark from './ui/StatusMark.vue';

const props = defineProps<{
  id: string;
  linked: boolean;
  /** True only once a keytab is durably linked (tier 4 can remint hands-free
   * indefinitely) -- distinct from `linked` alone, which also reads true for
   * nothing more than a live/renewable ticket with no keytab. Drives the
   * "keytab linked" badge and the "Replace keytab" vs. "Link a keytab"
   * button label. */
  krb5_has_keytab?: boolean;
  display_name: string;
  enables: string;
  /** Display names of catalog backends this identity's credential powers, empty/absent if none. */
  powers?: string[];
}>();

const emit = defineEmits<{
  (e: 'linked', meta: KrbTicketMetadata): void;
  // Fires only for the keytab-upload flow, alongside `linked` above (both
  // fire together for that flow) -- the one IdentitiesPage.vue listens to
  // in order to flip `krb5_has_keytab` locally without a full refetch.
  (e: 'keytab-linked'): void;
  // Fires when a hands-free refresh's 409 reveals the broker just deleted
  // this principal's stored keytab (see attemptHandsFreeRefresh() below) --
  // the counterpart to `keytab-linked`, dropping `krb5_has_keytab` locally
  // the moment the fallback form appears, rather than waiting for a later
  // /v1/identities refetch to notice.
  (e: 'keytab-unlinked'): void;
  (e: 'revoked'): void;
}>();

// Form state — password is ref('') and cleared immediately after use.
const formOpen = ref(false);
const username = ref('');
const password = ref('');
const busy = ref(false);
const error = ref<string | null>(null);
const usernameInput = ref<HTMLInputElement | null>(null);

// Result of a failed hands-free refresh attempt (see attemptHandsFreeRefresh()
// below) -- rendered in the body, not inside `formOpen`'s form, since a
// non-409 failure there leaves no form open at all. A 409 instead opens the
// password form with refreshFallbackNotice set, not this.
const refreshError = ref<string | null>(null);
// Set only when the password form was opened BECAUSE a hands-free refresh
// attempt came back 409 -- explains why the form suddenly appeared instead
// of the password hint's usual framing. Cleared whenever the form closes.
const refreshFallbackNotice = ref<string | null>(null);

// Keytab-upload form state — separate from the password-mint form above,
// and mutually exclusive with it (see openForm()/openKeytabForm()).
const keytabFormOpen = ref(false);
const keytabUsername = ref('');
const keytabFile = ref<File | null>(null);
const keytabBusy = ref(false);
const keytabError = ref<string | null>(null);
const keytabUsernameInput = ref<HTMLInputElement | null>(null);
const keytabFileInput = ref<HTMLInputElement | null>(null);

// Transient result of the last successful mint (either form) — local state
// only, never persisted, and gone on reload (see the module doc comment
// above).
const result = ref<KrbTicketMetadata | null>(null);

// Human-readable note for result.source (see describeKrb5Source's doc
// comment) -- '' both for a pre-#286 ticket with no source field and for
// any source value this card doesn't recognize, so the paragraph below
// simply doesn't render rather than showing a blank/garbled line.
const sourceNote = computed(() => (result.value ? describeKrb5Source(result.value.source) : ''));

// Two-step "Forget" confirmation (click "Forget this ticket", then "Confirm
// forget" via ArmedConfirmButton) — same inline pattern as
// X509IdentityCard.vue's proxy revoke, chosen over IdentityLink.vue's
// heavier ConfirmDialog since deleting the stored keytab is a
// comparable-consequence destructive action (losing hands-free renewal,
// same as revoking a proxy) rather than a lighter one.
const forgetArmed = ref(false);
// Separate from `error` above -- that one only renders inside the
// username/password form, but forgetting can be triggered (and can fail)
// while the form is closed.
const forgetError = ref<string | null>(null);

// Reset the two-step forget confirmation and any stale forget error whenever
// the mint form's visibility changes -- the forget row is hidden while the
// form is open (`v-if="!formOpen && linked"`), so without this an armed
// confirmation (or a leftover failure alert) survives invisibly and
// reappears pre-armed/stale once the form closes again.
function resetForgetState() {
  forgetArmed.value = false;
  forgetError.value = null;
}

async function openForm() {
  formOpen.value = true;
  closeKeytabForm();
  error.value = null;
  refreshError.value = null;
  resetForgetState();
  await nextTick();
  usernameInput.value?.focus();
}

function closeForm() {
  formOpen.value = false;
  username.value = '';
  password.value = '';
  error.value = null;
  refreshFallbackNotice.value = null;
  resetForgetState();
}

/**
 * Click handler for the top "Get Kerberos ticket" / "Refresh ticket"
 * button -- see the module doc comment for why a linked caller tries a
 * hands-free mint before ever seeing the password form, while an unlinked
 * one goes straight to it.
 */
async function handleMintClick() {
  if (props.linked) {
    await attemptHandsFreeRefresh();
  } else {
    await openForm();
  }
}

/**
 * POSTs /v1/krb5/ticket with no credential at all -- the broker's
 * KrbTokenProvider.issue() may already satisfy this via a linked keytab or
 * a still-renewable ticket (see requestKrb5Ticket()'s doc comment). A 409
 * means nothing worked without one, so this falls back to the password
 * form instead of surfacing it as an ordinary error.
 */
async function attemptHandsFreeRefresh() {
  closeKeytabForm();
  resetForgetState();
  // Captured before the request: a 409 always means the broker just
  // exhausted (and, if it was a keytab, deleted) whatever this caller had
  // BEFORE this attempt -- see the module doc comment's explanation of why
  // `krb5_has_keytab` alone is enough to tell the two 409 causes apart.
  const hadKeytab = props.krb5_has_keytab ?? false;
  busy.value = true;
  refreshError.value = null;
  try {
    const meta = await requestKrb5Ticket();
    result.value = meta;
    emit('linked', meta);
  } catch (err) {
    if (err instanceof APIError && err.status === 409) {
      if (hadKeytab) {
        refreshFallbackNotice.value =
          'Your linked keytab stopped working and was removed — enter your CERN password to get a new ticket, then link a fresh keytab below if you want automatic renewal again.';
        emit('keytab-unlinked');
      } else {
        refreshFallbackNotice.value =
          "Automatic renewal isn't available right now — enter your CERN password to get a new ticket.";
      }
      await openForm();
    } else {
      refreshError.value = krb5LinkErrorMessage(err);
    }
  } finally {
    busy.value = false;
  }
}

async function openKeytabForm() {
  keytabFormOpen.value = true;
  closeForm();
  keytabError.value = null;
  resetForgetState();
  await nextTick();
  keytabUsernameInput.value?.focus();
}

function closeKeytabForm() {
  keytabFormOpen.value = false;
  keytabUsername.value = '';
  keytabFile.value = null;
  if (keytabFileInput.value) keytabFileInput.value.value = '';
  keytabError.value = null;
  resetForgetState();
}

/** Reads a File as a base64 string — a keytab is a small binary file, a few KB at most. */
function fileToBase64(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      // readAsDataURL yields "data:<mime>;base64,<data>" — keep only the payload.
      const dataUrl = reader.result as string;
      resolve(dataUrl.slice(dataUrl.indexOf(',') + 1));
    };
    reader.onerror = () => reject(reader.error ?? new Error('Failed to read the keytab file.'));
    reader.readAsDataURL(file);
  });
}

function handleKeytabFileChange(event: Event) {
  const input = event.target as HTMLInputElement;
  keytabFile.value = input.files?.[0] ?? null;
}

async function handleSubmit() {
  if (!username.value || !password.value) return;

  busy.value = true;
  error.value = null;

  // Capture and immediately clear the password from Vue state
  const capturedUsername = username.value;
  const capturedPassword = password.value;
  password.value = ''; // cleared before the await — regardless of outcome

  try {
    const meta = await requestKrb5Ticket(
      capturedUsername,
      capturedPassword,
      undefined,
      undefined,
      undefined,
    );
    formOpen.value = false;
    result.value = meta;
    emit('linked', meta);
  } catch (err) {
    // 400 = bad username/password, 403 = revoked/expired account, 422 =
    // malformed input, 429 = rate limit, 502 = service outage — see
    // krb5LinkErrorMessage's contract notes.
    error.value = krb5LinkErrorMessage(err);
  } finally {
    busy.value = false;
    // password was already cleared above — this is belt-and-suspenders
    password.value = '';
  }
}

async function handleKeytabSubmit() {
  if (!keytabUsername.value || !keytabFile.value) return;

  keytabBusy.value = true;
  keytabError.value = null;

  try {
    const keytabB64 = await fileToBase64(keytabFile.value);
    const meta = await linkKrb5Keytab(keytabUsername.value, keytabB64);
    keytabFormOpen.value = false;
    result.value = meta;
    emit('linked', meta);
    emit('keytab-linked');
  } catch (err) {
    // Same status-code contract as the password form's handleSubmit — see
    // krb5LinkErrorMessage's contract notes (shared between both routes).
    keytabError.value = krb5LinkErrorMessage(err);
  } finally {
    keytabBusy.value = false;
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
    class="kc"
    :icon="Ticket"
    :display-name="display_name"
    :enables="enables"
    :powers="powers"
    :status-tone="linked ? 'ok' : 'off'"
    :status-label="linked ? 'Linked' : 'Not linked'"
  >
    <!-- Distinct from the status beside the name: `linked` alone can mean
         nothing more durable than a still-renewable ticket, see
         krb5_has_keytab's prop doc comment. -->
    <template #status-extra>
      <StatusMark
        v-if="krb5_has_keytab"
        class="kc__status kc__status--keytab"
        tone="ok"
        label="Keytab linked"
      />
    </template>

    <!-- Transient mint result — local state only, gone on reload. -->
    <template v-if="result">
      <dl class="af-kv kc__result">
        <dt>Principal</dt>
        <dd>
          <code>{{ result.principal }}</code>
        </dd>
        <dt>Realm</dt>
        <dd>
          <code>{{ result.realm }}</code>
        </dd>
        <dt>Expires</dt>
        <dd>{{ formatDateTime(new Date(result.expires_at)) }}</dd>
      </dl>
      <!-- af-mcp-platform#286 UI follow-up: says what a "Refresh ticket"
           click actually did -- cache hit vs. a genuine renew/remint --
           rather than every outcome rendering identically. Empty (and
           hidden) for a ticket minted before the broker returned this
           field. -->
      <p v-if="sourceNote" class="kc__source-note">{{ sourceNote }}</p>
    </template>

    <p v-if="forgetError" class="af-note bad kc__error" role="alert">{{ forgetError }}</p>
    <!-- A failed hands-free refresh that wasn't a 409 (see
         attemptHandsFreeRefresh()) -- a 409 opens the password form
         instead of landing here. -->
    <p v-if="refreshError" class="af-note bad kc__error" role="alert">{{ refreshError }}</p>

    <template #actions>
      <!-- While linked, this click attempts a hands-free mint before ever
           opening the password form below -- see handleMintClick()'s and
           the module doc comment's explanation. -->
      <button
        v-if="!formOpen"
        type="button"
        class="af-btn secondary s kc__btn kc__btn--link"
        :disabled="busy"
        @click="handleMintClick"
      >
        {{ busy ? 'Refreshing…' : linked ? 'Refresh ticket' : LINK_ACTION_LABEL.kerberos }}
      </button>

      <!-- Separate action from the one-shot mint above: uploads a
           user-generated keytab so the broker can renew the ticket
           hands-free -- see the module doc comment for the design split.
           Visible whenever its own form isn't already open (independent of
           `formOpen`), so it can be clicked directly to switch away from an
           open password form -- openKeytabForm() then closes that form. -->
      <button
        v-if="!keytabFormOpen"
        type="button"
        class="af-btn secondary s kc__btn kc__btn--keytab"
        :disabled="keytabBusy"
        @click="openKeytabForm"
      >
        {{ krb5_has_keytab ? 'Replace keytab' : 'Link a keytab' }}
      </button>

      <!-- "Forget" deletes the whole stored Vault record (any linked
           keytab included, not just the current ticket) -- shown only once
           linked, with a two-step confirm mirroring X509IdentityCard.vue's
           proxy revoke. -->
      <div v-if="!formOpen && !keytabFormOpen && linked" class="kc__forget-row">
        <ArmedConfirmButton
          v-model:armed="forgetArmed"
          label="Forget this ticket"
          armed-label="Confirm forget"
          busy-label="Forgetting…"
          :busy="busy"
          trigger-class="kc__btn kc__btn--forget"
          confirm-class="kc__btn kc__btn--forget"
          cancel-class="kc__btn kc__btn--cancel"
          @confirm="handleForget"
        />
      </div>
    </template>

    <!-- Username/password form and keytab-upload form are mutually exclusive
         (see openForm()/openKeytabForm()), so one form region serves both. -->
    <template v-if="formOpen || keytabFormOpen" #form>
      <!-- Username/password form — in-page, never a redirect: the broker
           needs the CERN password once to mint the ticket. -->
      <form v-if="formOpen" novalidate @submit.prevent="handleSubmit">
        <!-- Only present when this form opened because a hands-free refresh
             attempt came back 409 -- see attemptHandsFreeRefresh(). Its own
             class (rather than relying on text matching) is what tests
             target to tell this apart from the unconditional password hint
             below. -->
        <p v-if="refreshFallbackNotice" class="af-note warn kc__fallback-notice">
          {{ refreshFallbackNotice }}
        </p>

        <div class="af-field">
          <label for="krb5-link-username">CERN username</label>
          <input
            id="krb5-link-username"
            ref="usernameInput"
            v-model="username"
            type="text"
            class="af-input"
            autocomplete="username"
            :disabled="busy"
            required
            aria-required="true"
          />
        </div>

        <div class="af-field">
          <label for="krb5-link-password">CERN password</label>
          <input
            id="krb5-link-password"
            v-model="password"
            type="password"
            class="af-input"
            autocomplete="current-password"
            :disabled="busy"
            required
            aria-required="true"
            aria-describedby="krb5-link-password-hint"
          />
          <span id="krb5-link-password-hint" class="hint">
            Your CERN password is used once to create this ticket and is never stored — you'll need
            to re-enter it after the ticket expires.
          </span>
        </div>

        <p v-if="error" class="af-note bad kc__error" role="alert">{{ error }}</p>

        <div class="ids__form-actions">
          <button
            type="button"
            class="af-btn quiet kc__btn kc__btn--cancel"
            :disabled="busy"
            @click="closeForm"
          >
            Cancel
          </button>
          <button
            type="submit"
            class="af-btn secondary kc__btn kc__btn--submit"
            :disabled="busy || !username || !password"
            :aria-busy="busy"
          >
            {{ busy ? 'Minting…' : linked ? 'Refresh ticket' : 'Get ticket' }}
          </button>
        </div>
      </form>

      <!-- Keytab-upload form -- a separate action from the password-mint
           form above, never shown at the same time. -->
      <form v-else novalidate @submit.prevent="handleKeytabSubmit">
        <p class="kc__form-hint">
          Generate a keytab on lxplus, then upload it here so the broker can renew your Kerberos
          ticket automatically without asking for your password again:
        </p>
        <pre class="kc__keytab-steps"><code>ssh &lt;username&gt;@lxplus.cern.ch
cern-get-keytab --keytab &lt;username&gt;.keytab --user
# (enter your CERN password when prompted)
kinit -kt &lt;username&gt;.keytab &lt;username&gt;@CERN.CH   # verify it works
echo $?                                          # should print 0</code></pre>
        <p class="kc__form-hint">
          Then download <code>&lt;username&gt;.keytab</code> from lxplus (e.g.
          <code>scp &lt;username&gt;@lxplus.cern.ch:&lt;username&gt;.keytab .</code>) and upload it
          below.
        </p>

        <div class="af-field">
          <label for="krb5-keytab-username">CERN username</label>
          <input
            id="krb5-keytab-username"
            ref="keytabUsernameInput"
            v-model="keytabUsername"
            type="text"
            class="af-input"
            autocomplete="username"
            :disabled="keytabBusy"
            required
            aria-required="true"
          />
        </div>

        <div class="af-field">
          <label for="krb5-keytab-file">Keytab file</label>
          <input
            id="krb5-keytab-file"
            ref="keytabFileInput"
            type="file"
            class="af-input"
            :disabled="keytabBusy"
            required
            aria-required="true"
            @change="handleKeytabFileChange"
          />
        </div>

        <p v-if="keytabError" class="af-note bad kc__error" role="alert">{{ keytabError }}</p>

        <div class="ids__form-actions">
          <button
            type="button"
            class="af-btn quiet kc__btn kc__btn--cancel"
            :disabled="keytabBusy"
            @click="closeKeytabForm"
          >
            Cancel
          </button>
          <button
            type="submit"
            class="af-btn secondary kc__btn kc__btn--submit"
            :disabled="keytabBusy || !keytabUsername || !keytabFile"
            :aria-busy="keytabBusy"
          >
            {{ keytabBusy ? 'Linking…' : 'Link keytab' }}
          </button>
        </div>
      </form>
    </template>
  </IdentityCardShell>
</template>

<style scoped>
.kc__source-note,
.kc__form-hint {
  margin: 0;
  color: var(--color-af-text-secondary);
}

.kc__keytab-steps {
  margin: 0;
  padding: var(--space-12) var(--space-16);
  overflow-x: auto;
  border: 1px solid var(--color-af-border);
  border-radius: var(--radius-8);
  background: var(--color-af-bg-subtle);
  font: 400 var(--text-13) / 1.6 var(--font-mono);
}
</style>
