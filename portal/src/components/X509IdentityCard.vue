<script setup lang="ts">
/**
 * X509IdentityCard.vue — the Identities page's card for an x509 entry
 * (link_mechanism: "passphrase"), and the single home for x509 credential
 * status since the /status/ page was retired: linking, custody consent,
 * the Grid Certificates preflight checklist, and VOMS proxy details all
 * live here.
 *
 * Unlike IdentityLink.vue's redirect flows, x509 links via an in-page
 * passphrase form that POSTs to /v1/x509/proxy. Custody is an explicit
 * choice (the "remember" checkbox): checked (default), the broker stores
 * the passphrase encrypted in the AF vault and renews the proxy hands-free;
 * unchecked, only the proxy is stored and the link lasts exactly its
 * validity window. "Re-link" re-runs the same flow to overwrite a stale
 * link in place (e.g. after a changed Globus password).
 *
 * The two accordions fetch on expand, not on page load — the checklist and
 * proxy details are diagnostics, not something every Identities visit
 * should pay a round trip for.
 *
 * CRITICAL SECURITY NOTE (same contract as before): the passphrase input is
 * captured and cleared immediately before the API call, regardless of
 * success or failure. It is never stored anywhere beyond the controlled
 * ref() within this component's lifecycle.
 */
import { LINK_ACTION_LABEL } from '../lib/identityLinkLabel';
import { ShieldCheck } from '@lucide/vue';
import { nextTick, ref } from 'vue';
import {
  fetchProxyStatus,
  fetchX509Preflight,
  requestProxy,
  revokeProxy,
  type ProxyMetadata,
} from '../lib/api';
import {
  formatProxyExpiry,
  preflightCheckLabel,
  x509LinkErrorMessage,
  x509LinkModeLabel,
  x509PreflightErrorMessage,
} from '../lib/x509Identity';
import { formatDateTime, formatRemaining } from '../lib/relativeTime';
import { useFetchOnExpand } from '../lib/useFetchOnExpand';
import IdentityCardShell from './IdentityCardShell.vue';
import ArmedConfirmButton from './ui/ArmedConfirmButton.vue';
import Disclosure from './ui/Disclosure.vue';
import StatusMark from './ui/StatusMark.vue';

const props = defineProps<{
  linked: boolean;
  display_name: string;
  enables: string;
  /** Display names of catalog backends this identity's credential powers, empty/absent if none. */
  powers?: string[];
  proxy_expires_at?: string | null;
  x509_link_mode?: 'auto-renew' | 'until-expiry' | null;
}>();

const emit = defineEmits<{
  (e: 'linked', meta: ProxyMetadata, remember: boolean): void;
  (e: 'revoked'): void;
}>();

// Form state — passphrase is ref('') and cleared immediately after use.
const formOpen = ref(false);
const passphrase = ref('');
const remember = ref(true);
const busy = ref(false);
const error = ref<string | null>(null);
const passphraseInput = ref<HTMLInputElement | null>(null);

// Grid Certificates preflight accordion — fetched on expand, never on load.
// The fetcher maps a failure to the user-facing checklist message.
const {
  open: preflightOpen,
  data: preflight,
  loading: preflightLoading,
  error: preflightError,
  toggle: togglePreflight,
} = useFetchOnExpand(async () => {
  try {
    return await fetchX509Preflight();
  } catch (err) {
    throw new Error(x509PreflightErrorMessage(err));
  }
}, 'Could not load the certificate checklist. Try again.');

// VOMS proxy details accordion — fetched on expand, never on load.
const {
  open: proxyOpen,
  data: proxyStatus,
  loading: proxyLoading,
  error: proxyError,
  toggle: fetchProxyDetails,
} = useFetchOnExpand(() => fetchProxyStatus(), 'Could not load proxy status.');
// Two-step revoke confirmation (click "Revoke proxy", then "Confirm revoke").
const revokeArmed = ref(false);

async function openForm() {
  formOpen.value = true;
  remember.value = true;
  error.value = null;
  await nextTick();
  passphraseInput.value?.focus();
}

function closeForm() {
  formOpen.value = false;
  passphrase.value = '';
  error.value = null;
}

async function handleSubmit() {
  if (!passphrase.value) return;

  busy.value = true;
  error.value = null;

  // Capture and immediately clear the passphrase from Vue state
  const captured = passphrase.value;
  passphrase.value = ''; // cleared before the await — regardless of outcome

  try {
    const meta = await requestProxy(captured, '12:00', 'atlas', remember.value);
    formOpen.value = false;
    proxyStatus.value = null; // stale — refetched on next expand
    emit('linked', meta, remember.value);
  } catch (err) {
    // 400 = bad passphrase, 429 = unlock rate limit, 502 = service outage —
    // see x509LinkErrorMessage's contract notes.
    error.value = x509LinkErrorMessage(err);
  } finally {
    busy.value = false;
    // passphrase was already cleared above — this is belt-and-suspenders
    passphrase.value = '';
  }
}

function toggleProxyDetails() {
  revokeArmed.value = false;
  fetchProxyDetails();
}

async function handleRevoke() {
  busy.value = true;
  proxyError.value = null;
  try {
    await revokeProxy();
    revokeArmed.value = false;
    proxyStatus.value = { cached: false, voms_attributes: [] };
    emit('revoked');
  } catch (err) {
    proxyError.value = err instanceof Error ? err.message : 'Revoke failed.';
  } finally {
    busy.value = false;
  }
}

/** Time left on a proxy, from the service's own remaining_seconds so a skewed browser clock cannot misreport it. */
function remainingText(seconds?: number | null): string {
  const now = new Date();
  return formatRemaining(new Date(now.getTime() + (seconds ?? 0) * 1000), now);
}
</script>

<template>
  <IdentityCardShell
    class="xc"
    :icon="ShieldCheck"
    :display-name="display_name"
    :enables="enables"
    :powers="powers"
    :status-tone="linked ? 'ok' : 'off'"
    :status-label="linked ? 'Linked' : 'Not linked'"
  >
    <!-- Custody line: which mode the link is in. Falls back to the plain
         expiry line for a legacy-mode link, which has no custody concept. -->
    <p
      v-if="linked && x509LinkModeLabel(props.x509_link_mode, props.proxy_expires_at)"
      class="xc__expiry"
    >
      {{ x509LinkModeLabel(props.x509_link_mode, props.proxy_expires_at) }}
    </p>
    <p v-else-if="linked && formatProxyExpiry(props.proxy_expires_at)" class="xc__expiry">
      Proxy expires {{ formatProxyExpiry(props.proxy_expires_at) }}
    </p>

    <!-- Grid Certificates preflight — is the ~/.globus credential in a state
         where minting could possibly work? Fetched on expand. -->
    <div class="xc__section">
      <Disclosure :open="preflightOpen" @toggle="togglePreflight">
        <template #label>Grid certificate files</template>
        <template #badge>
          <StatusMark v-if="preflight?.ok" class="xc__chip" tone="ok" label="Mounted" />
          <StatusMark v-else-if="preflight" class="xc__chip" tone="warn" label="Problems found" />
        </template>

        <p v-if="preflightLoading" class="xc__section-note" aria-live="polite">
          Checking certificate files…
        </p>
        <p v-else-if="preflightError" class="alert af-note bad xc__error" role="alert">
          {{ preflightError }}
        </p>
        <div v-else-if="preflight" class="table-container af-box">
          <table class="af-compact table">
            <thead>
              <tr>
                <th>Check</th>
                <th>Path</th>
                <th>Exists</th>
                <th>Mode</th>
                <th>Readable</th>
              </tr>
            </thead>
            <tbody>
              <template v-for="check in preflight.checks" :key="check.name">
                <tr>
                  <td>{{ preflightCheckLabel(check.name) }}</td>
                  <td>
                    <code>{{ check.path }}</code>
                  </td>
                  <td>
                    <StatusMark
                      :tone="check.exists ? 'ok' : 'bad'"
                      :label="check.exists ? 'Yes' : 'No'"
                    />
                  </td>
                  <td>{{ check.mode ?? '—' }}</td>
                  <td>
                    <template
                      v-if="
                        check.readable_by_service === undefined ||
                        check.readable_by_service === null
                      "
                      >—</template
                    >
                    <StatusMark
                      v-else
                      :tone="check.readable_by_service ? 'ok' : 'bad'"
                      :label="check.readable_by_service ? 'Yes' : 'No'"
                    />
                  </td>
                </tr>
                <!-- The actionable fix (e.g. the chmod 400 command) for a
                     failing check gets its own full-width row. -->
                <tr v-if="!check.ok && check.detail" class="xc__detail-row">
                  <td colspan="5" class="af-sub">{{ check.detail }}</td>
                </tr>
              </template>
            </tbody>
          </table>
        </div>
      </Disclosure>
    </div>

    <!-- VOMS proxy details — DN, attributes, expiry, revoke. Only offered
         once linked; fetched on expand. -->
    <div v-if="linked" class="xc__section">
      <Disclosure :open="proxyOpen" @toggle="toggleProxyDetails">
        <template #label>VOMS proxy details</template>
        <template #badge>
          <StatusMark v-if="proxyStatus?.cached" class="xc__chip" tone="ok" label="Active" />
          <StatusMark v-else-if="proxyStatus" class="xc__chip" tone="off" label="No proxy" />
        </template>

        <p v-if="proxyLoading" class="xc__section-note" aria-live="polite">
          Checking proxy status…
        </p>
        <p v-else-if="proxyError" class="alert af-note bad xc__error" role="alert">
          {{ proxyError }}
        </p>
        <template v-else-if="proxyStatus">
          <template v-if="proxyStatus.cached">
            <dl class="af-kv xc__proxy">
              <dt>Subject DN</dt>
              <dd>
                <code>{{ proxyStatus.dn ?? '—' }}</code>
              </dd>
              <dt>Expires</dt>
              <dd>
                {{
                  proxyStatus.expires_at
                    ? formatDateTime(new Date(proxyStatus.expires_at), { year: true })
                    : 'unknown'
                }}
                ({{ remainingText(proxyStatus.remaining_seconds) }})
              </dd>
              <template v-if="proxyStatus.nickname">
                <dt>CERN account</dt>
                <dd>
                  <code>{{ proxyStatus.nickname }}</code>
                </dd>
              </template>
            </dl>
            <ArmedConfirmButton
              v-model:armed="revokeArmed"
              label="Revoke proxy"
              armed-label="Confirm revoke"
              busy-label="Revoking…"
              :busy="busy"
              trigger-class="xc__btn xc__btn--revoke"
              confirm-class="xc__btn xc__btn--revoke"
              cancel-class="xc__btn xc__btn--cancel"
              @confirm="handleRevoke"
            />
          </template>
          <p v-else class="xc__section-note">
            No proxy is currently stored — link (or re-link) above to create one.
          </p>
        </template>
      </Disclosure>
    </div>

    <template #actions>
      <button
        v-if="!formOpen && !linked"
        type="button"
        class="btn xc__btn xc__btn--link"
        data-variant="outline"
        data-size="sm"
        :disabled="busy"
        @click="openForm"
      >
        {{ LINK_ACTION_LABEL.certificate }}
      </button>

      <!-- Re-link re-runs the same passphrase flow, overwriting the stored
           link in place — the fix for a changed Globus password. -->
      <button
        v-else-if="!formOpen && linked"
        type="button"
        class="btn xc__btn xc__btn--relink"
        data-variant="outline"
        data-size="sm"
        :disabled="busy"
        @click="openForm"
      >
        Re-link
      </button>
    </template>

    <!-- Passphrase form — in-page, never a redirect: the broker needs the
         Globus passphrase once to mint the proxy (and, only with consent
         below, to store for renewal). -->
    <template v-if="formOpen" #form>
      <form novalidate @submit.prevent="handleSubmit">
        <div class="field af-narrow">
          <label for="x509-link-passphrase">Grid certificate passphrase</label>
          <input
            id="x509-link-passphrase"
            ref="passphraseInput"
            v-model="passphrase"
            type="password"
            class="input"
            autocomplete="current-password"
            :disabled="busy"
            required
            aria-required="true"
            aria-describedby="x509-link-passphrase-hint"
          />
          <p id="x509-link-passphrase-hint">
            Sent once to create the proxy — cleared from this page immediately after submission.
          </p>
        </div>

        <!-- Custody consent: storing the passphrase is the user's explicit
             choice, defaulting to the hands-free-renewal behavior. -->
        <div class="field af-narrow">
          <div class="field xc__consent" data-orientation="horizontal">
            <input
              id="x509-link-remember"
              v-model="remember"
              type="checkbox"
              class="input"
              :disabled="busy"
              aria-describedby="x509-consent-hint"
            />
            <label for="x509-link-remember">
              Remember my passphrase for automatic renewal (stored encrypted in the AF vault)
            </label>
          </div>
          <p v-if="!remember" id="x509-consent-hint">
            Your proxy will work for its validity window, then you'll re-link here.
          </p>
        </div>

        <p v-if="error" class="alert af-note bad xc__error" role="alert">{{ error }}</p>

        <div class="ids__form-actions">
          <button
            type="button"
            class="btn xc__btn xc__btn--cancel"
            data-variant="ghost"
            :disabled="busy"
            @click="closeForm"
          >
            Cancel
          </button>
          <button
            type="submit"
            class="btn xc__btn xc__btn--submit"
            data-variant="outline"
            :disabled="busy || !passphrase"
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
.xc__expiry,
.xc__section-note {
  margin: 0;
  color: var(--color-af-text-secondary);
}

.xc__section {
  padding-top: var(--space-8);
  border-top: 1px solid var(--color-af-border);
}

/* The status mark sits after the disclosure label inside its toggle button. */
.xc__chip {
  margin-left: var(--space-8);
  font-weight: 400;
}

.xc__proxy {
  margin-bottom: var(--space-12);
}
</style>
