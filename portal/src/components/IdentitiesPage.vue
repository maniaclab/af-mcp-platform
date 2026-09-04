<script setup lang="ts">
import { computed, onMounted, ref } from 'vue';
import {
  AccessDeniedError,
  clearIdentitiesCache,
  fetchCatalog,
  fetchIdentities,
  SessionExpiredError,
  type CatalogServer,
  type IdentityProvider,
  type KrbTicketMetadata,
  type ProxyMetadata,
} from '../lib/api';
import { groupServersByAlias } from '../lib/catalog';
import {
  extractLinkedErrorParams,
  extractLinkedParam,
  resolveLinkedBanner,
  resolveLinkedErrorBanner,
} from '../lib/linkedBanner';
import IdentityLink from './IdentityLink.vue';
import Krb5IdentityCard from './Krb5IdentityCard.vue';
import X509IdentityCard from './X509IdentityCard.vue';

const providers = ref<IdentityProvider[]>([]);
const loading = ref(true);
const error = ref<string | null>(null);
const sessionExpired = ref(false);
const accessDenied = ref<AccessDeniedError | null>(null);

// Which servers each identity feeds, for the "What each identity unlocks"
// grid below — joined client-side from the catalog's credential_provider
// field (issue #90). Fetched separately from providers/error/sessionExpired
// above since it's an enhancement to the explainer, not core identity-linking
// functionality: a catalog fetch failure just leaves the grid without its
// server list rather than blocking the page.
const catalogServers = ref<CatalogServer[]>([]);
const serversByAlias = computed(() => groupServersByAlias(catalogServers.value));

function serversForAlias(id: string): CatalogServer[] {
  return serversByAlias.value.get(id) ?? [];
}

/** Display names of the catalog backends this identity's credential powers,
 * rendered as capability chips -- empty array (not shown by IdentityLink/
 * X509IdentityCard) if none. */
function powersForAlias(id: string): string[] {
  return serversForAlias(id).map((s) => s.display_name);
}

// Set by a `?linked=<id>` landing (see broker/src/af_mcp_broker/api/oauth21.py's
// `callback` route) — the display_name of the just-linked provider, or null
// if `linked` was absent or didn't match a real provider (see
// resolveLinkedBanner in ../lib/linkedBanner.ts). Fades on its own after
// ~5s; also dismissed by the banner's own close affordance.
const linkedBanner = ref<string | null>(null);
let linkedBannerTimer: ReturnType<typeof setTimeout> | undefined;

// Set by a `?linked_error=<code>&linked_error_alias=<id>` landing — the
// backend AS itself failed (e.g. rucio-mcp's outbound call to Rucio auth
// 401ing), surfaced as a friendly message instead of the broker's raw 422.
// Same fade/dismiss behavior as `linkedBanner`.
const linkedErrorBanner = ref<string | null>(null);
let linkedErrorBannerTimer: ReturnType<typeof setTimeout> | undefined;

function dismissLinkedBanner() {
  linkedBanner.value = null;
  clearTimeout(linkedBannerTimer);
}

function dismissLinkedErrorBanner() {
  linkedErrorBanner.value = null;
  clearTimeout(linkedErrorBannerTimer);
}

onMounted(async () => {
  const { linkedId, remainingSearch: afterLinked } = extractLinkedParam(window.location.search);
  const linkedError = extractLinkedErrorParams(afterLinked);
  if (linkedId || linkedError) {
    // The cache now reflects a pre-link snapshot — drop it so the fetch
    // below (and every subsequent page load) sees the newly-linked provider.
    // Harmless on the error path too (linking didn't actually change
    // anything), but keeps this behavior uniform across both outcomes.
    clearIdentitiesCache();
    // Rewrite the URL so a refresh doesn't re-show the banner.
    window.history.replaceState(
      {},
      '',
      window.location.pathname +
        (linkedError ? linkedError.remainingSearch : afterLinked) +
        window.location.hash,
    );
  }

  try {
    const data = await fetchIdentities();
    providers.value = data.providers;
    linkedBanner.value = resolveLinkedBanner(data.providers, linkedId);
    if (linkedBanner.value) {
      linkedBannerTimer = setTimeout(dismissLinkedBanner, 5000);
    }
    linkedErrorBanner.value = resolveLinkedErrorBanner(data.providers, linkedError);
    if (linkedErrorBanner.value) {
      linkedErrorBannerTimer = setTimeout(dismissLinkedErrorBanner, 5000);
    }
  } catch (err) {
    if (err instanceof AccessDeniedError) {
      accessDenied.value = err;
    } else if (err instanceof SessionExpiredError) {
      sessionExpired.value = true;
    } else {
      error.value = err instanceof Error ? err.message : 'Could not load identity status.';
    }
  } finally {
    loading.value = false;
  }

  try {
    const catalog = await fetchCatalog();
    catalogServers.value = catalog.servers;
  } catch {
    // Non-critical -- see the comment on catalogServers above.
  }
});

function reload() {
  location.reload();
}

// Called on IdentityLink's `unlinked` event, once the DELETE has already
// succeeded — reflect it locally rather than re-fetching, and drop the
// cache so a subsequent page load doesn't serve the pre-unlink snapshot.
function handleUnlinked(id: string) {
  const provider = providers.value.find((p) => p.id === id);
  if (provider) provider.linked = false;
  clearIdentitiesCache();
}

// Called on X509IdentityCard's `linked` event, once POST /v1/x509/proxy has
// already succeeded — same reflect-locally-and-drop-cache pattern as
// handleUnlinked above. The mint response carries the fresh proxy expiry;
// the custody mode follows the remember choice the user just made.
function handleX509Linked(id: string, meta: ProxyMetadata, remember: boolean) {
  const provider = providers.value.find((p) => p.id === id);
  if (provider) {
    provider.linked = true;
    provider.proxy_expires_at = meta.expires_at;
    provider.x509_link_mode = remember ? 'auto-renew' : 'until-expiry';
  }
  clearIdentitiesCache();
}

// Called on Krb5IdentityCard's `linked` event, once POST /v1/krb5/ticket has
// already succeeded — same reflect-locally-and-drop-cache pattern as
// handleX509Linked above. Krb5 has no stored-credential custody mode or
// proxy expiry to track: a mint is a one-shot action (see
// Krb5IdentityCard.vue's doc comment), so only `linked` flips.
function handleKrb5Linked(id: string, meta: KrbTicketMetadata) {
  const provider = providers.value.find((p) => p.id === id);
  if (provider) provider.linked = true;
  clearIdentitiesCache();
}

// Called on Krb5IdentityCard's `keytab-linked` event, once POST
// /v1/krb5/keytab has already succeeded -- fires alongside `linked` above
// (both events fire together for that flow), the one that flips
// `krb5_has_keytab` so the card's "keytab linked" badge and the
// hands-free-first "Refresh ticket" behavior reflect the new durable link
// without a full page reload.
function handleKrb5KeytabLinked(id: string) {
  const provider = providers.value.find((p) => p.id === id);
  if (provider) provider.krb5_has_keytab = true;
  clearIdentitiesCache();
}

// Called on Krb5IdentityCard's `keytab-unlinked` event -- a hands-free
// refresh's 409 revealed the broker just deleted this principal's stored
// keytab server-side (a bad stored keytab, e.g. a rotated CERN password).
// Unlike handleKrb5Revoked below, `linked` is untouched: the caller may
// still get a ticket via the password form that's about to appear, and
// linkage is about the ticket, not the keytab specifically.
function handleKrb5KeytabUnlinked(id: string) {
  const provider = providers.value.find((p) => p.id === id);
  if (provider) provider.krb5_has_keytab = false;
  clearIdentitiesCache();
}

// Called on X509IdentityCard's `revoked` event, once DELETE /v1/x509/proxy
// has already succeeded. Revoking burns the proxy but never unlinks an
// auto-renew identity (the stored passphrase re-mints hands-free); an
// until-expiry link had ONLY the proxy, so it reads as unlinked now.
function handleX509Revoked(id: string) {
  const provider = providers.value.find((p) => p.id === id);
  if (provider) {
    provider.proxy_expires_at = null;
    if (provider.x509_link_mode === 'until-expiry') {
      provider.linked = false;
      provider.x509_link_mode = null;
    }
  }
  clearIdentitiesCache();
}

// Called on Krb5IdentityCard's `revoked` event, once DELETE
// /v1/identities/link/{alias} has already succeeded -- unlike
// handleX509Revoked, krb5's "Forget" always deletes the whole Vault record
// (there is no separate until-expiry/auto-renew distinction), so it always
// flips `linked` back to false.
function handleKrb5Revoked(id: string) {
  const provider = providers.value.find((p) => p.id === id);
  if (provider) {
    provider.linked = false;
    provider.krb5_has_keytab = false;
  }
  clearIdentitiesCache();
}
</script>

<template>
  <div class="ip">
    <!-- Linked confirmation banner -->
    <div v-if="linkedBanner" class="ip__banner" role="status">
      <span
        >Linked <strong>{{ linkedBanner }}</strong> successfully.</span
      >
      <button
        type="button"
        class="ip__banner-close"
        aria-label="Dismiss"
        @click="dismissLinkedBanner"
      >
        &times;
      </button>
    </div>

    <!-- Linking failure banner -->
    <div v-if="linkedErrorBanner" class="ip__banner ip__banner--error" role="alert">
      <span>{{ linkedErrorBanner }}</span>
      <button
        type="button"
        class="ip__banner-close"
        aria-label="Dismiss"
        @click="dismissLinkedErrorBanner"
      >
        &times;
      </button>
    </div>

    <!-- Loading -->
    <div v-if="loading" class="ip__loading" aria-live="polite">
      <span class="ip__spinner" aria-hidden="true"></span>
      Loading identity status…
    </div>

    <!-- Session expired -->
    <div v-else-if="sessionExpired" class="ip__error" role="alert">
      <span class="ip__error-title">Session expired</span>
      <span class="ip__error-body">
        Your session has expired.
        <button type="button" class="ip__reload" @click="reload">Reload</button>
        to re-authenticate.
      </span>
    </div>

    <!-- Access denied: a valid, unexpired credential that's missing the
         audience needed to use this platform -- a reload can't fix it, only
         an administrator granting access can (see identity.py's
         TokenAudienceError). -->
    <div v-else-if="accessDenied" class="ip__error" role="alert">
      <span class="ip__error-title">Access not yet granted</span>
      <span class="ip__error-body">{{ accessDenied.message }}</span>
    </div>

    <!-- Error -->
    <div v-else-if="error" class="ip__error" role="alert">
      <span class="ip__error-title">Could not load identities</span>
      <span class="ip__error-body">{{ error }}</span>
    </div>

    <template v-else>
      <!-- Identity list — one flat list. Redirect-mechanism providers
           (keycloak-brokered, oauth21-direct) render uniformly via
           IdentityLink; the passphrase-mechanism x509 entry gets its own
           card with the in-page passphrase form; the credential-mechanism
           krb5-token entry gets its own card with the in-page ticket form. -->
      <div v-if="providers.length > 0" class="ip__list">
        <template v-for="p in providers" :key="p.id">
          <!--
            Stable per-provider anchor -- af_link_identity (and the broker's
            not-linked ToolError) deep-link to
            `{portal_url}/identities#identity-card-{id}`. Wraps whichever
            card component renders rather than putting the id on the
            component itself: IdentityLink already declares its own `id`
            prop with a different meaning (the provider alias passed
            through to startIdpLink() and its dialog's aria ids), so
            reusing it for the DOM anchor would collide.
          -->
          <div :id="`identity-card-${p.id}`" class="ip__card-anchor">
            <X509IdentityCard
              v-if="p.link_mechanism === 'passphrase'"
              :linked="p.linked"
              :display_name="p.display_name"
              :enables="p.enables"
              :powers="powersForAlias(p.id)"
              :proxy_expires_at="p.proxy_expires_at"
              :x509_link_mode="p.x509_link_mode"
              @linked="(meta, remember) => handleX509Linked(p.id, meta, remember)"
              @revoked="handleX509Revoked(p.id)"
            />
            <Krb5IdentityCard
              v-else-if="p.link_mechanism === 'credential'"
              :id="p.id"
              :linked="p.linked"
              :krb5_has_keytab="p.krb5_has_keytab"
              :display_name="p.display_name"
              :enables="p.enables"
              :powers="powersForAlias(p.id)"
              @linked="(meta) => handleKrb5Linked(p.id, meta)"
              @keytab-linked="handleKrb5KeytabLinked(p.id)"
              @keytab-unlinked="handleKrb5KeytabUnlinked(p.id)"
              @revoked="handleKrb5Revoked(p.id)"
            />
            <IdentityLink
              v-else
              :id="p.id"
              :type="p.type"
              :linked="p.linked"
              :display_name="p.display_name"
              :enables="p.enables"
              :powers="powersForAlias(p.id)"
              :link_url="p.link_url"
              :link_permission_denied="p.link_permission_denied"
              @unlinked="handleUnlinked(p.id)"
            />
          </div>
        </template>
      </div>

      <!-- No providers returned at all -->
      <div v-else class="ip__empty">
        <p class="ip__empty-title">No identity providers configured</p>
        <p class="ip__empty-body">
          Contact your facility administrator to enable external identity providers.
        </p>
      </div>
    </template>
  </div>
</template>

<style scoped>
.ip {
  display: flex;
  flex-direction: column;
  gap: 1.5rem;
}

/* Linked confirmation banner */
.ip__banner {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 0.75rem;
  padding: 0.875rem 1rem;
  border: 1px solid rgb(from var(--color-af-green) r g b / 0.25);
  border-radius: 4px;
  background: rgb(from var(--color-af-green) r g b / 0.08);
  font-size: 0.875rem;
  color: var(--color-af-text);
  animation: ip-banner-fade-in 200ms ease-out;
}

.ip__banner-close {
  flex-shrink: 0;
  font: inherit;
  font-size: 1rem;
  line-height: 1;
  color: var(--color-af-dim);
  background: none;
  border: none;
  cursor: pointer;
  padding: 0 0.25rem;
}
.ip__banner-close:hover {
  color: var(--color-af-text);
}

/* Linking failure banner — same layout as the success banner, red/warning styling */
.ip__banner--error {
  border-color: rgb(from var(--color-af-red) r g b / 0.25);
  background: rgb(from var(--color-af-red) r g b / 0.06);
}

@keyframes ip-banner-fade-in {
  from {
    opacity: 0;
    transform: translateY(-4px);
  }
  to {
    opacity: 1;
    transform: translateY(0);
  }
}
@media (prefers-reduced-motion: reduce) {
  .ip__banner {
    animation: none;
  }
}

/* List */
.ip__list {
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
}

/* Anchor wrapper for a `#identity-card-{id}` deep link (af_link_identity,
   and the broker's not-linked ToolError) -- scroll-margin-top keeps the
   card clear of Base.astro's sticky .af-topbar (56px tall) when the
   browser scrolls a hash target into view. */
.ip__card-anchor {
  scroll-margin-top: 72px;
}

/* Loading */
.ip__loading {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  padding: 2rem;
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.8125rem;
  color: var(--color-af-dim);
}

.ip__spinner {
  width: 16px;
  height: 16px;
  border: 2px solid var(--color-af-border);
  border-top-color: var(--color-af-teal);
  border-radius: 50%;
  animation: spin 600ms linear infinite;
}
@keyframes spin {
  to {
    transform: rotate(360deg);
  }
}
@media (prefers-reduced-motion: reduce) {
  .ip__spinner {
    animation: none;
    border-top-color: var(--color-af-dim);
  }
}

/* Error */
.ip__error {
  display: flex;
  flex-direction: column;
  gap: 0.375rem;
  padding: 1rem;
  border: 1px solid rgb(from var(--color-af-red) r g b / 0.2);
  border-radius: 4px;
  background: rgb(from var(--color-af-red) r g b / 0.05);
}
.ip__error-title {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.8125rem;
  font-weight: 600;
  color: var(--color-af-red);
}
.ip__error-body {
  font-size: 0.875rem;
  color: var(--color-af-dim);
}

.ip__reload {
  font: inherit;
  color: var(--color-af-teal);
  background: none;
  border: none;
  padding: 0;
  cursor: pointer;
  text-decoration: underline;
}

/* Empty */
.ip__empty {
  padding: 3rem 1.5rem;
  text-align: center;
  border: 1px dashed var(--color-af-border);
  border-radius: 4px;
}
.ip__empty-title {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 1rem;
  color: var(--color-af-label);
  margin: 0 0 0.5rem;
}
.ip__empty-body {
  font-size: 0.875rem;
  color: var(--color-af-dim);
  margin: 0;
}
</style>
