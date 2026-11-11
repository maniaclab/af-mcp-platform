<script setup lang="ts">
import { X } from '@lucide/vue';
import { computed, onMounted, ref } from 'vue';
import {
  clearIdentitiesCache,
  fetchCatalog,
  fetchIdentities,
  type CatalogServer,
  type IdentityProvider,
  type KrbTicketMetadata,
  type ProxyMetadata,
  type ServiceXTokenMetadata,
} from '../lib/api';
import { groupServersByAlias } from '../lib/catalog';
import {
  extractLinkedErrorParams,
  extractLinkedParam,
  resolveLinkedBanner,
  resolveLinkedErrorBanner,
} from '../lib/linkedBanner';
import { formatDateTime, formatRemaining } from '../lib/relativeTime';
import { proxyExpiryState } from '../lib/x509Identity';
import { useLoadState } from '../lib/useLoadState';
import IdentityLink from './IdentityLink.vue';
import Krb5IdentityCard from './Krb5IdentityCard.vue';
import ServiceXIdentityCard from './ServiceXIdentityCard.vue';
import X509IdentityCard from './X509IdentityCard.vue';
import AsyncState from './ui/AsyncState.vue';

const providers = ref<IdentityProvider[]>([]);
const { loading, error, sessionExpired, accessDenied, run } = useLoadState();

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

  await run(async () => {
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
  }, 'Could not load identity status.');

  try {
    const catalog = await fetchCatalog();
    catalogServers.value = catalog.servers;
  } catch {
    // Non-critical -- see the comment on catalogServers above.
  }
});

interface StateBanner {
  tone: 'bad' | 'warn';
  title: string;
  text: string;
  /** Exact time shown on hover for relative wording in `text`. */
  hoverTitle?: string;
  /** Provider the banner's one button jumps to; absent when no single target exists. */
  targetId?: string;
  button?: string;
}

// The one most urgent state problem, or null. The proxy is judged by
// proxyExpiryState: an auto-renewing link re-mints hands-free, so it never
// warns of expiry.
// Problem beats warning: an expired proxy, then an expiring one. An account
// that is not linked is the user's choice, and one that needs access is for an
// administrator to fix, so neither raises a banner; each card says so itself.
const stateBanner = computed<StateBanner | null>(() => {
  const now = new Date();
  const x509 = providers.value.find((p) => p.link_mechanism === 'passphrase');
  const expiry = x509?.proxy_expires_at ? new Date(x509.proxy_expires_at) : null;
  if (x509 && expiry && !Number.isNaN(expiry.getTime())) {
    const state = proxyExpiryState(
      (expiry.getTime() - now.getTime()) / 1000,
      x509.x509_link_mode === 'auto-renew',
    );
    if (state === 'expired') {
      return {
        tone: 'bad',
        title: 'Your grid proxy has expired',
        text: 'Link your grid certificate again to restore HTCondor and grid data access.',
        hoverTitle: formatDateTime(expiry, { year: true }),
        targetId: x509.id,
        button: 'Link certificate',
      };
    }
    if (x509.linked && state === 'expiring') {
      return {
        tone: 'warn',
        title: 'Your grid proxy expires soon',
        text: `${formatRemaining(expiry, now)}. Re-link your grid certificate to renew it.`,
        hoverTitle: formatDateTime(expiry, { year: true }),
        targetId: x509.id,
        button: 'Re-link certificate',
      };
    }
  }

  return null;
});

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

// Called on ServiceXIdentityCard's `linked` event, once POST
// /v1/servicex/link has already succeeded — same reflect-locally-and-drop-
// cache pattern as handleKrb5Linked. servicex-token has no separate
// custody mode (always the hands-free-renewal shape), so only `linked`
// flips.
function handleServiceXLinked(id: string, meta: ServiceXTokenMetadata) {
  const provider = providers.value.find((p) => p.id === id);
  if (provider) provider.linked = true;
  clearIdentitiesCache();
}

// Called on ServiceXIdentityCard's `revoked` event, once DELETE
// /v1/identities/link/{alias} has already succeeded — mirrors
// handleKrb5Revoked: "Forget" always deletes the whole Vault record (both
// the refresh token and any cached access token), so it always flips
// `linked` back to false.
function handleServiceXRevoked(id: string) {
  const provider = providers.value.find((p) => p.id === id);
  if (provider) provider.linked = false;
  clearIdentitiesCache();
}
</script>

<template>
  <div class="af-page">
    <!-- Banner slot: one message. A just-finished link attempt outranks the
         standing state, which returns once it is dismissed or fades. -->
    <div v-if="linkedErrorBanner" class="alert af-banner bad" role="alert">
      <span class="af-mark bad" aria-hidden="true"></span>
      <div>
        <b>Linking failed</b>
        {{ linkedErrorBanner }}
      </div>
      <button
        type="button"
        class="btn"
        data-variant="ghost"
        data-size="sm"
        aria-label="Dismiss"
        @click="dismissLinkedErrorBanner"
      >
        <X class="af-icon" :size="16" aria-hidden="true" />
      </button>
    </div>

    <div v-else-if="linkedBanner" class="alert af-banner ok" role="status">
      <span class="af-mark ok" aria-hidden="true"></span>
      <div>
        <b>{{ linkedBanner }} linked</b>
      </div>
      <button
        type="button"
        class="btn"
        data-variant="ghost"
        data-size="sm"
        aria-label="Dismiss"
        @click="dismissLinkedBanner"
      >
        <X class="af-icon" :size="16" aria-hidden="true" />
      </button>
    </div>

    <div v-else-if="stateBanner" class="alert af-banner" :class="stateBanner.tone" role="alert">
      <span class="af-mark" :class="stateBanner.tone" aria-hidden="true"></span>
      <div>
        <b>{{ stateBanner.title }}</b>
        <span :title="stateBanner.hoverTitle">{{ stateBanner.text }}</span>
      </div>
      <a
        v-if="stateBanner.targetId"
        class="btn"
        data-variant="outline"
        data-size="sm"
        :href="`#identity-card-${stateBanner.targetId}`"
      >
        {{ stateBanner.button }}
      </a>
    </div>

    <section class="af-sect">
      <h2>Accounts and credentials</h2>
      <AsyncState
        :loading="loading"
        :error="error"
        error-title="Could not load identities"
        :session-expired="sessionExpired"
        :access-denied="accessDenied"
        :empty="providers.length === 0"
        loading-label="Loading identity status…"
      >
        <!-- Identity list — one flat list. Redirect-mechanism providers
             (keycloak-brokered, oauth21-direct) render uniformly via
             IdentityLink; the passphrase-mechanism x509 entry gets its own
             card with the in-page passphrase form; the credential-mechanism
             krb5-token entry gets its own card with the in-page ticket form;
             the servicex-token entry gets its own card with the in-page
             refresh-token paste form and an external-link-out button. -->
        <div class="ip__list">
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
              <ServiceXIdentityCard
                v-else-if="p.link_mechanism === 'servicex-token'"
                :id="p.id"
                :linked="p.linked"
                :display_name="p.display_name"
                :enables="p.enables"
                :powers="powersForAlias(p.id)"
                :external_login_url="p.external_login_url"
                @linked="(meta) => handleServiceXLinked(p.id, meta)"
                @revoked="handleServiceXRevoked(p.id)"
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
        <template #empty>
          <header>
            <h3>No identity providers configured</h3>
            <p>Contact your facility administrator to enable external identity providers.</p>
          </header>
        </template>
      </AsyncState>
    </section>
  </div>
</template>

<style scoped>
.ip__list {
  display: flex;
  flex-direction: column;
  gap: var(--space-16);
}

/* A deep link (#identity-card-<id>) lands with the row clear of the sticky
   top bar. That bar exists only under 860px, where it is 52px tall
   (--control-m + --space-16); above it nothing is sticky. */
.ip__card-anchor {
  scroll-margin-top: var(--space-16);
}

@media (max-width: 859px) {
  .ip__card-anchor {
    scroll-margin-top: calc(var(--control-m) + var(--space-16) + var(--space-16));
  }
}
</style>
