<script setup lang="ts">
import { onMounted, ref } from 'vue';
import {
  clearIdentitiesCache,
  fetchIdentities,
  SessionExpiredError,
  type IdentityProvider,
} from '../lib/api';
import { extractLinkedErrorParams, extractLinkedParam } from '../lib/linkedBanner';
import IdentityLink from './IdentityLink.vue';

const providers = ref<IdentityProvider[]>([]);
const loading = ref(true);
const error = ref<string | null>(null);
const sessionExpired = ref(false);

// Set by a `?linked=<id>` landing (see broker/src/af_mcp_broker/api/oauth21.py's
// `callback` route) — the display_name of the just-linked provider, or the
// raw id as a fallback if it doesn't match anything in `providers`. Fades on
// its own after ~5s; also dismissed by the banner's own close affordance.
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
    if (linkedId) {
      const linked = data.providers.find((p) => p.id === linkedId);
      linkedBanner.value = linked ? linked.display_name : linkedId;
      linkedBannerTimer = setTimeout(dismissLinkedBanner, 5000);
    }
    if (linkedError) {
      const failed = data.providers.find((p) => p.id === linkedError.alias);
      const displayName = failed ? failed.display_name : linkedError.alias;
      const reason = linkedError.description ?? linkedError.code;
      linkedErrorBanner.value = `Linking ${displayName} failed: ${reason}`;
      linkedErrorBannerTimer = setTimeout(dismissLinkedErrorBanner, 5000);
    }
  } catch (err) {
    if (err instanceof SessionExpiredError) {
      sessionExpired.value = true;
    } else {
      error.value = err instanceof Error ? err.message : 'Could not load identity status.';
    }
  } finally {
    loading.value = false;
  }
});

function reload() {
  location.reload();
}

// Show the "missing required identity" warning when a key provider is unlinked.
function missingRequired(id: string): boolean {
  return !providers.value.some((p) => p.id === id && p.linked);
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

    <!-- Error -->
    <div v-else-if="error" class="ip__error" role="alert">
      <span class="ip__error-title">Could not load identities</span>
      <span class="ip__error-body">{{ error }}</span>
    </div>

    <template v-else>
      <!-- Warning: missing required identities -->
      <div
        v-if="missingRequired('cern') || missingRequired('atlas-iam')"
        class="ip__warn"
        role="status"
      >
        <svg width="14" height="14" viewBox="0 0 14 14" fill="none" aria-hidden="true">
          <path
            d="M7 1L13 12H1L7 1Z"
            stroke="var(--color-af-amber)"
            stroke-width="1.25"
            stroke-linejoin="round"
          />
          <path
            d="M7 5.5V8"
            stroke="var(--color-af-amber)"
            stroke-width="1.25"
            stroke-linecap="round"
          />
          <circle cx="7" cy="10" r="0.6" fill="var(--color-af-amber)" />
        </svg>
        <span>
          Link CERN and ATLAS IAM to access the full tool catalog and grid proxy generation.
        </span>
      </div>

      <!-- Identity list — one flat list, rendered uniformly regardless of
           linking mechanism (keycloak-brokered or oauth21-direct). -->
      <div v-if="providers.length > 0" class="ip__list">
        <IdentityLink
          v-for="p in providers"
          :key="p.id"
          :id="p.id"
          :type="p.type"
          :linked="p.linked"
          :display_name="p.display_name"
          :enables="p.enables"
          :link_url="p.link_url"
        />
      </div>

      <!-- No providers returned at all -->
      <div v-else class="ip__empty">
        <p class="ip__empty-title">No identity providers configured</p>
        <p class="ip__empty-body">
          Contact your facility administrator to enable external identity providers.
        </p>
      </div>

      <!-- What each provider unlocks -->
      <div v-if="providers.length > 0" class="ip__explainer">
        <h2 class="ip__explainer-title">What each identity unlocks</h2>
        <div class="ip__explainer-grid">
          <div v-for="p in providers" :key="p.id" class="ip__explainer-row">
            <span class="ip__explainer-provider">{{ p.id }}</span>
            <span class="ip__explainer-desc">{{ p.enables }}</span>
          </div>
        </div>
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

/* Warning */
.ip__warn {
  display: flex;
  align-items: flex-start;
  gap: 0.625rem;
  padding: 0.875rem 1rem;
  border: 1px solid rgb(from var(--color-af-amber) r g b / 0.25);
  border-radius: 4px;
  background: rgb(from var(--color-af-amber) r g b / 0.06);
  font-size: 0.875rem;
  color: #d97706;
  line-height: 1.5;
}

.ip__warn svg {
  flex-shrink: 0;
  margin-top: 0.1875rem;
}

/* List */
.ip__list {
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
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
  color: #9ca3af;
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
  color: #4b5563;
  margin: 0 0 0.5rem;
}
.ip__empty-body {
  font-size: 0.875rem;
  color: var(--color-af-muted);
  margin: 0;
}

/* Explainer */
.ip__explainer {
  padding: 1.25rem;
  border: 1px solid var(--color-af-border);
  border-radius: 4px;
  background: rgb(from var(--color-af-surface) r g b / 0.5);
}

.ip__explainer-title {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.625rem;
  font-weight: 600;
  letter-spacing: 0.1em;
  text-transform: uppercase;
  color: #4b5563;
  margin: 0 0 0.875rem;
}

.ip__explainer-grid {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.ip__explainer-row {
  display: grid;
  grid-template-columns: 8rem 1fr;
  gap: 1rem;
  align-items: baseline;
}

.ip__explainer-provider {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.75rem;
  color: var(--color-af-teal);
}

.ip__explainer-desc {
  font-size: 0.8125rem;
  color: var(--color-af-dim);
}
</style>
