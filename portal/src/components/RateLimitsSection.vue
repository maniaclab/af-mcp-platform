<script setup lang="ts">
/**
 * RateLimitsSection.vue — the Entitlements page's "Rate limits" section.
 *
 * Each configured rule (GET /v1/rate-limits) in plain language, the caller's
 * own methods it covers, and how much of its window they have used, so a
 * limit is visible before a call is refused. Loads on its own, apart from the
 * permission matrix, so a broker without the endpoint (or an outage of the
 * usage store) never hides the matrix.
 *
 * Which methods a rule covers is computed here, not by the broker: the broker
 * would have to list every backend to know. The page asks for the methods of
 * each service the caller can list (the Services page's own endpoint), and
 * says so when it could not list one, so the covered lists are never silently
 * incomplete. Only fetched when there are rules to match.
 */
import { onMounted, ref } from 'vue';
import {
  fetchCatalog,
  fetchRateLimits,
  fetchServerTools,
  type CatalogTool,
  type RateLimitsResponse,
} from '../lib/api';
import { coveredToolNames, describeRule, usageLabel, usageTone } from '../lib/rateLimits';
import { useLoadState } from '../lib/useLoadState';
import StatusMark from './ui/StatusMark.vue';
import ToolNameList from './ui/ToolNameList.vue';
import AsyncState from './ui/AsyncState.vue';

const response = ref<RateLimitsResponse>({ rate_limits: [], usage_available: true });
const tools = ref<CatalogTool[]>([]);
const toolsLoading = ref(false);
// Services whose methods are missing from `tools`: not available to the
// caller, or the listing failed.
const unlisted = ref<string[]>([]);
const toolsFailed = ref(false);
const { loading, error, sessionExpired, accessDenied, run } = useLoadState();

async function loadTools(): Promise<void> {
  toolsLoading.value = true;
  try {
    const { servers } = await fetchCatalog();
    const listable = servers.filter((s) => s.status === 'available');
    unlisted.value = servers.filter((s) => s.status !== 'available').map((s) => s.name);
    const listings = await Promise.allSettled(listable.map((s) => fetchServerTools(s.name)));
    listings.forEach((result, i) => {
      if (result.status === 'fulfilled' && result.value.status === 'ok') {
        tools.value.push(...result.value.tools);
      } else {
        unlisted.value.push(listable[i].name);
      }
    });
  } catch {
    toolsFailed.value = true;
  } finally {
    toolsLoading.value = false;
  }
}

onMounted(() =>
  run(async () => {
    response.value = await fetchRateLimits();
    // Not awaited: the rules and usage are useful before the method lists arrive.
    if (response.value.rate_limits.length > 0) void loadTools();
  }, 'Could not load rate limits.'),
);
</script>

<template>
  <section class="af-sect rl" aria-labelledby="rl-heading">
    <h2 id="rl-heading">Rate limits</h2>
    <p class="af-help">
      Caps on how often you can call methods. Every limit that covers a call applies, so the
      strictest one decides. Counts are yours alone, and each window opens at your first covered
      call.
    </p>

    <AsyncState
      :loading="loading"
      :error="error"
      error-title="Could not load rate limits"
      :session-expired="sessionExpired"
      :access-denied="accessDenied"
      :empty="response.rate_limits.length === 0"
      loading-label="Loading rate limits…"
      inline
    >
      <template #empty>
        <header>
          <h3>No rate limits are configured.</h3>
          <p>Limits on how often you can call methods appear here once the admins set them.</p>
        </header>
      </template>

      <p v-if="!response.usage_available" class="alert af-note warn" data-testid="rl-usage-note">
        <span class="af-mark warn" aria-hidden="true"></span>
        <span>
          Your usage could not be read right now. The limits still apply; a refused call says when
          to retry.
        </span>
      </p>

      <div class="table-container af-box">
        <table class="af-compact table">
          <caption class="sr-only">
            Configured rate limits, the methods each covers for you, and your usage
          </caption>
          <thead>
            <tr>
              <th scope="col">Limit</th>
              <th scope="col">Covers your methods</th>
              <th scope="col">Your usage</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="(rule, i) in response.rate_limits" :key="i">
              <th scope="row">
                <span>{{ describeRule(rule).subject }}</span>
                <template v-if="describeRule(rule).pattern"
                  >{{ ' ' }}<code>{{ describeRule(rule).pattern }}</code></template
                ><span>: {{ describeRule(rule).budget }}</span>
              </th>
              <td>
                <span v-if="toolsLoading" class="af-sub">Loading methods…</span>
                <span v-else-if="toolsFailed" class="af-sub">Could not list your methods.</span>
                <ToolNameList
                  v-else-if="coveredToolNames(rule, tools).length > 0"
                  :names="coveredToolNames(rule, tools)"
                />
                <span v-else class="af-sub">No tool of yours matches this limit.</span>
              </td>
              <td>
                <StatusMark :tone="usageTone(rule)">{{ usageLabel(rule) }}</StatusMark>
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <p v-if="unlisted.length > 0" class="af-help" data-testid="rl-unlisted">
        Methods of these services are not listed above, because they are unavailable to you or could
        not be fetched:
        <code v-for="(name, i) in unlisted" :key="name"
          >{{ name }}<template v-if="i < unlisted.length - 1">, </template></code
        >.
      </p>
    </AsyncState>
  </section>
</template>

<style scoped>
/* The permission matrix above it is a sibling section, not a child of one
   wrapper that spaces its sections. */
.rl {
  margin-top: var(--space-32);
}
</style>
