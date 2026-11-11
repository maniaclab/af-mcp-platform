<script setup lang="ts">
/**
 * OverviewSummary.vue — the Overview page's banner slot, status list and
 * usage stats, in one island.
 *
 * The list has one row per area a new user needs to understand (services,
 * identities, tokens, usage): a plain-language explanation, a status word
 * with its mark, and a link to the page that manages it. The summary and usage
 * fetches are independent, so a slow or failing /v1/usage never blocks the
 * other rows. Usage numbers are ESTIMATES (tokenized tool-result text, not
 * provider-reported spend) and are labelled as such — see the broker's
 * GET /v1/usage caveats.
 */
import { ArrowRight, ChartColumn, KeyRound, Server, UserRound } from '@lucide/vue';
import type { Component } from 'vue';
import { computed, onMounted, ref } from 'vue';
import { fetchDashboardSummary, fetchUsage } from '../lib/api';
import type { DashboardSummary, UsageResponse } from '../lib/api';
import { overviewBanner } from '../lib/overviewBanner';
import { formatCost, formatTokens } from '../lib/usageFormat';
import StatusMark from './ui/StatusMark.vue';

type Tone = InstanceType<typeof StatusMark>['$props']['tone'];

interface Row {
  key: string;
  icon: Component;
  name: string;
  description: string;
  tone: Tone;
  state: string;
  href: string;
  linkLabel: string;
}

const summary = ref<DashboardSummary | null>(null);
const usage = ref<UsageResponse | null>(null);
const summaryLoading = ref(true);
const usageLoading = ref(true);

// Each row degrades on its own to "Status unavailable": a failed fetch is not
// a critical path, and zeros would read as a real answer.
onMounted(() => {
  fetchDashboardSummary()
    .then((s) => (summary.value = s))
    .catch(() => {})
    .finally(() => (summaryLoading.value = false));
  fetchUsage()
    .then((u) => (usage.value = u))
    .catch(() => {})
    .finally(() => (usageLoading.value = false));
});

const banner = computed(() => (summary.value ? overviewBanner(summary.value) : null));

function pending(loading: boolean): { tone: Tone; state: string } {
  return loading
    ? { tone: 'busy', state: 'Loading…' }
    : { tone: 'off', state: 'Status unavailable' };
}

function gridCertificate(s: DashboardSummary): 'not linked' | 'expired' | 'active' {
  const { cached, remaining_seconds: remaining } = s.proxyStatus;
  if (!cached) return 'not linked';
  return remaining != null && remaining <= 0 ? 'expired' : 'active';
}

const servicesStatus = computed(() => {
  const s = summary.value;
  if (!s) return pending(summaryLoading.value);
  return { tone: s.serverCount > 0 ? 'ok' : 'off', state: `${s.serverCount} services` } as const;
});

const identitiesStatus = computed(() => {
  const s = summary.value;
  if (!s) return pending(summaryLoading.value);
  const cert = gridCertificate(s);
  // A certificate that is not linked is absent by choice, not a problem; an
  // expired one is.
  const tone: Tone = cert === 'expired' ? 'bad' : s.linkedCount > 0 ? 'ok' : 'off';
  return { tone, state: `${s.linkedCount} linked · grid certificate ${cert}` };
});

const tokensStatus = computed(() => {
  const s = summary.value;
  if (!s) return pending(summaryLoading.value);
  return {
    tone: s.activeTokenCount > 0 ? 'ok' : 'off',
    state: `${s.activeTokenCount} active`,
  } as const;
});

const usageStatus = computed(() => {
  const u = usage.value;
  if (!u) return pending(usageLoading.value);
  if (u.totals.calls === 0) {
    return { tone: 'off', state: `No tool calls in the last ${u.window_days} days` } as const;
  }
  return {
    tone: 'ok',
    state: `${u.totals.calls.toLocaleString('en-US')} calls in ${u.window_days} days`,
  } as const;
});

const rows = computed<Row[]>(() => [
  {
    key: 'services',
    icon: Server,
    name: 'Services',
    description:
      'The backend systems your AI assistant can reach through this platform — dataset lookup, metadata, job submission, and more — all exposed as methods it can call directly.',
    ...servicesStatus.value,
    href: '/catalog/',
    linkLabel: 'Browse the catalog',
  },
  {
    key: 'identities',
    icon: UserRound,
    name: 'Identities',
    description:
      'The external accounts — your CERN/ATLAS login, your grid certificate — this platform uses to act on your behalf, without ever handing your AI assistant a raw credential.',
    ...identitiesStatus.value,
    href: '/identities/',
    linkLabel: 'Manage identities',
  },
  {
    key: 'tokens',
    icon: KeyRound,
    name: 'Tokens',
    description:
      "A Personal Access Token (PAT) is what lets a client that can't sign in with a browser on its own — like Claude Desktop — connect on your behalf.",
    ...tokensStatus.value,
    href: '/tokens/',
    linkLabel: 'Manage tokens',
  },
  {
    key: 'usage',
    icon: ChartColumn,
    name: 'Usage',
    description:
      "What your AI assistant's tool calls put into its context through this platform — counted as estimated tokens and priced, for scale, at a reference model's input rate. Estimates only: this is not your provider bill.",
    ...usageStatus.value,
    href: '/usage/',
    linkLabel: 'View usage details',
  },
]);

const showStats = computed(() => usage.value !== null && usage.value.totals.calls > 0);
</script>

<template>
  <div
    v-if="banner"
    class="af-banner"
    :class="banner.tone"
    :role="banner.tone === 'bad' ? 'alert' : 'status'"
  >
    <span class="af-mark" :class="banner.tone" aria-hidden="true"></span>
    <div>
      <b>{{ banner.title }}</b
      >{{ banner.body }}
    </div>
    <a class="af-btn s" :href="banner.action.href">{{ banner.action.label }}</a>
  </div>

  <section class="af-sect" aria-labelledby="ov-access-heading">
    <h2 id="ov-access-heading">Your access</h2>
    <ul class="af-tbl-box ov__rows">
      <li v-for="row in rows" :key="row.key" class="ov__row">
        <div class="ov__area">
          <component :is="row.icon" class="af-icon" :size="16" aria-hidden="true" />
          <div>
            <h3 class="ov__name">{{ row.name }}</h3>
            <p class="ov__desc">{{ row.description }}</p>
          </div>
        </div>
        <StatusMark :tone="row.tone" :label="row.state" class="ov__state" />
        <a class="af-btn quiet s" :href="row.href">
          {{ row.linkLabel }}
          <ArrowRight class="af-icon" :size="16" aria-hidden="true" />
        </a>
      </li>
    </ul>
  </section>

  <section v-if="showStats && usage" class="af-sect" aria-labelledby="ov-usage-heading">
    <h2 id="ov-usage-heading">Usage in the last {{ usage.window_days }} days</h2>
    <div class="af-stats">
      <div class="af-stat">
        <span>Tool calls</span>
        <b>{{ usage.totals.calls.toLocaleString('en-US') }}</b>
        <small>{{ usage.totals.errors.toLocaleString('en-US') }} errors</small>
      </div>
      <div class="af-stat">
        <span>Tokens (estimated)</span>
        <b>{{ formatTokens(usage.totals.result_tokens_est) }}</b>
        <small>In tool results</small>
      </div>
      <div class="af-stat">
        <span>Cost (estimated)</span>
        <b>{{ formatCost(usage.totals.estimated_cost_usd) }}</b>
        <small>At {{ usage.cost_model }} input rate</small>
      </div>
    </div>
  </section>
</template>

<style scoped>
.ov__rows {
  list-style: none;
  margin: 0;
  padding: 0;
}

.ov__row {
  display: grid;
  grid-template-columns: minmax(0, 3fr) minmax(0, 2fr) 12rem;
  align-items: center;
  gap: var(--space-8) var(--space-16);
  padding: var(--space-12) var(--space-16);
  border-bottom: 1px solid var(--color-af-border);
}

.ov__row:last-child {
  border-bottom: 0;
}

.ov__area {
  display: flex;
  align-items: flex-start;
  gap: var(--space-12);
}

.ov__area > .af-icon {
  margin-top: var(--space-2);
}

.ov__name {
  font: 500 var(--text-14) / 1.45 var(--font-sans);
  margin: 0;
}

.ov__desc {
  margin: 0;
  font-size: var(--text-13);
  color: var(--color-af-text-secondary);
}

/* The status word may be long ("3 linked · grid certificate active"), so it
 * wraps instead of forcing the row wider than the viewport. */
.ov__state {
  white-space: normal;
}

.ov__row > a {
  justify-self: end;
}

@media (max-width: 720px) {
  .ov__row {
    grid-template-columns: minmax(0, 1fr);
  }
}
</style>
