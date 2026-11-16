<script setup lang="ts">
/**
 * AdminPage.vue -- body of the /admin page, reachable only once GET
 * /v1/identities reports `is_admin: true` (gated client-side in
 * Base.astro's nav script -- this is a static build with no per-request
 * server auth state).
 *
 * A column of independent admin panels (usage across users, maintenance
 * mode, annotation mismatches, tool mapping drift, credmon sync), each its
 * own component with its own fetch so one failing endpoint leaves the others
 * usable. The page itself only owns the banner, which needs the two lint
 * counts the mismatch and drift panels report.
 */
import { computed, ref } from 'vue';
import AdminCredmonSection from './AdminCredmonSection.vue';
import AdminDriftSection from './AdminDriftSection.vue';
import AdminMaintenanceSection from './AdminMaintenanceSection.vue';
import AdminMismatchesSection from './AdminMismatchesSection.vue';
import AdminUsageSection from './AdminUsageSection.vue';

function plural(n: number, one: string, many: string): string {
  return `${n} ${n === 1 ? one : many}`;
}

// ── Page banner: the single most urgent message ─────────────────────────
// Problem beats warning; maintenance mode is reported by the shell's bar and
// in its own section below.
const mismatchCount = ref(0);
const driftCount = ref(0);
const issueCount = computed(() => mismatchCount.value + driftCount.value);

const driftBannerText = computed(() => {
  const parts: string[] = [];
  if (mismatchCount.value > 0) {
    parts.push(plural(mismatchCount.value, 'annotation mismatch', 'annotation mismatches'));
  }
  if (driftCount.value > 0) {
    parts.push(`${plural(driftCount.value, 'service', 'services')} with tool mapping drift`);
  }
  return `${parts.join(' and ')}. Enforcement is unchanged; review them below.`;
});
</script>

<template>
  <div class="af-page af-wide compact ap">
    <!-- Page banner: the single most urgent message. -->
    <div v-if="issueCount > 0" class="alert af-banner warn" role="alert" data-af-admin-banner>
      <span class="af-mark warn" aria-hidden="true"></span>
      <div>
        <b
          >{{
            plural(issueCount, 'tool configuration issue', 'tool configuration issues')
          }}
          found</b
        >
        {{ driftBannerText }}
      </div>
      <a
        class="btn"
        data-variant="outline"
        data-size="sm"
        :href="mismatchCount > 0 ? '#ap-mismatches' : '#ap-drift'"
        >Review issues</a
      >
    </div>

    <AdminUsageSection />
    <AdminMaintenanceSection />
    <AdminMismatchesSection @count="mismatchCount = $event" />
    <AdminDriftSection @count="driftCount = $event" />
    <AdminCredmonSection />
  </div>
</template>
