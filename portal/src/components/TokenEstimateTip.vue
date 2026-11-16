<script setup lang="ts">
/**
 * TokenEstimateTip.vue — an info button beside token figures whose tooltip
 * states how token counts are estimated (lib/tokenExplainer.ts). The tooltip
 * is not interactive, so the docs link lives in the surrounding text.
 */
import { TOKEN_ESTIMATE_RULES, TOKEN_ESTIMATE_SUMMARY } from '../lib/tokenExplainer';
import InfoTip from './ui/InfoTip.vue';

defineProps<{ id: string }>();
</script>

<template>
  <InfoTip :id="id" label="How token counts are estimated" placement="bottom">
    <span class="tet__line">{{ TOKEN_ESTIMATE_SUMMARY }}</span>
    <span class="tet__line">{{ TOKEN_ESTIMATE_RULES.text }}</span>
    <span class="tet__line">{{ TOKEN_ESTIMATE_RULES.image }}</span>
    <span class="tet__line">{{ TOKEN_ESTIMATE_RULES.other }}</span>
    <span class="tet__line">{{ TOKEN_ESTIMATE_RULES.structured }}</span>
  </InfoTip>
</template>

<style scoped>
.tet__line {
  display: block;
}

.tet__line + .tet__line {
  margin-top: var(--space-4);
}
</style>
