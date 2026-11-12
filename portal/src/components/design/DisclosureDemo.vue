<script setup lang="ts">
/**
 * DisclosureDemo.vue — the real Disclosure, and ToolNameList, which uses one
 * to fold a long list of names behind a count.
 */
import { ref } from 'vue';
import Disclosure from '../ui/Disclosure.vue';
import ToolNameList from '../ui/ToolNameList.vue';

const TOOL_NAMES = [
  'rucio_list_dids',
  'rucio_list_replicas',
  'rucio_get_did',
  'rucio_list_rules',
  'rucio_list_rses',
];

const open = ref(false);
</script>

<template>
  <div class="design-cols">
    <div class="design-stage">
      <h3 class="design-label">Disclosure</h3>
      <Disclosure v-model:open="open" label="Show certificate details">
        <p class="af-help">The details of one record, shown only when asked for.</p>
      </Disclosure>
    </div>
    <div class="design-stage">
      <h3 class="design-label">Tool names, three shown</h3>
      <ToolNameList :names="TOOL_NAMES" :visible="3" />
    </div>
  </div>
</template>
