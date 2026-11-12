<script setup lang="ts">
/**
 * ToolNameList.vue — tool names, one per line in mono, each kept whole (a
 * name never wraps mid-word; a cell that is too narrow scrolls its table box
 * instead). A long list shows the first `visible` names and puts the rest
 * behind a disclosure labelled with their count.
 */
import { computed, ref } from 'vue';
import Disclosure from './Disclosure.vue';

const props = withDefaults(defineProps<{ names: string[]; visible?: number }>(), { visible: 3 });

const open = ref(false);
const shown = computed(() => props.names.slice(0, props.visible));
const rest = computed(() => props.names.slice(props.visible));
</script>

<template>
  <div v-if="names.length > 0" class="tnl-wrap">
    <ul class="tnl">
      <li v-for="name in shown" :key="name">
        <code>{{ name }}</code>
      </li>
    </ul>
    <Disclosure v-if="rest.length > 0" v-model:open="open" :label="`${rest.length} more`">
      <ul class="tnl">
        <li v-for="name in rest" :key="name">
          <code>{{ name }}</code>
        </li>
      </ul>
    </Disclosure>
  </div>
</template>

<style scoped>
.tnl-wrap {
  padding-block: var(--space-8);
}

.tnl {
  display: flex;
  flex-direction: column;
  gap: var(--space-2);
  margin: 0;
  padding: 0;
  list-style: none;
}

.tnl li {
  white-space: nowrap;
}

.tnl code {
  font-family: var(--font-mono);
  font-size: var(--text-12);
}
</style>
