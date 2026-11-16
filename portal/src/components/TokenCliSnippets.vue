<script setup lang="ts">
/**
 * TokenCliSnippets.vue — copy-paste snippets for creating and using a token
 * outside the browser (testing, scripts, CI).
 */
import { computed, ref } from 'vue';
import { curlMintSnippet, pythonMintAndConnectSnippet } from '../lib/tokenCliSnippets';
import CopyField from './ui/CopyField.vue';
import Disclosure from './ui/Disclosure.vue';

const props = defineProps<{
  /** The broker's origin, empty until the page has resolved it. */
  brokerOrigin: string;
}>();

const curlSnippet = computed(() => curlMintSnippet(props.brokerOrigin));
const pythonSnippet = computed(() => pythonMintAndConnectSnippet(props.brokerOrigin));
const cliOpen = ref(false);
</script>

<template>
  <!-- issue #122: copy-paste snippets for creating/using a token outside the browser. -->
  <section class="af-sect" aria-labelledby="tp-cli-heading">
    <h2 id="tp-cli-heading">Use from the command line</h2>
    <p class="af-help">
      Create and use a token without opening a browser, for scripts or CI. See
      <a
        href="https://maniaclab.github.io/af-mcp-platform/connecting-a-client/"
        target="_blank"
        rel="noopener noreferrer"
        >Connecting a client</a
      >
      for the full setup guide.
    </p>
    <Disclosure v-model:open="cliOpen" label="Show curl and Python snippets">
      <div class="tp__cli">
        <h3 class="tp__label">Create a token with curl</h3>
        <CopyField :value="curlSnippet" label="Copy curl snippet" multiline />

        <h3 class="tp__label">Create a token and connect from Python</h3>
        <CopyField :value="pythonSnippet" label="Copy Python snippet" multiline />

        <p class="af-help">
          A token created this way appears in the list above like any other, with a name, an expiry
          and a <strong>Revoke</strong> action.
        </p>
      </div>
    </Disclosure>
  </section>
</template>

<style scoped>
.tp__cli {
  display: flex;
  flex-direction: column;
  gap: var(--space-12);
}

.tp__label {
  margin: 0;
  font-size: var(--text-13);
  font-weight: 500;
}
</style>
