<script setup lang="ts">
/**
 * ConnectClient.vue — the Overview page's "connect a client" section: three
 * numbered step boxes (copy the MCP endpoint, add it to a client, sign in), and
 * a collapsed disclosure with the personal-access-token route and a curl snippet.
 *
 * The endpoint depends on a runtime fetch (getBrokerOrigin() reads
 * /config.json), so it cannot be a build-time constant: a hardcoded URL would
 * show every deployment its own host or a different, wrong one.
 */
import { computed, onMounted, ref } from 'vue';
import { getBrokerOrigin } from '../lib/auth';
import CopyField from './ui/CopyField.vue';
import Disclosure from './ui/Disclosure.vue';

const origin = ref<string | null>(null);

onMounted(async () => {
  origin.value = await getBrokerOrigin();
});

// Trailing slash matters: some MCP clients don't follow the redirect a bare
// /mcp gets from Starlette's Mount (see docs/connecting-a-client.md).
const endpoint = computed(() => (origin.value === null ? null : `${origin.value}/mcp/`));

const curlSnippet = computed(
  () => `export MCP_TOKEN="<your token>"
curl -H "Authorization: Bearer $MCP_TOKEN" \\
     ${endpoint.value}`,
);
</script>

<template>
  <section class="af-sect" aria-labelledby="ov-connect-heading">
    <h2 id="ov-connect-heading">Connect to this endpoint</h2>
    <p class="cc__body">
      Add this server to Claude or any MCP-compatible client. You sign in with your own account; the
      assistant never sees your credentials.
    </p>

    <ol class="cc__steps">
      <li class="af-box cc__step">
        <span class="cc__num">1</span>
        <h3 class="cc__title">Copy the server URL</h3>
        <p v-if="endpoint === null" class="cc__text" role="status">Loading…</p>
        <!-- multiline: a step box is too narrow for a whole URL on one line,
             and the value to copy must never be cut off with an ellipsis. -->
        <CopyField v-else :value="endpoint" label="Copy endpoint URL to clipboard" multiline />
      </li>
      <li class="af-box cc__step">
        <span class="cc__num">2</span>
        <h3 class="cc__title">Add it to your client</h3>
        <p class="cc__text">
          In Claude: <strong>Settings → Connectors → Add custom connector</strong>, and paste the
          URL. No header or token needed. Other MCP clients: add it as a remote server.
        </p>
      </li>
      <li class="af-box cc__step">
        <span class="cc__num">3</span>
        <h3 class="cc__title">Sign in when asked</h3>
        <p class="cc__text">
          The first call opens a browser window to sign in with your account. Your client stores the
          credential itself.
        </p>
      </li>
    </ol>

    <Disclosure label="No browser? Use a personal access token">
      <div class="cc__token">
        <p class="cc__body">
          Create a token on the <a href="/tokens/">Tokens page</a>. In your client's request headers
          (in Claude, <strong>Request headers</strong>), add name <code>Authorization</code>, value
          <code>Bearer &lt;your token&gt;</code>. To try it from a terminal, paste the token in
          place of <code>&lt;your token&gt;</code> below.
        </p>
        <CopyField
          v-if="endpoint !== null"
          :value="curlSnippet"
          label="Copy curl snippet to clipboard"
          multiline
        />
      </div>
    </Disclosure>
  </section>
</template>

<style scoped>
.cc__body {
  margin: 0;
  max-width: 68ch;
}

/* Three boxes side by side when there is room, one column when narrow. */
.cc__steps {
  margin: 0;
  padding: 0;
  list-style: none;
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(14rem, 1fr));
  gap: var(--space-16);
}

.cc__step {
  display: flex;
  flex-direction: column;
  align-items: flex-start;
  gap: var(--space-8);
  min-width: 0;
  padding: var(--space-16);
}

.cc__step > :where(.af-copy) {
  align-self: stretch;
}

.cc__num {
  font: 500 var(--text-13) / 1 var(--font-mono);
  color: var(--color-af-text-secondary);
}

.cc__title {
  margin: 0;
  font: 600 var(--text-14) / 1.45 var(--font-sans);
}

.cc__text {
  margin: 0;
}

.cc__token {
  display: flex;
  flex-direction: column;
  gap: var(--space-8);
}

a {
  text-underline-offset: 3px;
}

code {
  font-family: var(--font-mono);
}
</style>
