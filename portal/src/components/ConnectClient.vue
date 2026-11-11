<script setup lang="ts">
/**
 * ConnectClient.vue — the Overview page's "connect a client" section: the MCP
 * endpoint as a copy field, numbered steps for Claude, and a curl snippet.
 *
 * The endpoint depends on a runtime fetch (getBrokerOrigin() reads
 * /config.json), so it cannot be a build-time constant: a hardcoded URL would
 * show every deployment its own host or a different, wrong one.
 */
import { computed, onMounted, ref } from 'vue';
import { getBrokerOrigin } from '../lib/auth';
import CopyField from './ui/CopyField.vue';

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
    <p class="ov__body">
      Add this server URL to Claude Desktop, Gemini Advanced, or any MCP-compatible client. Your
      account signs in automatically the first time you connect — you never paste a credential by
      hand unless your client can't open a browser (see below).
    </p>

    <p v-if="endpoint === null" class="ov__body" role="status">Loading…</p>
    <template v-else>
      <div class="ov__field">
        <span class="ov__label">MCP server URL</span>
        <CopyField :value="endpoint" label="Copy endpoint URL to clipboard" />
      </div>

      <h3 class="ov__subheading">Claude (Claude.ai, Claude Desktop)</h3>
      <ol class="ov__steps">
        <li>
          Add a custom connector with just the server URL above — no header, no token needed:
          <strong>Settings → Connectors → Add custom connector.</strong>
        </li>
        <li>
          The first call opens a browser window to sign in with your account. Claude stores the
          resulting credential itself — you won't see it again.
        </li>
        <li>
          If your client can't open a browser, skip that step: create a personal access token from
          the <a href="/tokens/">Tokens page</a> instead, then under
          <strong>Request headers</strong> add name <code>Authorization</code>, value
          <code>Bearer &lt;your token&gt;</code>.
        </li>
      </ol>

      <h3 class="ov__subheading">curl</h3>
      <p class="ov__body">
        Create a personal access token on the <a href="/tokens/">Tokens page</a> first, then paste
        it in place of <code>&lt;your token&gt;</code> below.
      </p>
      <CopyField :value="curlSnippet" label="Copy curl snippet to clipboard" multiline />
    </template>
  </section>
</template>

<style scoped>
.ov__subheading {
  font: 600 var(--text-14) / 1.45 var(--font-sans);
  margin: var(--space-8) 0 0;
}

.ov__body {
  margin: 0;
  max-width: 68ch;
}

.ov__field {
  display: flex;
  flex-direction: column;
  gap: var(--space-8);
}

.ov__label {
  font-weight: 500;
  font-size: var(--text-13);
}

.ov__steps {
  margin: 0;
  padding-inline-start: var(--space-24);
  list-style: decimal;
  display: flex;
  flex-direction: column;
  gap: var(--space-8);
  max-width: 68ch;
}

a {
  text-underline-offset: 3px;
}

code {
  font-family: var(--font-mono);
}
</style>
