<script setup lang="ts">
/**
 * TokenTable.vue — a table of design tokens that shows each token's value as
 * it is in effect now. Names, uses and the specimen frames render on the
 * server, so the table is meaningful before hydration; the value column and
 * the specimens (a swatch, a bar, a corner, a type sample) are filled on the
 * client from the page's computed style, again whenever the theme or the
 * page-local accent changes (designTokens.ts). Nothing here repeats a value
 * from global.css.
 *
 * Specimens are set through the CSSOM (`el.style`), not a `style` attribute,
 * which the page's Content-Security-Policy would block.
 */
import { onBeforeUnmount, onMounted, ref } from 'vue';
import {
  DESIGN_SCOPE_ID,
  readTokenValues,
  subscribeToTokenChanges,
  type TokenRow,
} from '../../lib/designTokens';

const props = withDefaults(
  defineProps<{
    tokens: TokenRow[];
    /** What to draw beside the name: a colour swatch, a spacing bar, a corner, a type sample or nothing. */
    specimen?: 'colour' | 'space' | 'radius' | 'type' | 'none';
    caption: string;
  }>(),
  { specimen: 'none' },
);

const values = ref<Record<string, string>>({});
let stop: (() => void) | undefined;

function read(): void {
  const scope = document.getElementById(DESIGN_SCOPE_ID) ?? document.documentElement;
  values.value = readTokenValues(
    props.tokens.map((t) => t.name),
    getComputedStyle(scope),
  );
}

/** Function ref: runs on the client only, after the element exists. */
function paint(el: unknown, token: TokenRow): void {
  if (!(el instanceof HTMLElement)) return;
  const ref = `var(${token.name})`;
  if (props.specimen === 'colour') el.style.background = ref;
  else if (props.specimen === 'space') el.style.width = ref;
  else if (props.specimen === 'radius') el.style.borderRadius = ref;
  else if (props.specimen === 'type') {
    el.style.fontSize = ref;
    el.style.lineHeight = '1.3';
    el.style.fontWeight = String(token.weight ?? 400);
  }
}

onMounted(() => {
  read();
  stop = subscribeToTokenChanges(read);
});
onBeforeUnmount(() => stop?.());
</script>

<template>
  <div class="table-container af-box design-table">
    <table class="af-compact table">
      <caption class="sr-only">
        {{
          caption
        }}
      </caption>
      <thead>
        <tr>
          <th v-if="specimen !== 'none'" scope="col">
            {{ specimen === 'type' ? 'Specimen' : '' }}
          </th>
          <th scope="col">Token</th>
          <th scope="col">Value now</th>
          <th scope="col">Use</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="t in tokens" :key="t.name">
          <td v-if="specimen !== 'none'">
            <span v-if="specimen === 'type'" :ref="(el) => paint(el, t)" class="design-specimen">{{
              t.sample
            }}</span>
            <span
              v-else
              :ref="(el) => paint(el, t)"
              :class="specimen === 'space' ? 'design-bar-spec' : 'design-chip'"
              aria-hidden="true"
            ></span>
          </td>
          <td>
            <code class="design-token">{{ t.name }}</code>
          </td>
          <td>
            <code class="design-value">{{ values[t.name] ?? '' }}</code>
          </td>
          <td>{{ t.use }}</td>
        </tr>
      </tbody>
    </table>
  </div>
</template>
