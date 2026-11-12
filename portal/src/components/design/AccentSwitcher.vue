<script setup lang="ts">
/**
 * AccentSwitcher.vue — try a facility accent on this page only. Picking a
 * colour writes the portal's own derivation of it (accent.ts) on the page's
 * accent scope, so every example below responds; "Default" removes it and the
 * deployment's configured accent (or ink) shows again. The choice is never
 * stored and re-derives when the theme changes (designAccent.ts).
 *
 * The derived values shown are read back from the scope's computed style, so
 * they are what the examples actually use, configured accent included.
 */
import { onBeforeUnmount, onMounted, ref } from 'vue';
import { ACCENT_CHOICES, applyLocalAccent, watchLocalAccent } from '../../lib/designAccent';
import {
  DESIGN_ACCENT_EVENT,
  DESIGN_SCOPE_ID,
  readTokenValues,
  subscribeToTokenChanges,
} from '../../lib/designTokens';

const PICKER_START = '#0a0a0a';

/** The chosen #rrggbb, or null for the default (the deployment's own accent). */
const choice = ref<string | null>(null);
const picker = ref(PICKER_START);
const accent = ref('');
const onAccent = ref('');

let scope: HTMLElement | null = null;
const cleanups: (() => void)[] = [];

function readEffective(): void {
  if (!scope) return;
  const values = readTokenValues(
    ['--color-af-accent', '--color-af-on-accent'],
    getComputedStyle(scope),
  );
  accent.value = values['--color-af-accent'];
  onAccent.value = values['--color-af-on-accent'];
  if (choice.value === null && /^#[0-9a-f]{6}$/i.test(accent.value)) picker.value = accent.value;
}

function pick(hex: string | null): void {
  if (!scope) return;
  choice.value = hex;
  if (hex) picker.value = hex;
  applyLocalAccent(scope, hex);
  document.documentElement.dispatchEvent(new Event(DESIGN_ACCENT_EVENT));
}

/** Function ref: a swatch's colour is example data, set through the CSSOM. */
function paint(el: unknown, hex: string): void {
  if (el instanceof HTMLElement) el.style.background = hex;
}

onMounted(() => {
  scope = document.getElementById(DESIGN_SCOPE_ID);
  if (!scope) return;
  cleanups.push(watchLocalAccent(scope, () => choice.value));
  cleanups.push(subscribeToTokenChanges(readEffective));
  readEffective();
});
onBeforeUnmount(() => cleanups.forEach((stop) => stop()));
</script>

<template>
  <div class="accent">
    <span id="accent-label" class="accent__label">Facility accent</span>
    <div class="accent__scroll">
      <div class="button-group af-toggle" role="group" aria-labelledby="accent-label">
        <button
          type="button"
          class="btn"
          data-variant="outline"
          data-size="sm"
          :aria-pressed="choice === null"
          title="The deployment's accent: ink unless the facility sets a colour"
          @click="pick(null)"
        >
          Default
        </button>
        <button
          v-for="c in ACCENT_CHOICES"
          :key="c.hex"
          type="button"
          class="btn"
          data-variant="outline"
          data-size="sm"
          :aria-pressed="choice === c.hex"
          :title="c.note"
          @click="pick(c.hex)"
        >
          <span :ref="(el) => paint(el, c.hex)" class="accent__dot" aria-hidden="true"></span>
          {{ c.label }}
        </button>
      </div>
    </div>
    <label class="accent__picker">
      <span class="accent__label">Any colour</span>
      <input
        type="color"
        class="accent__input"
        :value="picker"
        @input="pick(($event.target as HTMLInputElement).value)"
      />
    </label>
    <span class="accent__values" role="status">
      Accent <code>{{ accent }}</code> · on-accent <code>{{ onAccent }}</code>
    </span>
  </div>
</template>

<style scoped>
.accent {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: var(--space-8) var(--space-16);
  font-size: var(--text-13);
}

.accent__scroll {
  /* The five buttons are wider than a phone: scroll the group, not the page. The
     padding keeps the focus halo of the outer buttons from being clipped. */
  max-width: 100%;
  overflow-x: auto;
  padding: var(--space-4);
  margin: calc(-1 * var(--space-4));
}

.accent__label {
  color: var(--color-af-text-secondary);
}

.accent__dot {
  display: inline-block;
  width: var(--space-12);
  height: var(--space-12);
  border-radius: 50%;
  border: 1px solid var(--color-af-border-strong);
}

.accent__picker {
  display: inline-flex;
  align-items: center;
  gap: var(--space-8);
}

.accent__input {
  width: var(--control-m);
  height: var(--control-s);
  padding: 0;
  border: 1px solid var(--color-af-border-strong);
  border-radius: var(--radius-8);
  background: var(--color-af-bg);
  cursor: pointer;
}

.accent__values {
  color: var(--color-af-text-secondary);
}

.accent__values code {
  font-family: var(--font-mono);
  color: var(--color-af-text);
}
</style>
