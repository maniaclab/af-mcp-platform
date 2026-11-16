<script setup lang="ts">
/**
 * Renders Markdown from a backend MCP server (a tool or service description).
 * The HTML comes from renderMarkdown, which sanitizes it (see markdown.ts), so
 * binding it with v-html is safe; never bind other strings this way.
 *
 * The renderer is imported on first mount (see markdownRenderer.ts). Until it
 * arrives, and if the import fails, the source shows as plain text; Vue
 * escapes text interpolation, so that fallback needs no sanitizing.
 *
 * Block mode wraps the content in Tailwind typography's `prose` (themed in
 * components.css as `.af-markdown`); `inline` renders a span for text that
 * sits inside another element.
 */
import { computed, onMounted } from 'vue';
import { loadMarkdownRenderer, markdownRenderer } from '../../lib/markdownRenderer';

const props = defineProps<{
  source: string;
  inline?: boolean;
}>();

const html = computed(
  () => markdownRenderer.value?.(props.source, { inline: props.inline }) ?? null,
);

onMounted(() => {
  // A failed import leaves the plain-text fallback in place.
  loadMarkdownRenderer().catch(() => {});
});
</script>

<template>
  <span v-if="inline && html !== null" class="af-markdown" v-html="html" />
  <span v-else-if="inline" class="af-markdown">{{ source }}</span>
  <div v-else-if="html !== null" class="af-markdown prose" v-html="html" />
  <div v-else class="af-markdown prose">{{ source }}</div>
</template>
