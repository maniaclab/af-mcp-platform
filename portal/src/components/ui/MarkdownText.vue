<script setup lang="ts">
/**
 * Renders Markdown from a backend MCP server (a tool or service description).
 * The HTML comes from renderMarkdown, which sanitizes it (see markdown.ts), so
 * binding it with v-html is safe; never bind other strings this way.
 *
 * Block mode wraps the content in Tailwind typography's `prose` (themed in
 * components.css as `.af-markdown`); `inline` renders a span for text that
 * sits inside another element.
 */
import { computed } from 'vue';
import { renderMarkdown } from '../../lib/markdown';

const props = defineProps<{
  source: string;
  inline?: boolean;
}>();

const html = computed(() => renderMarkdown(props.source, { inline: props.inline }));
</script>

<template>
  <span v-if="inline" class="af-markdown" v-html="html" />
  <div v-else class="af-markdown prose" v-html="html" />
</template>
