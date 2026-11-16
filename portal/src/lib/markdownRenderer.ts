/**
 * markdownRenderer.ts — loads markdown.ts (marked and DOMPurify, the largest
 * dependencies of the catalog page) with a dynamic import the first time a
 * description needs rendering, so they stay out of every page's entry chunk.
 *
 * `markdownRenderer` is reactive: components that read it re-render when the
 * import resolves. It stays `null` until then.
 */
import { shallowRef } from 'vue';
import type { renderMarkdown } from './markdown';

export const markdownRenderer = shallowRef<typeof renderMarkdown | null>(null);

let pending: Promise<void> | null = null;

/** Starts the import once; later calls share it. A failed import may be retried. */
export function loadMarkdownRenderer(): Promise<void> {
  pending ??= import('./markdown').then(
    (module) => {
      markdownRenderer.value = module.renderMarkdown;
    },
    (err: unknown) => {
      pending = null;
      throw err;
    },
  );
  return pending;
}
