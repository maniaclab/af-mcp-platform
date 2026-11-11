/**
 * useFetchOnExpand.ts — state for a disclosure whose content is fetched each
 * time it expands (Disclosure.vue is the matching control).
 *
 * Every toggle, in either direction, bumps a sequence number, and a fetch
 * may only apply its result while the number still matches the one captured
 * when that fetch started. A response landing after a collapse, or after a
 * newer expand, is discarded; otherwise a slow response rewrites the section
 * one fetch behind the clicks.
 */
import { ref } from 'vue';

export function useFetchOnExpand<T>(
  fetcher: () => Promise<T>,
  fallbackMessage = 'Could not load.',
) {
  const open = ref(false);
  const data = ref<T | null>(null);
  const loading = ref(false);
  const error = ref<string | null>(null);
  let seq = 0;

  async function toggle(): Promise<void> {
    open.value = !open.value;
    seq += 1;
    if (!open.value) {
      loading.value = false;
      return;
    }
    const mine = seq;
    loading.value = true;
    error.value = null;
    try {
      const result = await fetcher();
      if (mine !== seq) return;
      data.value = result;
    } catch (err) {
      if (mine !== seq) return;
      data.value = null;
      error.value = err instanceof Error ? err.message : fallbackMessage;
    } finally {
      if (mine === seq) loading.value = false;
    }
  }

  return { open, data, loading, error, toggle };
}
